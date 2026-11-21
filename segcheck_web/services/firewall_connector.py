"""Read-only firewall log connector for declared boundary devices.

SegCheck never logs in to, configures or sends traffic to a firewall. For each
boundary device with log collection enabled it opens a local UDP syslog
listener, accepts datagrams only from the device's declared sender address, and
keeps a bounded in-memory window of parsed packet-filter decisions (plus an
append-only JSONL copy in the private data folder).

After a run, every probe attempt is cross-checked against those decisions:
  logged_block  – the firewall recorded dropping/rejecting this exact attempt
  logged_pass   – the firewall recorded allowing it through
  no_matching_log, not_connected
The evidence is supporting only. It never changes PASS / FAIL / INCONCLUSIVE.
UDP syslog is unauthenticated; sender filtering is not cryptographic proof.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import errno
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from segcheck.syslog_collector import parse_filterlog

MAX_DATAGRAM = 4096
MAX_EVENTS_PER_DEVICE = 20000
LOG_WAIT_SECONDS = 3.0
WINDOW_BEFORE = timedelta(seconds=2)
WINDOW_AFTER = timedelta(seconds=6)

_IPTABLES = re.compile(
    r"(?P<prefix>[A-Za-z0-9_:\-\[\] ]*?)\s*IN=(?P<in>\S*) OUT=(?P<out>\S*).*?SRC=(?P<src>[0-9a-fA-F:.]+) "
    r"DST=(?P<dst>[0-9a-fA-F:.]+).*?PROTO=(?P<proto>\w+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)
_BLOCK_WORDS = ("DROP", "REJECT", "BLOCK", "DENY")
_PASS_WORDS = ("ACCEPT", "ALLOW", "PASS")


def _utc_now():
    return datetime.now(timezone.utc)


def parse_firewall_line(message: str) -> dict | None:
    """Parse pfSense/OPNsense filterlog or Linux iptables/nftables LOG lines."""
    if "filterlog" in message:
        event = parse_filterlog(message)
        fields = event.get("filterlog_fields") or []
        if event.get("parse_status") == "insufficient_fields" and len(fields) >= 20 and fields[16].lower().startswith("icmp"):
            try:
                event.update(action=fields[6].lower(), direction=fields[7].lower(), interface=fields[4],
                             rule_tracker=fields[3], protocol="icmp",
                             source_ip=str(ipaddress.ip_address(fields[18])),
                             destination_ip=str(ipaddress.ip_address(fields[19])), parse_status="parsed")
            except (ValueError, IndexError):
                return None
        if event.get("parse_status") != "parsed":
            return None
        return {"format": "pf_filterlog", "action": event["action"], "protocol": event["protocol"].replace("icmp6", "icmp"),
                "source_ip": event["source_ip"], "destination_ip": event["destination_ip"],
                "destination_port": event.get("destination_port"), "interface": event.get("interface"),
                "rule": event.get("rule_tracker")}
    match = _IPTABLES.search(message)
    if not match:
        return None
    prefix = (match.group("prefix") or "").upper() + " " + message.upper()[:120]
    action = "block" if any(word in prefix for word in _BLOCK_WORDS) else "pass" if any(word in prefix for word in _PASS_WORDS) else "logged"
    protocol = match.group("proto").lower()
    protocol = "icmp" if protocol.startswith("icmp") else protocol
    try:
        return {"format": "iptables", "action": action, "protocol": protocol,
                "source_ip": str(ipaddress.ip_address(match.group("src"))),
                "destination_ip": str(ipaddress.ip_address(match.group("dst"))),
                "destination_port": int(match.group("dpt")) if match.group("dpt") else None,
                "interface": match.group("in") or match.group("out"), "rule": (match.group("prefix") or "").strip()[:64]}
    except ValueError:
        return None


def explain_bind_error(exc: OSError, address: str, port: int):
    """(short problem, [fixes]) for a log listener that cannot open its UDP port."""
    code = getattr(exc, "winerror", None) or exc.errno
    if code in (10048, errno.EADDRINUSE):
        return (f"UDP port {port} is already used by another program on this PC.",
                [f"Choose another port for this device (for example {port + 1}) and save it again.",
                 "Then set the same port in the firewall's remote logging settings, so the logs go to the new port.",
                 "Or close the other program that uses the port (often another syslog tool)."])
    if code in (10049, errno.EADDRNOTAVAIL):
        return (f"{address} is not an address of this PC, so SegCheck cannot receive logs on it.",
                ["Leave 'Listen on' empty to use this PC's probe address, or enter one of this PC's addresses (ipconfig).",
                 "If the PC's address changed (DHCP), click 'Use this PC as the probe' first."])
    if code in (10013, errno.EACCES):
        return (f"Windows refused UDP port {port} (reserved or blocked by security software).",
                ["Choose a port between 1024 and 65535 that is not reserved, for example 5514 or 5515.",
                 "Set the same port in the firewall's remote logging settings."])
    return (f"Cannot listen on {address}:{port} ({exc.strerror or exc}).",
            ["Check the address and port of this device, save it again, and try once more."])


class DeviceListener:
    def __init__(self, device: dict, bind_ip: str, evidence_dir: Path | None):
        self.device = dict(device)
        self.bind_ip = bind_ip
        self.port = int(device["log_port"])
        self.sender_ip = device["log_sender_ip"]
        self.events: deque = deque(maxlen=MAX_EVENTS_PER_DEVICE)
        self.stats = {"received": 0, "parsed": 0, "rejected_sender": 0, "unparsed": 0, "last_seen": None, "error": None}
        self.started = time.monotonic()
        self.other_sender = None  # last address that sent logs but is not the declared firewall
        self.learned_sender = None  # set when the sender was learned from the first firewall log
        self.fixes: list[str] = []
        self._stop = threading.Event()
        self._file = (evidence_dir / f"{device['id']}.jsonl") if evidence_dir else None
        self._socket = None
        self.thread = None

    def start(self):
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(self.bind_ip).version == 6 else socket.AF_INET
            self._socket = socket.socket(family, socket.SOCK_DGRAM)
            self._socket.bind((self.bind_ip, self.port))
            self._socket.settimeout(0.5)
        except OSError as exc:
            self.stats["error"], self.fixes = explain_bind_error(exc, self.bind_ip, self.port)
            return
        self.thread = threading.Thread(target=self._loop, name=f"segcheck-syslog-{self.device['id']}", daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, (sender, _port, *_rest) = self._socket.recvfrom(MAX_DATAGRAM)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                continue
            self.stats["received"] += 1
            if not self.sender_ip:
                # Learning mode: lock onto the first sender whose message is a recognised firewall log.
                if parse_firewall_line(data.decode("utf-8", "replace").strip()) is None:
                    self.stats["unparsed"] += 1
                    continue
                self.sender_ip = self.learned_sender = sender
            if sender != self.sender_ip:
                self.stats["rejected_sender"] += 1
                self.other_sender = sender
                continue
            received = _utc_now()
            self.stats["last_seen"] = received.isoformat()
            message = data.decode("utf-8", "replace").strip()
            parsed = parse_firewall_line(message)
            if parsed is None:
                self.stats["unparsed"] += 1
                continue
            self.stats["parsed"] += 1
            event = {"received_at": received.isoformat(), **parsed}
            self.events.append(event)
            if self._file is not None:
                try:
                    with self._file.open("a", encoding="utf-8", newline="\n") as handle:
                        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
                except OSError:
                    pass
        try:
            self._socket.close()
        except OSError:
            pass

    def stop(self, wait=False):
        """Stop listening. With wait=True the UDP port is free again when this returns (needed when the
        same port is reopened straight away, e.g. after the firewall setting was edited)."""
        self._stop.set()
        if wait and self.thread is not None:
            self.thread.join(timeout=2)

    @property
    def listening(self):
        return self.thread is not None and self.thread.is_alive()

    def advice(self):
        """What is wrong with the log feed right now and how to fix it (empty when logs flow)."""
        if self.stats["error"]:
            return self.fixes
        if self.stats["parsed"]:
            return []
        tips = []
        if self.other_sender and self.sender_ip:
            tips.append(f"Logs are arriving from {self.other_sender}, but the firewall's log sender IP is set to "
                        f"{self.sender_ip}. If {self.other_sender} is the firewall, change the sender IP to it.")
        if self.stats["unparsed"]:
            tips.append("Logs arrive but their format is not recognised. pfSense/OPNsense: Status > System Logs > "
                        "Settings, log message format 'BSD (RFC 3164)'. Linux: use iptables/nftables LOG rules.")
        if not self.stats["received"] and time.monotonic() - self.started > 60:
            tips.extend([
                f"Nothing has arrived for a minute. In the firewall's remote logging, the target must be "
                f"{self.bind_ip}:{self.port} (UDP) and firewall events must be selected.",
                "The firewall only sends a log when a rule with logging switched on matches: run an assessment, "
                "or tick 'Log' on the deny rules.",
                f"Windows Firewall on this PC may block it. If Windows asked to allow Python, choose Allow. Otherwise "
                f"ask an administrator to allow inbound UDP {self.port} "
                f"(netsh advfirewall firewall add rule name=SegCheck-syslog dir=in action=allow protocol=UDP localport={self.port}).",
            ])
        return tips

    def status(self):
        return {"id": self.device["id"], "name": self.device["name"], "kind": self.device["kind"],
                "listening": self.listening, "address": f"{self.bind_ip}:{self.port}", "sender_ip": self.sender_ip,
                "connected": self.stats["parsed"] > 0 or self.stats["last_seen"] is not None, **self.stats,
                "advice": self.advice(), "learned_sender": self.learned_sender, "buffered_events": len(self.events)}


class ConnectorRegistry:
    """One listener per logging device; reconciled whenever the environment changes."""

    def __init__(self):
        self.listeners: dict[str, DeviceListener] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _signature(device, bind_ip):
        return (device.get("log_port"), device.get("log_sender_ip"), bind_ip)

    def sync(self, environment: dict, evidence_dir: Path | None):
        probe_ip = environment.get("source_ip")
        # Each device listens on its own fixed address if set, otherwise on the probe IP.
        bind_for = lambda device: device.get("log_listen_ip") or probe_ip
        wanted = {device["id"]: device for device in environment.get("devices", [])
                  if device.get("logging") and device.get("log_port") and bind_for(device)}  # empty sender = learn it
        with self.lock:
            for device_id in list(self.listeners):
                listener = self.listeners[device_id]
                device = wanted.get(device_id)
                if device is None or self._signature(device, bind_for(device)) != self._signature(listener.device, listener.bind_ip):
                    listener.stop(wait=True)  # release the port before a replacement binds it
                    del self.listeners[device_id]
                else:
                    listener.device.update(name=device["name"], kind=device["kind"], zones=device.get("zones", []))
            for device_id, device in wanted.items():
                if device_id not in self.listeners:
                    listener = DeviceListener(device, bind_for(device), evidence_dir)
                    listener.start()
                    self.listeners[device_id] = listener

    def status(self):
        with self.lock:
            return {device_id: listener.status() for device_id, listener in self.listeners.items()}

    def stop_all(self):
        with self.lock:
            for listener in self.listeners.values():
                listener.stop()
            self.listeners.clear()

    def events_for(self, device_id):
        listener = self.listeners.get(device_id)
        return list(listener.events) if listener else []


def registry(app) -> ConnectorRegistry:
    return app.extensions.setdefault("segcheck_connectors", ConnectorRegistry())


def evidence_directory():
    from segcheck.storage import ensure_private_directory, resolve_data_dir
    try:
        return ensure_private_directory(resolve_data_dir() / "evidence")
    except (ValueError, OSError):
        return None


def devices_on_path(environment, source_zone, destination_zone):
    if source_zone == destination_zone:
        return []
    return [device for device in environment.get("devices", [])
            if source_zone in device.get("zones", []) and destination_zone in device.get("zones", [])]


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


INTERPRETATION = {
    ("inconclusive", "logged_block"): "Firewall confirmed it blocked this attempt: deny is enforced at the boundary (corroborated).",
    ("inconclusive", "logged_pass"): "Firewall let this attempt through; the target simply did not answer. The path is OPEN at the boundary: investigate.",
    ("reachable", "logged_pass"): "Firewall logged allowing this connection, matching the observed reachability (corroborated).",
    ("reachable", "logged_block"): "Contradiction: the firewall logged a block, yet the target answered. Check for another path or NAT.",
    ("inconclusive", "no_matching_log"): "No firewall decision was logged for this attempt. Check the rule has logging enabled.",
    ("reachable", "no_matching_log"): "No firewall decision was logged; the connection still succeeded.",
}


def cross_check(details: list[dict], environment: dict, connector: ConnectorRegistry | None, wait=True) -> dict:
    """Match each probe attempt with logged firewall decisions on its path."""
    devices = environment.get("devices", [])
    path_devices = {(detail["source_zone"], detail["destination_zone"]) for detail in details}
    relevant = {device["id"]: device for pair in path_devices for device in devices_on_path(environment, *pair)}
    statuses = connector.status() if connector else {}
    connected_ids = [device_id for device_id in relevant if statuses.get(device_id, {}).get("listening")]
    if wait and connected_ids:
        time.sleep(LOG_WAIT_SECONDS)  # allow the last syslog datagrams to arrive
    attempts, summary = [], {"logged_block": 0, "logged_pass": 0, "no_matching_log": 0, "not_connected": 0, "same_zone": 0, "contradictions": 0, "open_at_boundary": 0}
    for detail in details:
        on_path = devices_on_path(environment, detail["source_zone"], detail["destination_zone"])
        record = {"check_id": detail["check_id"], "protocol": detail["protocol"], "host": detail["destination_host"],
                  "port": detail["port"], "observed": detail["observed"], "devices": [device["name"] for device in on_path]}
        if not on_path:
            record.update(evidence="same_zone", interpretation="Source and target are in the same zone; no boundary device applies.")
            summary["same_zone"] += 1
            attempts.append(record)
            continue
        listening = [device for device in on_path if device["id"] in connected_ids]
        if not listening:
            kinds = {device.get("kind") for device in on_path}
            record.update(evidence="not_connected", interpretation=(
                "Boundary declared as none/unknown; no enforcement evidence is possible." if kinds == {"none"} else
                "The boundary device's log feed is not connected, so this attempt could not be cross-checked."))
            summary["not_connected"] += 1
            attempts.append(record)
            continue
        started = _parse_time(detail.get("started_at"))
        completed = _parse_time(detail.get("completed_at")) or started
        matches = []
        for device in listening:
            for event in connector.events_for(device["id"]):
                when = _parse_time(event["received_at"])
                if started is None or when is None or not (started - WINDOW_BEFORE <= when <= completed + WINDOW_AFTER):
                    continue
                if event["destination_ip"] != detail["destination_host"] or event["protocol"] != detail["protocol"]:
                    continue
                if detail.get("source_ip") and event["source_ip"] != detail["source_ip"]:
                    continue
                if detail["protocol"] in {"tcp", "udp"} and event.get("destination_port") != detail["port"]:
                    continue
                matches.append({**event, "device": device["name"]})
        if any(item["action"] == "block" for item in matches):
            evidence = "logged_block"
        elif any(item["action"] == "pass" for item in matches):
            evidence = "logged_pass"
        else:
            evidence = "no_matching_log"
        summary[evidence] += 1
        if evidence == "logged_block" and detail["observed"] == "reachable":
            summary["contradictions"] += 1
        if evidence == "logged_pass" and detail["observed"] == "inconclusive":
            summary["open_at_boundary"] += 1
        record.update(evidence=evidence, matched_events=len(matches), sample=matches[:3],
                      interpretation=INTERPRETATION.get((detail["observed"], evidence), ""))
        attempts.append(record)
    return {
        "devices": [{"id": device["id"], "name": device["name"], "kind": device.get("kind"),
                     "zones": device.get("zones", []), "connected": device["id"] in connected_ids}
                    for device in relevant.values()],
        "attempts": attempts, "summary": summary,
        "note": "Supporting evidence only. Firewall logs never change PASS/FAIL/INCONCLUSIVE. UDP syslog is unauthenticated.",
    }
