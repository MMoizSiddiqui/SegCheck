"""Readers for commercial firewall syslog formats: FortiGate, Cisco ASA / Firepower (FTD), Sophos Firewall, MikroTik.

Each reader turns one syslog line into the same small record the rest of SegCheck uses:
    {"format", "action": "block" | "pass" | "logged", "protocol", "source_ip", "destination_ip",
     "destination_port", "interface", "rule"}
or returns None when the line is not a firewall decision of that vendor. Lines are only read, never acted on.
"""
from __future__ import annotations

import ipaddress
import re

_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp"}
_BLOCK = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected"}
_PASS = {"accept", "accepted", "allow", "allowed", "permit", "permitted", "close", "timeout", "client-rst",
         "server-rst", "ip-conn", "start"}


def _kv(message):
    return {key.lower(): value.strip('"') for key, value in _KV.findall(message)}


def _ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _proto(value):
    value = (value or "").strip().lower()
    value = _PROTO_NUMBERS.get(value, value)
    return "icmp" if value.startswith("icmp") else value


def _record(fmt, action, protocol, src, dst, port, interface, rule):
    src, dst = _ip(src), _ip(dst)
    if not src or not dst or protocol not in {"tcp", "udp", "icmp"}:
        return None
    return {"format": fmt, "action": action, "protocol": protocol, "source_ip": src, "destination_ip": dst,
            "destination_port": None if protocol == "icmp" else _port(port), "interface": interface or "",
            "rule": (rule or "")[:64]}


# --------------------------------------------------------------------------- FortiGate (FortiOS traffic logs)
def fortigate(message):
    if "srcip=" not in message or ("devname=" not in message and "logid=" not in message):
        return None
    kv = _kv(message)
    if kv.get("type") not in (None, "traffic"):
        return None
    word = kv.get("action", "").lower()
    action = "block" if word in _BLOCK else "pass" if word in _PASS else "logged"
    rule = kv.get("policyname") or (f"policy {kv['policyid']}" if kv.get("policyid") else "")
    if kv.get("policyid") == "0" and action == "block":
        rule = "implicit deny (policy 0)"
    return _record("fortigate", action, _proto(kv.get("proto")), kv.get("srcip"), kv.get("dstip"), kv.get("dstport"),
                   kv.get("srcintf"), rule)


# --------------------------------------------------------------------------- Sophos Firewall (SFOS / XG)
def sophos(message):
    if "src_ip=" not in message or ("log_component=" not in message and "fw_rule_id=" not in message):
        return None
    kv = _kv(message)
    if kv.get("log_type", "Firewall").lower() not in {"firewall", "content filtering"} and "fw_rule_id" not in kv:
        return None
    word = (kv.get("log_subtype") or kv.get("status") or "").lower()
    action = "block" if word in _BLOCK else "pass" if word in _PASS else "logged"
    rule = kv.get("fw_rule_name") or (f"rule {kv['fw_rule_id']}" if kv.get("fw_rule_id") not in (None, "", "0") else "")
    if not rule and action == "block":
        rule = "default drop"
    return _record("sophos", action, _proto(kv.get("protocol")), kv.get("src_ip"), kv.get("dst_ip"), kv.get("dst_port"),
                   kv.get("in_interface") or kv.get("in_display_interface"), rule)


# --------------------------------------------------------------------------- Cisco ASA / Firepower Threat Defense
_ASA = re.compile(r"%(?:ASA|FTD)-\d-(\d{6}):\s*(.*)")
_ASA_106023 = re.compile(r"Deny (\w+) src ([\w.-]+):([0-9a-fA-F:.]+?)(?:/(\d+))? dst ([\w.-]+):([0-9a-fA-F:.]+?)(?:/(\d+))?"
                         r"(?: \(type.*?\))? by access-group \"([^\"]+)\"")
_ASA_106100 = re.compile(r"access-list (\S+) (permitted|denied|est-allowed) (\w+) ([\w.-]+)/([0-9a-fA-F:.]+)\((\d+)\) -> "
                         r"([\w.-]+)/([0-9a-fA-F:.]+)\((\d+)\)")
_ASA_106001 = re.compile(r"Inbound (TCP) connection denied from ([0-9a-fA-F:.]+)/(\d+) to ([0-9a-fA-F:.]+)/(\d+).*? on interface (\S+)")
_ASA_10600X = re.compile(r"Deny inbound (UDP|icmp|protocol \d+) from ([0-9a-fA-F:.]+)(?:/(\d+))? to ([0-9a-fA-F:.]+)(?:/(\d+))?.*? on interface (\S+)")
_ASA_302 = re.compile(r"Built (inbound|outbound) (TCP|UDP) connection \d+ for ([\w.-]+):([0-9a-fA-F:.]+)/(\d+) .*?to "
                      r"([\w.-]+):([0-9a-fA-F:.]+)/(\d+)")


def cisco(message):
    match = _ASA.search(message)
    if not match:
        return None
    msg_id, text = match.groups()
    if msg_id == "106023" and (m := _ASA_106023.search(text)):
        proto, src_if, src, _, _, dst, dport, acl = m.groups()
        return _record("cisco", "block", _proto(proto), src, dst, dport, src_if, acl)
    if msg_id == "106100" and (m := _ASA_106100.search(text)):
        acl, verdict, proto, src_if, src, _, _, dst, dport = m.groups()
        return _record("cisco", "block" if verdict == "denied" else "pass", _proto(proto), src, dst, dport, src_if, acl)
    if msg_id == "106001" and (m := _ASA_106001.search(text)):
        proto, src, _, dst, dport, iface = m.groups()
        return _record("cisco", "block", "tcp", src, dst, dport, iface, "implicit deny")
    if msg_id in {"106006", "106007", "106014"} and (m := _ASA_10600X.search(text)):
        proto, src, _, dst, dport, iface = m.groups()
        return _record("cisco", "block", _proto(proto.split()[0]), src, dst, dport, iface, "implicit deny")
    if msg_id in {"302013", "302015"} and (m := _ASA_302.search(text)):
        direction, proto, if1, ip1, port1, if2, ip2, port2 = m.groups()
        # inbound: "for <source> to <destination>"; outbound: "for <destination> to <source>"
        if direction == "inbound":
            return _record("cisco", "pass", _proto(proto), ip1, ip2, port2, if1, "")
        return _record("cisco", "pass", _proto(proto), ip2, ip1, port1, if2, "")
    return None


# --------------------------------------------------------------------------- MikroTik RouterOS (firewall topic)
_MIKROTIK = re.compile(r"(?:^|\s)(?P<prefix>[^\s,]*?)\s*(?:forward|input|output|[\w-]+):\s*in:(?P<in>\S*?)\s+out:(?P<out>\S*?),.*?"
                       r"proto (?P<proto>\w+)(?: \([^)]*\))?, (?P<src>[0-9a-fA-F.:]+?)(?::(?P<sport>\d+))?->"
                       r"(?P<dst>[0-9a-fA-F.:]+?)(?::(?P<dport>\d+))?, len")


def mikrotik(message):
    if "proto " not in message or "->" not in message or " in:" not in message:
        return None
    match = _MIKROTIK.search(message)
    if not match:
        return None
    prefix = (match.group("prefix") or "").upper()
    action = "block" if any(word in prefix for word in ("DROP", "REJECT", "DENY", "BLOCK")) else (
        "pass" if any(word in prefix for word in ("ACCEPT", "ALLOW", "PASS")) else "logged")
    rule = re.sub(r"^SEGCHECK-(ACCEPT|DROP)[-_ ]?", "", match.group("prefix") or "", flags=re.I) or match.group("prefix") or ""
    return _record("mikrotik", action, _proto(match.group("proto")), match.group("src"), match.group("dst"),
                   match.group("dport"), match.group("in"), rule)


READERS = (fortigate, sophos, cisco, mikrotik)


def parse_vendor_line(message: str) -> dict | None:
    for reader in READERS:
        try:
            event = reader(message)
        except (ValueError, IndexError):
            event = None
        if event:
            return event
    return None
