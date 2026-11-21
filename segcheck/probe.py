"""Conservative, policy-scoped TCP connectivity measurements for SegCheck.

Only explicitly listed destination IP addresses and ports are tested.
TCP success proves reachability. Socket errors remain inconclusive.
The module never scans a subnet or a port range.
"""
from __future__ import annotations

import ipaddress
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable


if TYPE_CHECKING:  # type-only: keeps this module importable with the standard library alone
    from .policy_engine import SegmentationPolicy


@dataclass(frozen=True)
class ProbeOutcome:
    state: str
    reason: str
    duration_ms: float
    source_ip: str | None = None
    # Optional measurement times recorded with the attempt.
    started_at: str | None = None
    completed_at: str | None = None


def _sortable(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _determine_source_ip(host: str, port: int) -> str | None:
    """Ask the OS which local address it would use for this destination.

    UDP connect selects a route and local address; it does not transmit
    application data. Return None if route selection cannot be determined.
    """
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET

    try:
        with socket.socket(family, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect((host, port))
            source_ip = route_socket.getsockname()[0]
            return str(ipaddress.ip_address(source_ip))
    except OSError:
        return None


def tcp_connect_probe(host: str, port: int, timeout: float = 1.5, *, source_ip: str | None = None) -> ProbeOutcome:
    """Attempt one TCP handshake to one explicit IP:port."""
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            f"Target must be a literal IP address, not a hostname: {host}"
        ) from exc

    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Port must be an integer between 1 and 65535")

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0.1 <= timeout <= 10
    ):
        raise ValueError("Timeout must be between 0.1 and 10 seconds")

    bound_source = source_ip
    if bound_source is not None:
        source_address = ipaddress.ip_address(bound_source)
        if source_address.version != ipaddress.ip_address(host).version:
            raise ValueError("Source and destination IP families must match")
        source_ip = str(source_address)
    else:
        source_ip = _determine_source_ip(host, port)
    started = time.perf_counter()

    try:
        connection_options = {"timeout": float(timeout)}
        if bound_source is not None:
            connection_options["source_address"] = (source_ip, 0)
        with socket.create_connection((host, port), **connection_options):
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            return ProbeOutcome(
                state="reachable",
                reason="tcp_connect_succeeded",
                duration_ms=duration_ms,
                source_ip=source_ip,
            )

    except ConnectionRefusedError:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome(
            state="inconclusive",
            reason="connection_refused_service_may_be_closed; not proof of segmentation",
            duration_ms=duration_ms,
            source_ip=source_ip,
        )

    except (TimeoutError, socket.timeout):
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome(
            state="inconclusive",
            reason="connection_timeout; not proof of firewall filtering",
            duration_ms=duration_ms,
            source_ip=source_ip,
        )

    except OSError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome(
            state="inconclusive",
            reason=f"socket_error_{_socket_error_label(exc)}; not proof of segmentation",
            duration_ms=duration_ms,
            source_ip=source_ip,
        )


# Stable labels for common local routing failures (POSIX errno and Windows WSA codes).
_SOCKET_ERROR_LABELS = {
    101: "network_unreachable", 10051: "network_unreachable",
    113: "host_unreachable", 10065: "host_unreachable", 65: "host_unreachable",
    51: "network_unreachable",
    99: "source_address_unavailable", 10049: "source_address_unavailable",
    49: "source_address_unavailable",
    10013: "access_denied_by_local_policy", 13: "access_denied_by_local_policy",
}


def _socket_error_label(exc: OSError) -> str:
    """Name an OS socket error without leaking arbitrary message text."""
    code = getattr(exc, "winerror", None) or exc.errno
    label = _SOCKET_ERROR_LABELS.get(code) if isinstance(code, int) else None
    return label or type(exc).__name__


# ---------------------------------------------------------------------------
# Additional probe methods. Each sends one benign, protocol-valid request to one
# explicit target and treats ONLY a genuine reply as "reachable". Silence, ICMP
# errors and resets stay "inconclusive": they never prove a firewall blocked it.
# ---------------------------------------------------------------------------

# DNS: standard A query for a reserved name (RFC 6761 ".invalid").
_DNS_QUERY = bytes.fromhex("5343" "0100" "0001" "0000" "0000" "0000") + b"\x08segcheck\x07invalid\x00" + b"\x00\x01\x00\x01"
# NTP: version 4 client request (mode 3).
_NTP_REQUEST = b"\x23" + b"\x00" * 47
# SNMPv3 engine-ID discovery: no community string, no credentials (RFC 3414 §4).
_SNMPV3_DISCOVERY = bytes.fromhex(
    "303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400"
    "301204000400a00c020237f00201000201003000"
)
UDP_PAYLOADS = {53: _DNS_QUERY, 123: _NTP_REQUEST, 161: _SNMPV3_DISCOVERY}
UDP_SERVICE_NAMES = {53: "dns_query", 123: "ntp_client_request", 161: "snmpv3_discovery"}


def _validate_target(host, port, timeout, *, allow_zero_port=False):
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"Target must be a literal IP address, not a hostname: {host}") from exc
    lowest = 0 if allow_zero_port else 1
    if isinstance(port, bool) or not isinstance(port, int) or not lowest <= port <= 65535:
        raise ValueError("Port must be an integer between 1 and 65535")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.1 <= timeout <= 10:
        raise ValueError("Timeout must be between 0.1 and 10 seconds")


def _bound_source(host, source_ip):
    if source_ip is None:
        return None
    address = ipaddress.ip_address(source_ip)
    if address.version != ipaddress.ip_address(host).version:
        raise ValueError("Source and destination IP families must match")
    return str(address)


def udp_request_probe(host: str, port: int, timeout: float = 1.5, *, source_ip: str | None = None) -> ProbeOutcome:
    """Send one protocol-appropriate UDP datagram; only a reply proves reachability."""
    _validate_target(host, port, timeout)
    bound = _bound_source(host, source_ip)
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    payload = UDP_PAYLOADS.get(port, b"SEGCHECK-UDP-PROBE")
    label = UDP_SERVICE_NAMES.get(port, "generic_datagram")
    started = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(float(timeout))
            if bound is not None:
                sock.bind((bound, 0))
            sock.connect((host, port))
            used_source = str(ipaddress.ip_address(sock.getsockname()[0]))
            sock.send(payload)
            reply = sock.recv(4096)
            duration = round((time.perf_counter() - started) * 1000, 2)
            if reply:
                return ProbeOutcome("reachable", f"udp_{label}_reply_received", duration, bound or used_source)
            return ProbeOutcome("inconclusive", f"udp_{label}_empty_reply; not proof of segmentation", duration, bound or used_source)
    except (TimeoutError, socket.timeout):
        duration = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome("inconclusive", f"udp_{label}_no_reply; silence is not proof of filtering", duration, bound)
    except ConnectionRefusedError:
        duration = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome("inconclusive", f"udp_{label}_port_unreachable_reported; not proof of segmentation", duration, bound)
    except OSError as exc:
        duration = round((time.perf_counter() - started) * 1000, 2)
        code = getattr(exc, "winerror", None) or exc.errno
        label_err = "port_unreachable_reported" if code in (10054, 104) else _socket_error_label(exc)
        return ProbeOutcome("inconclusive", f"udp_{label_err}; not proof of segmentation", duration, bound)


def _ping_command(host, timeout, source_ip):
    import platform
    system = platform.system()
    six = ipaddress.ip_address(host).version == 6
    if system == "Windows":
        command = ["ping", "-6" if six else "-4", "-n", "1", "-w", str(max(100, int(timeout * 1000)))]
        if source_ip:
            command += ["-S", source_ip]
    elif system == "Darwin":
        command = ["ping6" if six else "ping", "-n", "-c", "1"]
        if not six:
            command += ["-t", str(max(1, round(timeout)))]
        if source_ip:
            command += ["-S", source_ip]
    else:
        command = ["ping", "-6" if six else "-4", "-n", "-c", "1", "-W", str(max(1, round(timeout)))]
        if source_ip:
            command += ["-I", source_ip]
    return command + [host]


def icmp_echo_probe(host: str, port: int = 0, timeout: float = 1.5, *, source_ip: str | None = None) -> ProbeOutcome:
    """One ICMP echo request using the OS ping utility (no administrator rights needed)."""
    import subprocess
    _validate_target(host, port, timeout, allow_zero_port=True)
    bound = _bound_source(host, source_ip)
    started = time.perf_counter()
    try:
        result = subprocess.run(_ping_command(host, timeout, bound), capture_output=True, text=True,
                                timeout=float(timeout) + 3, shell=False, encoding="utf-8", errors="replace")
        duration = round((time.perf_counter() - started) * 1000, 2)
    except FileNotFoundError:
        return ProbeOutcome("inconclusive", "icmp_ping_utility_unavailable; not proof of segmentation", 0.0, bound)
    except (subprocess.SubprocessError, OSError):
        duration = round((time.perf_counter() - started) * 1000, 2)
        return ProbeOutcome("inconclusive", "icmp_no_echo_reply; silence is not proof of filtering", min(duration, 60000), bound)
    output = (result.stdout or "").lower()
    # Windows can exit 0 for "destination host unreachable"; require a real echo reply (TTL field).
    if result.returncode == 0 and ("ttl=" in output or "hlim=" in output):
        return ProbeOutcome("reachable", "icmp_echo_reply_received", duration, bound)
    reason = "icmp_destination_unreachable_reported" if "unreachable" in output else "icmp_no_echo_reply"
    return ProbeOutcome("inconclusive", f"{reason}; not proof of segmentation", duration, bound)


PROBE_METHODS = {"udp": udp_request_probe, "icmp": icmp_echo_probe}


def method_probe(protocol: str, host: str, port: int, timeout: float = 1.5, *, source_ip: str | None = None) -> ProbeOutcome:
    """Dispatch one non-TCP attempt to its probe method."""
    try:
        method = PROBE_METHODS[protocol]
    except KeyError as exc:
        raise ValueError(f"No probe method for protocol '{protocol}'") from exc
    return method(host, port, timeout, source_ip=source_ip)


def probe_points(check) -> tuple[int, ...]:
    """Attempts per check: one per port, or a single portless attempt for ICMP."""
    return tuple(check.ports) if check.protocol != "icmp" else (0,)


def _aggregate_check_observation(expected: str, port_states: list[str]) -> str:
    """Aggregate TCP measurements without inferring firewall blocking."""
    if not port_states:
        return "inconclusive"

    if expected == "deny":
        if any(state == "reachable" for state in port_states):
            return "reachable"
        return "inconclusive"

    if all(state == "reachable" for state in port_states):
        return "reachable"

    return "inconclusive"


def probe_policy(
    policy: SegmentationPolicy,
    source_zone: str,
    timeout: float = 1.5,
    probe_func: Callable[[str, int, float], ProbeOutcome] | None = None,
    protocol_probe: Callable[[str, str, int, float], ProbeOutcome] | None = None,
) -> dict:
    """Probe only policy checks originating from the selected source zone.

    The operator must run this from a host actually connected to that zone.
    The zone label alone does not prove network attachment.
    """
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0.1 <= timeout <= 10
    ):
        raise ValueError("Timeout must be between 0.1 and 10 seconds")

    zone_ids = {zone.id for zone in policy.zones}
    if source_zone not in zone_ids:
        raise ValueError(
            f"Unknown source zone '{source_zone}'. Choose one of: "
            f"{', '.join(sorted(zone_ids))}"
        )

    selected_checks = [
        check for check in policy.checks if check.source_zone == source_zone
    ]
    if not selected_checks:
        raise ValueError(
            f"No policy checks originate from source zone '{source_zone}'"
        )

    unsupported = [
        check.id for check in selected_checks if check.protocol not in {"tcp", *PROBE_METHODS}
    ]
    if unsupported:
        raise ValueError(
            "No probe method exists for the protocol in check(s): " + ", ".join(unsupported)
        )

    run_probe = probe_func or tcp_connect_probe
    run_method = protocol_probe or method_probe
    run_started_at = _timestamp()
    run_id = "PROBE-" + uuid.uuid4().hex[:12].upper()
    observations: dict[str, str] = {}
    details: list[dict] = []

    for check in selected_checks:
        port_states: list[str] = []

        for port in probe_points(check):
            probe_started_at = _timestamp()
            if check.protocol == "tcp":
                outcome = run_probe(check.destination_host, port, float(timeout))
            else:
                outcome = run_method(check.protocol, check.destination_host, port, float(timeout))
            probe_completed_at = _timestamp()
            if getattr(outcome, "started_at", None) and getattr(outcome, "completed_at", None):
                # The attempt carries its own timestamps: keep them.
                probe_started_at, probe_completed_at = outcome.started_at, outcome.completed_at

            if not isinstance(outcome, ProbeOutcome):
                raise ValueError("Probe function must return a ProbeOutcome")

            if outcome.state not in {"reachable", "inconclusive"}:
                raise ValueError(
                    f"Probe returned unsupported state '{outcome.state}'. "
                    "Probes may report only reachable or inconclusive; "
                    "firewall blocking requires separate evidence."
                )

            port_states.append(outcome.state)

            details.append({
                "check_id": check.id,
                "check_name": check.name,
                "source_zone": check.source_zone,
                "source_ip": outcome.source_ip,
                "destination_zone": check.destination_zone,
                "destination_host": check.destination_host,
                "protocol": check.protocol,
                "port": port,
                "expected": check.expected,
                "observed": outcome.state,
                "reason": outcome.reason,
                "duration_ms": outcome.duration_ms,
                "started_at": probe_started_at,
                "completed_at": probe_completed_at,
            })

        observations[check.id] = _aggregate_check_observation(
            check.expected, port_states
        )

    return {
        "observations": observations,
        "measurement": {
            "policy_id": policy.policy_id,
        "run_id": run_id,
            "started_at": min([run_started_at] + [d["started_at"] for d in details], key=_sortable),
            "completed_at": max([_timestamp()] + [d["completed_at"] for d in details], key=_sortable),
            "source_zone": source_zone,
            "method": (
                "TCP connect handshake (socket.create_connection), UDP protocol "
                "request/response and ICMP echo (system ping) per check protocol; "
                "source address selected using local UDP route lookup"
            ),
            "timeout_seconds": float(timeout),
            "scope": (
                "Only destination IPs and ports explicitly listed in the "
                "validated policy were tested."
            ),
            "interpretation_limit": (
                "A successful connection proves TCP reachability for that "
                "IP:port at test time. A timeout, refusal, or socket error is "
                "INCONCLUSIVE, not proof of firewall blocking. Source IP is "
                "the address selected by the local OS route lookup. This "
                "probe does not identify a responsible firewall rule or test "
                "application-layer behavior."
            ),
            "details": details,
        },
    }
