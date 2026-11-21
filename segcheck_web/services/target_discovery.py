"""Find hosts in a target network, so the auditor can tick them instead of typing.

Two ways, both limited to the network the auditor entered:
* known hosts: what this PC already knows without sending anything (its neighbour/ARP table and its
  default gateways);
* ping sweep (only after explicit authorisation): one ping to every address of the network, at most
  256 addresses, then the neighbour table is read again (hosts that ignore ping still answer ARP when
  they are in the same network as this PC).
Names come from reverse DNS when it answers quickly.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, wait

from segcheck.probe import icmp_echo_probe

MAX_SWEEP_ADDRESSES = 256
SWEEP_WORKERS = 48
PING_TIMEOUT = 1.0
NAME_TIMEOUT = 1.5


class DiscoveryError(ValueError):
    pass


def _run(command):
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return subprocess.run(command, capture_output=True, text=True, timeout=5, creationflags=flags).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def neighbour_table():
    """{ip: mac} from the operating system's ARP/neighbour cache (read only, nothing is sent)."""
    found = {}
    if sys.platform == "win32":
        for line in _run(["arp", "-a"]).splitlines():
            match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if match:
                found[match.group(1)] = match.group(2).replace("-", ":").lower()
    else:
        for line in _run(["ip", "neigh"]).splitlines():
            parts = line.split()
            if parts and "lladdr" in parts and "FAILED" not in parts:
                found[parts[0]] = parts[parts.index("lladdr") + 1].lower()
    return found


def _usable(address, network):
    ip = ipaddress.ip_address(address)
    if ip not in network or ip.is_multicast or ip.is_loopback or ip.is_unspecified:
        return False
    if network.version == 4 and network.prefixlen < 31 and ip in (network.network_address, network.broadcast_address):
        return False
    return True


def _names(addresses):
    """Reverse DNS names, best effort and time-boxed."""
    names = {}
    if not addresses:
        return names
    pool = ThreadPoolExecutor(max_workers=16)
    futures = {pool.submit(socket.gethostbyaddr, address): address for address in addresses}
    done, _ = wait(futures, timeout=NAME_TIMEOUT)
    for future in done:
        try:
            names[futures[future]] = future.result()[0]
        except (OSError, IndexError):
            pass
    pool.shutdown(wait=False, cancel_futures=True)
    return names


def _network(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise DiscoveryError("Enter the target network as a subnet, for example 10.30.0.0/24.") from exc


def known_hosts(cidr, gateways=()):
    """Hosts in this network that this PC already knows about. Sends nothing."""
    network = _network(cidr)
    table = neighbour_table()
    hosts = {}
    for address, mac in table.items():
        if _usable(address, network) and mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
            hosts[address] = {"address": address, "seen": "known to this PC (neighbour table)", "mac": mac}
    for gateway in gateways:
        if gateway and _usable(gateway, network):
            hosts.setdefault(gateway, {"address": gateway, "seen": "a gateway of this PC", "mac": table.get(gateway, "")})
    names = _names(list(hosts))
    rows = [{**row, "name": names.get(row["address"], "")} for row in hosts.values()]
    return sorted(rows, key=lambda row: ipaddress.ip_address(row["address"]))


def ping_sweep(cidr, source_ip=None):
    """Ping every address of a network of at most 256 addresses, then re-read the neighbour table."""
    network = _network(cidr)
    if network.num_addresses > MAX_SWEEP_ADDRESSES:
        raise DiscoveryError(f"{network} has {network.num_addresses} addresses; a sweep covers at most "
                             f"{MAX_SWEEP_ADDRESSES} (a /24). Sweep one /24 part of it, or type the hosts.")
    addresses = [str(ip) for ip in (network.hosts() if network.num_addresses > 2 else network)]
    answered = set()

    def ping(address):
        outcome = icmp_echo_probe(address, 0, PING_TIMEOUT, source_ip=source_ip)
        if outcome.state == "reachable":
            answered.add(address)

    with ThreadPoolExecutor(max_workers=SWEEP_WORKERS) as pool:
        list(pool.map(ping, addresses))
    table = neighbour_table()
    hosts = {address: {"address": address, "seen": "answered ping", "mac": table.get(address, "")} for address in answered}
    for address, mac in table.items():
        if address not in hosts and _usable(address, network) and mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
            hosts[address] = {"address": address, "seen": "answered ARP (ignores ping)", "mac": mac}
    names = _names(list(hosts))
    rows = [{**row, "name": names.get(row["address"], "")} for row in hosts.values()]
    return {"network": str(network), "pinged": len(addresses),
            "hosts": sorted(rows, key=lambda row: ipaddress.ip_address(row["address"]))}
