"""Read local network facts using fixed OS commands; never scan remote hosts."""
import ipaddress
import json
import platform
import re
import subprocess
import socket
import struct
from pathlib import Path

MAX_OUTPUT = 262144


class DiscoveryUnavailable(ValueError):
    pass


def _run(command, timeout=3):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=True,
                                text=True, encoding="utf-8", errors="replace", shell=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryUnavailable("Local discovery unavailable. Enter network settings manually.") from exc
    if len(result.stdout.encode("utf-8")) > MAX_OUTPUT:
        raise DiscoveryUnavailable("Local discovery output exceeds the supported size.")
    return result.stdout


def _entry(name, address, prefix, gateway=""):
    try:
        interface = ipaddress.ip_interface(f"{address}/{prefix}")
        ip = interface.ip
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return None
        normalized_gateway = str(ipaddress.ip_address(gateway)) if gateway else ""
        if normalized_gateway and ipaddress.ip_address(normalized_gateway).version != ip.version:
            normalized_gateway = ""
        return {"interface": str(name)[:120], "source_ip": str(ip), "cidr": str(interface.network),
                "gateway": normalized_gateway, "family": f"IPv{ip.version}"}
    except (ValueError, TypeError):
        return None


def parse_linux(addresses, routes):
    gateways = {row.get("dev"): row.get("gateway", "") for row in routes if isinstance(row, dict)}
    output = []
    for interface in addresses[:256]:
        for address in interface.get("addr_info", [])[:32]:
            row = _entry(interface.get("ifname", ""), address.get("local"), address.get("prefixlen"),
                         gateways.get(interface.get("ifname"), ""))
            if row:
                output.append(row)
    return output


# Get-NetIPConfiguration takes ~10 s on hosts with several virtual adapters,
# so read addresses and default routes directly (typically ~1.5 s).
WINDOWS_COMMAND = (
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
    "$gw = @{}; "
    "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | ForEach-Object { "
    "if (-not $gw.ContainsKey($_.InterfaceIndex)) { $gw[$_.InterfaceIndex] = @() }; "
    "$gw[$_.InterfaceIndex] += $_.NextHop }; "
    "Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.AddressState -eq 'Preferred' } | "
    "ForEach-Object { [PSCustomObject]@{ Interface = $_.InterfaceAlias; Address = $_.IPAddress; "
    "Prefix = $_.PrefixLength; Gateway = (@($gw[$_.InterfaceIndex]) -join ',') } } | "
    "ConvertTo-Json -Depth 3 -Compress"
)
# PowerShell start-up alone can exceed the generic 3 s budget on a cold host.
WINDOWS_TIMEOUT_SECONDS = 15


def parse_windows(data):
    if isinstance(data, dict):
        data = [data]
    output = []
    for item in data[:256]:
        gateway = ""
        for candidate in str(item.get("Gateway", "")).split(","):
            try:
                if ipaddress.ip_address(candidate).version == ipaddress.ip_address(item["Address"]).version:
                    gateway = candidate
                    break
            except (ValueError, KeyError):
                continue
        row = _entry(item.get("Interface", ""), item.get("Address"), item.get("Prefix"), gateway)
        if row:
            output.append(row)
    return output


def parse_macos(interfaces, route):
    gateway_match = re.search(r"^\s*gateway:\s*([0-9.]+)\s*$", route, re.M)
    interface_match = re.search(r"^\s*interface:\s*(\S+)\s*$", route, re.M)
    default_interface = interface_match.group(1) if interface_match else ""
    name, output = "", []
    for line in interfaces.splitlines()[:8192]:
        if line and not line[0].isspace():
            name = line.split(":", 1)[0]
        match = re.search(r"\binet ([0-9.]+) netmask (0x[0-9a-fA-F]+|[0-9.]+)", line)
        if match:
            mask = match.group(2)
            if mask.startswith("0x"):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            row = _entry(name, match.group(1), mask,
                         gateway_match.group(1) if gateway_match and name == default_interface else "")
            if row:
                output.append(row)
        v6 = re.search(r"\binet6 ([0-9a-fA-F:]+)(?:%\S+)? prefixlen (\d+)", line)
        if v6:
            row = _entry(name, v6.group(1), v6.group(2))
            if row:
                output.append(row)
    return output


def _linux_fallback():
    """IPv4 interface ioctls and procfs route facts when netlink is restricted."""
    import fcntl
    gateways, output = {}, []
    try:
        with Path("/proc/net/route").open() as stream:
            route_text = stream.read(MAX_OUTPUT)
        for line in route_text.splitlines()[1:257]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                gateways[fields[0]] = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
        for interface in list(Path("/sys/class/net").iterdir())[:256]:
            name = interface.name
            if len(name.encode()) > 15:
                continue
            request = struct.pack("256s", name.encode())
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    address = socket.inet_ntoa(fcntl.ioctl(connection.fileno(), 0x8915, request)[20:24])
                    mask = socket.inet_ntoa(fcntl.ioctl(connection.fileno(), 0x891b, request)[20:24])
                row = _entry(name, address, mask, gateways.get(name, ""))
                if row:
                    output.append(row)
            except OSError:
                continue
        return output
    except (OSError, ValueError, struct.error) as exc:
        raise DiscoveryUnavailable("Local discovery is restricted. Use manual configuration.") from exc


def discover_local_network():
    system = platform.system()
    try:
        if system == "Linux":
            try:
                rows = parse_linux(json.loads(_run(["ip", "-j", "address", "show"])),
                                   json.loads(_run(["ip", "-j", "route", "show", "default"])))
            except DiscoveryUnavailable:
                rows = _linux_fallback()
        elif system == "Windows":
            text = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_COMMAND],
                        timeout=WINDOWS_TIMEOUT_SECONDS)
            rows = parse_windows(json.loads(text or "[]"))
        elif system == "Darwin":
            interfaces = _run(["ifconfig"])
            try:
                route = _run(["route", "-n", "get", "default"])
            except DiscoveryUnavailable:
                route = ""
            rows = parse_macos(interfaces, route)
        else:
            raise DiscoveryUnavailable("This OS has no discovery adapter. Use manual configuration.")
    except (ValueError, TypeError, AttributeError) as exc:
        if isinstance(exc, DiscoveryUnavailable):
            raise
        raise DiscoveryUnavailable("Network information could not be decoded. Use manual configuration.") from exc
    unique = {(row["interface"], row["source_ip"]): row for row in rows}
    return {"os": system, "interfaces": list(unique.values())[:256],
            "scope": "This PC only; no remote hosts were scanned."}
