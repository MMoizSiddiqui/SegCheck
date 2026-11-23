"""Which firewall rule decided an attempt.

Two independent sources, both read-only:

* the firewall's own log line (pfSense filterlog carries the rule's tracker number, Linux iptables/nftables
  carries the log prefix), and
* an optional rule export the auditor loads in Step 3: pfSense/OPNsense ``config.xml`` or Linux
  ``iptables-save`` output. SegCheck evaluates it the way the firewall does (first matching rule wins) to
  name the rule that most likely permitted or blocked a path, even without logs.

Nothing here changes PASS/FAIL; it explains *why* a path is open and *which rule* to change.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import xml.etree.ElementTree as ET

MAX_RULES = 2000
MAX_EXPORT_BYTES = 1024 * 1024


class RuleExportError(ValueError):
    """The rule export could not be read; the message says why in plain words."""


# --------------------------------------------------------------------------- parsing
def parse_export(text: str) -> dict:
    """{'kind': 'pfsense'|'iptables', 'rules': [...], 'interfaces': {...}} from config.xml or iptables-save."""
    if not text or not text.strip():
        raise RuleExportError("The file is empty.")
    if len(text.encode("utf-8", "ignore")) > MAX_EXPORT_BYTES:
        raise RuleExportError("The file is larger than 1 MB; export only the firewall rules.")
    head = text.lstrip()[:400].lower()
    if head.startswith("<?xml") or "<pfsense" in head or "<opnsense" in head:
        return _parse_pfsense(text)
    if re.search(r"^-A \S+", text, re.M) or "*filter" in text:
        return _parse_iptables(text)
    raise RuleExportError("Not a rule export SegCheck understands. Use pfSense/OPNsense Diagnostics > Backup "
                          "(config.xml) or, on Linux, the output of: iptables-save")


def _text(node, path, default=""):
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else default


def _parse_pfsense(text):
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise RuleExportError("The XML file contains a DOCTYPE/ENTITY declaration; export config.xml again.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise RuleExportError(f"config.xml could not be read ({exc}).") from exc
    interfaces = {}
    for iface in list(root.find("interfaces") if root.find("interfaces") is not None else []):
        address, bits = _text(iface, "ipaddr"), _text(iface, "subnet")
        try:
            network = str(ipaddress.ip_network(f"{address}/{bits}", strict=False)) if address and bits else ""
        except ValueError:
            network = ""
        interfaces[iface.tag] = {"name": _text(iface, "descr") or iface.tag.upper(), "network": network,
                                 "address": address if network else ""}
    webgui = root.find("system/webgui")
    management = {
        # pfSense's built-in anti-lockout rule lets anyone on LAN reach the web admin (and SSH) on the LAN address,
        # before any user rule, unless it was switched off (System > Advanced > Admin Access).
        "antilockout": "lan" in interfaces and (webgui is None or webgui.find("noantilockout") is None),
        "webgui_port": int(_text(webgui, "port") or 0) if _text(webgui, "port").isdigit() else 0,
        "webgui_protocol": _text(webgui, "protocol") or "https",
        "ssh_port": int(_text(root, "system/ssh/port") or 22) if (_text(root, "system/ssh/port") or "22").isdigit() else 22,
        "ssh_enabled": root.find("system/ssh/enable") is not None or root.find("system/enablesshd") is not None,
    }
    aliases = {}
    for alias in root.iter("alias"):
        aliases[_text(alias, "name")] = {"type": _text(alias, "type"), "values": _text(alias, "address").split()}
    rules = []
    filter_node = root.find("filter")
    for number, rule in enumerate(filter_node.findall("rule") if filter_node is not None else [], start=1):
        if rule.find("disabled") is not None:
            continue
        action = {"pass": "pass", "block": "block", "reject": "block"}.get(_text(rule, "type", "pass"), "pass")
        protocol = _text(rule, "protocol", "any").lower()
        rules.append({
            "number": number, "tracker": _text(rule, "tracker"), "action": action,
            "interfaces": [part for part in _text(rule, "interface").split(",") if part],
            "floating": _text(rule, "floating") == "yes",
            "protocols": ["tcp", "udp"] if protocol == "tcp/udp" else ["any"] if protocol in {"", "any"} else [protocol],
            "source": _endpoint(rule.find("source"), interfaces, aliases),
            "destination": _endpoint(rule.find("destination"), interfaces, aliases),
            "ports": _ports(_text(rule.find("destination"), "port"), aliases),
            "label": _text(rule, "descr") or f"Rule {number}",
        })
        if len(rules) >= MAX_RULES:
            break
    if not rules:
        raise RuleExportError("config.xml has no enabled firewall rules.")
    return {"kind": "pfsense", "rules": rules, "interfaces": interfaces, "management": management}


def _endpoint(node, interfaces, aliases):
    """{'any': bool, 'not': bool, 'networks': [cidr...]}; an unresolvable alias makes it 'unknown'."""
    if node is None or node.find("any") is not None:
        return {"any": True, "not": False, "networks": [], "text": "any"}
    negate = node.find("not") is not None
    network, address = _text(node, "network"), _text(node, "address")
    nets, text = [], network or address or "any"
    if network == "(self)":  # "This firewall": every address of the firewall itself
        nets = [f"{iface['address']}/32" for iface in interfaces.values() if iface.get("address")]
        text = "This firewall (self)"
    elif network:
        name = network[:-2] if network.endswith("ip") else network
        iface = interfaces.get(name, {})
        if network.endswith("ip") and iface.get("address"):
            nets = [f"{iface['address']}/32"]
        elif iface.get("network"):
            nets = [iface["network"]]
        text = f"{iface.get('name', network)} {'address' if network.endswith('ip') else 'net'}"
    elif address:
        nets = _resolve(address, aliases)
    if not nets:
        return {"any": False, "not": negate, "networks": [], "unknown": True, "text": text}
    return {"any": False, "not": negate, "networks": nets, "text": ("not " if negate else "") + text}


def _resolve(value, aliases, depth=0):
    if depth > 5:
        return []
    try:
        return [str(ipaddress.ip_network(value, strict=False))]
    except ValueError:
        pass
    alias = aliases.get(value)
    if not alias or alias["type"] not in {"host", "network"}:
        return []
    out = []
    for item in alias["values"]:
        out += _resolve(item, aliases, depth + 1)
    return out


def _ports(value, aliases):
    """None = any port; else a list of (low, high)."""
    if not value:
        return None
    ranges = []
    items = aliases[value]["values"] if value in aliases and aliases[value]["type"] == "port" else [value]
    for item in items:
        low, _, high = item.replace("-", ":").partition(":")
        try:
            ranges.append((int(low), int(high or low)))
        except ValueError:
            return None
    return ranges


def _parse_iptables(text):
    """FORWARD (traffic through the firewall) and INPUT (traffic to the firewall itself) rules."""
    table = re.search(r"^\*filter\s*$(.*?)^COMMIT\s*$", text, re.M | re.S)
    if table:  # iptables-save lists every table (nat, mangle...); the firewall's rules are the filter table
        text = table.group(1)
    forward = _parse_iptables_chain(text, "FORWARD")
    local = _parse_iptables_chain(text, "INPUT")
    if not forward and not local:
        raise RuleExportError("No FORWARD rules found in the iptables-save output.")
    return {"kind": "iptables", "rules": forward, "input_rules": local, "interfaces": {}}


def _parse_iptables_chain(text, chain):
    rules, pending_label = [], {}
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.startswith(f"-A {chain} ") and not line.startswith(f"-A {chain.lower()} "):
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        opts = _iptables_options(words)
        target = opts.get("-j", "")
        match_key = (opts.get("-s"), opts.get("-d"), opts.get("-p"), opts.get("ports"))
        if target in {"NFLOG", "LOG"}:
            prefix = opts.get("--nflog-prefix") or opts.get("--log-prefix") or ""
            pending_label[match_key] = re.sub(r"^SEGCHECK-(ACCEPT|DROP)\s*", "", prefix.strip()) or prefix.strip()
            continue
        if target not in {"ACCEPT", "DROP", "REJECT"}:
            continue
        if "ESTABLISHED" in (opts.get("--ctstate") or "") or "ESTABLISHED" in (opts.get("--state") or ""):
            continue
        if opts.get("-i") == "lo":
            continue  # the firewall talking to itself
        label = opts.get("--comment") or pending_label.get(match_key) or f"{chain} rule {len(rules) + 1}"
        rules.append({
            "number": len(rules) + 1, "line": line_no, "tracker": "", "action": "pass" if target == "ACCEPT" else "block",
            "interfaces": [], "floating": True,
            "protocols": [opts["-p"].lower()] if opts.get("-p") else ["any"],
            "source": _cidr_endpoint(opts.get("-s")), "destination": _cidr_endpoint(opts.get("-d")),
            "ports": _ports_list(opts.get("ports")), "label": label, "text": line[:200], "chain": chain,
        })
        if len(rules) >= MAX_RULES:
            break
    policy = re.search(rf"^:{chain} (ACCEPT|DROP)", text, re.M)
    if policy and (rules or chain == "FORWARD"):
        rules.append({"number": len(rules) + 1, "line": 0, "tracker": "", "action": "pass" if policy.group(1) == "ACCEPT" else "block",
                      "interfaces": [], "floating": True, "protocols": ["any"], "source": _cidr_endpoint(None),
                      "destination": _cidr_endpoint(None), "ports": None, "chain": chain,
                      "label": f"{chain} chain default policy ({policy.group(1)})", "text": f":{chain} {policy.group(1)}"})
    elif policy and chain == "INPUT":
        rules.append({"number": 1, "line": 0, "tracker": "", "action": "pass" if policy.group(1) == "ACCEPT" else "block",
                      "interfaces": [], "floating": True, "protocols": ["any"], "source": _cidr_endpoint(None),
                      "destination": _cidr_endpoint(None), "ports": None, "chain": chain,
                      "label": f"INPUT chain default policy ({policy.group(1)})" +
                               (": no rule protects the firewall itself" if policy.group(1) == "ACCEPT" else ""),
                      "text": f":INPUT {policy.group(1)}"})
    return rules


def _iptables_options(words):
    opts, i = {}, 0
    while i < len(words):
        word = words[i]
        value = words[i + 1] if i + 1 < len(words) else ""
        if word in {"-s", "--source", "-d", "--destination", "-p", "--protocol", "-j", "--jump", "--comment", "-i", "--in-interface",
                    "--nflog-prefix", "--log-prefix", "--ctstate", "--state", "--dport", "--dports", "--destination-port"}:
            key = {"--source": "-s", "--destination": "-d", "--protocol": "-p", "--jump": "-j", "--in-interface": "-i"}.get(word, word)
            if key in {"--dport", "--dports", "--destination-port"}:
                key = "ports"
            opts[key] = value
            i += 2
            continue
        i += 1
    return opts


def _cidr_endpoint(value):
    if not value:
        return {"any": True, "not": False, "networks": [], "text": "any"}
    try:
        return {"any": False, "not": False, "networks": [str(ipaddress.ip_network(value, strict=False))], "text": value}
    except ValueError:
        return {"any": False, "not": False, "networks": [], "unknown": True, "text": value}


def _ports_list(value):
    if not value:
        return None
    ranges = []
    for part in value.split(","):
        low, _, high = part.partition(":")
        try:
            ranges.append((int(low), int(high or low)))
        except ValueError:
            return None
    return ranges


# --------------------------------------------------------------------------- evaluation
def _in(endpoint, ip):
    if endpoint.get("any"):
        return True
    if endpoint.get("unknown"):
        return None
    hit = any(ip in ipaddress.ip_network(net) for net in endpoint["networks"])
    return (not hit) if endpoint.get("not") else hit


def first_match(ruleset: dict | None, source_ip: str, destination_ip: str, protocol: str, port: int | None,
                to_device: bool = False) -> dict | None:
    """The rule the firewall applies first to this attempt, or None when the export cannot tell.

    to_device: the attempt is aimed at one of the firewall's own addresses (its management plane). Linux then uses
    the INPUT chain instead of FORWARD; pfSense uses the same interface rules, after its anti-lockout rule."""
    if not ruleset or not (ruleset.get("input_rules") if to_device and ruleset.get("kind") == "iptables" else ruleset.get("rules")):
        return None
    src, dst = ipaddress.ip_address(source_ip), ipaddress.ip_address(destination_ip)
    ingress = None
    for key, iface in ruleset.get("interfaces", {}).items():
        if iface.get("network") and src in ipaddress.ip_network(iface["network"]):
            ingress = key
    rules = ruleset["rules"]
    if to_device and ruleset["kind"] == "iptables":
        rules = ruleset.get("input_rules")
        if not rules:
            return None  # an older export without the INPUT chain: SegCheck cannot tell
    if to_device and ruleset["kind"] == "pfsense":
        lockout = _anti_lockout(ruleset, ingress, dst, protocol, port)
        if lockout:
            return lockout
    uncertain = False
    for rule in rules:
        if not rule["floating"] and ingress and ingress not in rule["interfaces"]:
            continue
        if "any" not in rule["protocols"] and protocol not in rule["protocols"]:
            continue
        if rule["ports"] is not None and protocol in {"tcp", "udp"}:
            if port is None or not any(low <= port <= high for low, high in rule["ports"]):
                continue
        matches = (_in(rule["source"], src), _in(rule["destination"], dst))
        if False in matches:
            continue
        if None in matches:
            uncertain = True  # an alias SegCheck cannot resolve: keep looking, but say so
            continue
        return {**_summary(rule, ruleset["kind"]), "uncertain": uncertain}
    if ruleset["kind"] == "pfsense":
        return {"label": "pfSense default deny (no rule matched)", "action": "block", "number": None, "tracker": "",
                "where": "implicit", "uncertain": uncertain}
    return None


def _anti_lockout(ruleset, ingress, dst, protocol, port):
    management = ruleset.get("management") or {}
    lan = ruleset.get("interfaces", {}).get("lan", {})
    if not management.get("antilockout") or ingress != "lan" or protocol != "tcp" or str(dst) != lan.get("address"):
        return None
    web = management.get("webgui_port") or (443 if management.get("webgui_protocol") == "https" else 80)
    ports = {web, 80, 443} | ({management.get("ssh_port", 22)} if management.get("ssh_enabled") else set())
    if port not in ports:
        return None
    return {"label": "pfSense anti-lockout rule (built in)", "action": "pass", "number": None, "tracker": "",
            "where": "automatic rule before all LAN rules",
            "detail": f"pass LAN net → LAN address tcp {', '.join(str(p) for p in sorted(ports))}. Turn it off in System > "
                      "Advanced > Admin Access (Anti-lockout) once a rule allows admin access only from the management network.",
            "text": "", "uncertain": False}


def _summary(rule, kind):
    ports = ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in rule["ports"]) if rule["ports"] else "any port"
    where = (f"rule {rule['number']} (tracker {rule['tracker']})" if kind == "pfsense" and rule.get("tracker")
             else f"rule {rule['number']}" if kind == "pfsense" else f"{rule.get('chain', 'FORWARD')} rule {rule['number']}")
    return {"label": rule["label"], "action": rule["action"], "number": rule["number"], "tracker": rule.get("tracker", ""),
            "where": where, "detail": f"{rule['action']} {rule['source']['text']} → {rule['destination']['text']} "
                                      f"{'/'.join(rule['protocols'])} {ports}".strip(),
            "text": rule.get("text", "")}


def log_rule_label(event: dict, ruleset: dict | None = None) -> str:
    """A readable rule name from one logged firewall decision."""
    rule = str(event.get("rule") or "").strip()
    if not rule:
        return ""
    if event.get("format") == "pf_filterlog" or rule.isdigit():
        for item in (ruleset or {}).get("rules", []):
            if item.get("tracker") and item["tracker"] == rule:
                return f"{item['label']} (tracker {rule})"
        return f"pfSense rule tracker {rule}"
    tag = rule.rsplit(": ", 1)[-1].strip()  # drop the syslog header (time, host, program)
    name = re.sub(r"^SEGCHECK-(ACCEPT|DROP)\s*", "", tag).strip()
    if name:
        return name
    return {"SEGCHECK-DROP": "final drop-and-log rule (SEGCHECK-DROP)",
            "SEGCHECK-ACCEPT": "allow rule (SEGCHECK-ACCEPT)"}.get(tag, tag)
