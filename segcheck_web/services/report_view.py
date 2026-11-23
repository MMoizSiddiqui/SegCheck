"""Plain-language reading of a saved report: verdict, one row per rule, every attempt explained.

Used by the report page, the live page, the map and the PDF, so the same words appear everywhere.
Nothing here changes a result: PASS/FAIL/INCONCLUSIVE are decided by the policy engine.
"""
from __future__ import annotations

from segcheck_web.services.report_analysis import analyse, method_label

UDP_NAMES = {"dns_query": "DNS", "ntp_client_request": "NTP", "snmpv3_discovery": "SNMP", "generic_datagram": "UDP"}

# (reason prefix, short label, plain explanation). The first matching prefix wins.
REASONS = [
    ("tcp_connect_succeeded", "Connected",
     "The target accepted a TCP connection on this port (the handshake completed), so this path is open."),
    ("connection_refused", "Refused",
     "The target answered but nothing listens on this port. The network path reaches the host; only this port is closed."),
    ("connection_timeout", "No reply",
     "No reply within the wait. A firewall silently dropped the attempt, or the host is off or does not exist. "
     "Silence alone cannot tell which."),
    ("socket_error_network_unreachable", "No route",
     "This PC has no route to that network, so nothing left the PC."),
    ("socket_error_host_unreachable", "Unreachable",
     "The network reported the host as unreachable (often a router or firewall rejecting it)."),
    ("socket_error_source_address_unavailable", "Address gone",
     "This PC's Step 1 address was no longer available (the network changed), so nothing was sent."),
    ("socket_error_access_denied", "Blocked on this PC",
     "This PC's own security software refused to send the attempt, so it never reached the network."),
    ("socket_error", "Error",
     "The attempt could not be completed because of a local network error."),
    ("udp_", "", ""),  # handled below
    ("icmp_echo_reply_received", "Ping answered",
     "The host answered a ping, so it is reachable at network level."),
    ("icmp_destination_unreachable_reported", "Unreachable",
     "A router or firewall reported the destination as unreachable."),
    ("icmp_ping_utility_unavailable", "Ping unavailable",
     "The ping tool is not available on this PC, so nothing was sent."),
    ("icmp_no_echo_reply", "No ping reply",
     "No ping reply within the wait. A firewall dropped it, ping is disabled on the host, or the host is off."),
]


def explain(reason: str, protocol: str = "") -> dict:
    """{label, text} for one attempt's raw reason code (e.g. 'connection_timeout; not proof …'), plus what happened
    on a second try when the first one was silent (see services/patience.py)."""
    result = _explain(reason, protocol)
    note = next((part.strip() for part in str(reason or "").split(";")[1:] if "2nd try" in part or "in 2 tries" in part), "")
    if note.startswith("answered on the 2nd try"):
        return {"label": result["label"] + " (2nd try)",
                "text": result["text"] + f" The first try got no reply; then it {note}. The path is open."}
    if "blocked by the firewall (its log shows it)" in str(reason or ""):
        return {"label": "Blocked (logged)", "text": result["text"].split(". ")[0] + ". The firewall's own log shows it "
                "blocked this attempt, so the silence is explained: blocked, and proven."}
    if note.startswith("no reply in 2 tries"):
        return {"label": result["label"], "text": result["text"] + f" Tried twice to rule out a lost packet or a slow network: {note}."}
    return result


def _explain(reason: str, protocol: str = "") -> dict:
    code = str(reason or "").split(";")[0].strip()
    if code.startswith("udp_"):
        parts = code[4:]
        service = next((name for key, name in UDP_NAMES.items() if parts.startswith(key)), "UDP")
        if parts.endswith("reply_received"):
            return {"label": "Replied", "text": f"The {service} service answered a real request, so this path is open."}
        if parts.endswith("empty_reply"):
            return {"label": "Empty reply", "text": f"Something answered, but not with a real {service} reply."}
        if "port_unreachable" in parts:
            return {"label": "Port closed", "text": f"The host reported this UDP port closed: it is reachable, but no {service} service runs there."}
        if parts.endswith("no_reply"):
            return {"label": "No reply", "text": f"No {service} reply within the wait. A firewall dropped it, or no service is there."}
        return {"label": "Error", "text": "The UDP attempt could not be completed because of a local network error."}
    for prefix, label, text in REASONS:
        if prefix != "udp_" and code.startswith(prefix):
            return {"label": label, "text": text}
    return {"label": code.replace("_", " ") or "Unknown", "text": "Raw probe result: " + (code.replace("_", " ") or "unknown") + "."}


def glossary() -> list:
    """[(prefix, label, text)] for the live page's JavaScript (same words as the report)."""
    rows = [[prefix, label, text] for prefix, label, text in REASONS if prefix != "udp_"]
    for key, name in UDP_NAMES.items():
        rows += [[f"udp_{key}_reply_received", "Replied", f"The {name} service answered a real request, so this path is open."],
                 [f"udp_{key}_no_reply", "No reply", f"No {name} reply within the wait. A firewall dropped it, or no service is there."],
                 [f"udp_{key}_port_unreachable", "Port closed", f"The host reported this UDP port closed: no {name} service runs there."]]
    return rows


def _service(row) -> str:
    protocol = row.get("protocol", "")
    if protocol == "icmp":
        return "Ping (ICMP)"
    ports = row.get("ports") or []
    return f"{protocol.upper()} {', '.join(str(port) for port in ports)}"


OUTCOMES = {
    "fail": ("Failed", "fail"),
    "open": ("Failed: firewall let it through", "fail"),
    "down": ("Failed: approved service not working", "fail"),
    "proven": ("Passed: blocked, proven by firewall log", "pass"),
    "pass": ("Passed: works as approved", "pass"),
    "unproven": ("No answer: not proven", "unproven"),
    "skipped": ("Not run from this PC", "skipped"),
}


def _rule(item, attempts, firewall_connected):
    row = item["row"]
    expected = row.get("expected")
    reached = [a for a in attempts if a["observed"] == "reachable"]
    if item["result"] == "NOT EXERCISED":
        key = "skipped"
        why = "This rule starts in another network; run the audit from a PC there."
        fix = ""
    elif expected == "deny" and item["result"] == "FAIL":
        key = "fail"
        ports = ", ".join(str(a["port"]) for a in reached if a["protocol"] != "icmp") or "ping"
        why = f"It must be blocked, but it answered ({ports}). Traffic that should be stopped gets through."
        fix = item["guidance"][0] if item.get("guidance") else "Add or correct the firewall rule that blocks this path, then run the audit again."
    elif expected == "deny" and item.get("evidence") == "passed":
        key = "open"
        why = "The target did not answer, but the firewall's own log shows it let the attempt through: the path is open at the boundary."
        fix = "Add a block rule for this path on the firewall, then run the audit again."
    elif expected == "deny" and item.get("evidence") == "corroborated":
        key = "proven"
        why = "Nothing answered, and the firewall's log shows it blocked every attempt. This is proof the path is closed."
        fix = ""
    elif expected == "deny":
        key = "unproven"
        why = ("Nothing answered, which is what you want, but without firewall logs SegCheck cannot tell a firewall block "
               "from a service that is simply off." if not firewall_connected else
               "Nothing answered, but the firewall logged no decision for these attempts: check that its block rules log.")
        fix = "Connect the firewall's logs in Step 3 (and enable logging on its block rules) to turn this into proof."
    elif item["result"] == "PASS":
        key = "pass"
        why = "It must work, and every port answered."
        fix = ""
    else:
        key = "down"
        missing = ", ".join(str(a["port"]) for a in attempts if a["observed"] != "reachable" and a["protocol"] != "icmp") or "ping"
        why = f"It must work, but it did not answer ({missing}). The approved service is down or blocked."
        fix = "Check that the service is running and that no rule blocks this approved flow."
    label, tone = OUTCOMES[key]
    cause = _cause(key, attempts)
    return {"cause": cause, "check_id": row.get("check_id"), "name": row.get("check_name") or row.get("check_id"),
            "host": row.get("destination_host"), "zone": row.get("destination_zone"), "source": row.get("source_zone"),
            "service": _service(row), "method": item.get("method_label") or method_label(item.get("method", "")),
            "expected": "Must be blocked" if expected == "deny" else "Must work",
            "result": item["result"], "outcome": key, "outcome_label": label, "tone": tone,
            "why": why, "fix": fix, "attempts": attempts, "cde": item.get("cde", False),
            "reason": "" if (row.get("rationale") or "").strip() in ("", "Auditor-defined rule.")
            or "(supporting technical check)" in (row.get("rationale") or "") else row["rationale"].strip()}


def _clean_log_rule(label):
    """Older reports stored the syslog header with the log prefix; show only the rule's name."""
    if "SEGCHECK-" in label:
        from segcheck_web.services.rule_attribution import log_rule_label
        return ", ".join(log_rule_label({"format": "iptables", "rule": part}) for part in label.split(", "))
    return label


def _cause(key, attempts):
    """The firewall rule behind this outcome, from its logs and/or the loaded rule export."""
    if key in {"fail", "open"}:
        wanted, relevant = "pass", [a for a in attempts if a["observed"] == "reachable" or a.get("firewall") == "logged_pass"]
    elif key in {"down"}:
        wanted, relevant = "block", [a for a in attempts if a["observed"] != "reachable"]
    elif key in {"proven", "unproven"}:
        wanted, relevant = "block", attempts
    else:
        return None
    logged = list(dict.fromkeys(_clean_log_rule(a["log_rule"]) for a in relevant if a.get("log_rule")))
    configured = [a["config_rule"] for a in relevant if a.get("config_rule") and a["config_rule"].get("action") == wanted]
    if not logged and not configured:
        return None
    config = configured[0] if configured else None
    if key in {"fail", "open"}:
        title = "Let through by firewall rule"
        fix = ("Remove or narrow this rule (or add a more specific block rule above it), then run the audit again."
               if config or logged else "")
    elif key == "down":
        title, fix = "Blocked by firewall rule", "Add an allow rule for this approved service above it, or correct this rule."
    else:
        title, fix = "Blocked by firewall rule", ""
    return {"title": title, "rule": logged[0] if logged else config["label"],
            "source": " + ".join(part for part in ("firewall log" if logged else "", "rule export" if config else "") if part),
            "detail": f"{config['where']}: {config['detail']}" if config else "",
            "uncertain": bool(config and config.get("uncertain")), "fix": fix, "blocking": wanted == "block"}


def build(report: dict) -> dict:
    """Everything the report page needs to read the report in plain language."""
    report = report if isinstance(report, dict) else {}
    assessment = report.get("assessment") if isinstance(report.get("assessment"), dict) else {}
    environment = assessment.get("environment") if isinstance(assessment.get("environment"), dict) else {}
    networks = environment.get("networks", {}) if isinstance(environment.get("networks"), dict) else {}
    analysis = analyse(report, networks)
    details = (report.get("probe_measurement") or {}).get("details", []) if isinstance(report.get("probe_measurement"), dict) else []
    boundary = report.get("boundary_evidence") if isinstance(report.get("boundary_evidence"), dict) else {}
    firewall_by_attempt = {(a.get("check_id"), a.get("port"), a.get("protocol")): a.get("evidence")
                           for a in boundary.get("attempts", []) if isinstance(a, dict)}
    rule_by_attempt = {(a.get("check_id"), a.get("port"), a.get("protocol")): (a.get("log_rule") or "",
                       a.get("config_rule") if isinstance(a.get("config_rule"), dict) else None)
                       for a in boundary.get("attempts", []) if isinstance(a, dict)}
    firewall_connected = any(device.get("connected") for device in boundary.get("devices", []) if isinstance(device, dict))

    attempts_by_check = {}
    for detail in details if isinstance(details, list) else []:
        if not isinstance(detail, dict):
            continue
        reading = explain(detail.get("reason", ""), detail.get("protocol", ""))
        attempts_by_check.setdefault(detail.get("check_id"), []).append({
            "port": detail.get("port"), "protocol": detail.get("protocol"), "observed": detail.get("observed"),
            "label": reading["label"], "text": reading["text"], "ms": detail.get("duration_ms"),
            "firewall": firewall_by_attempt.get((detail.get("check_id"), detail.get("port"), detail.get("protocol"))),
            "host": detail.get("destination_host"),
            "log_rule": rule_by_attempt.get((detail.get("check_id"), detail.get("port"), detail.get("protocol")), ("", None))[0],
            "config_rule": rule_by_attempt.get((detail.get("check_id"), detail.get("port"), detail.get("protocol")), ("", None))[1]})

    rules = [_rule(item, attempts_by_check.get(item["row"].get("check_id"), []), firewall_connected) for item in analysis["checks"]]
    counts = {"rules": len(rules), "passed": sum(r["tone"] == "pass" for r in rules),
              "failed": sum(r["tone"] == "fail" for r in rules), "unproven": sum(r["tone"] == "unproven" for r in rules),
              "skipped": sum(r["tone"] == "skipped" for r in rules)}
    holes = sum(r["outcome"] in {"fail", "open"} for r in rules)
    denies = [r for r in rules if r["expected"] == "Must be blocked" and r["tone"] != "skipped"]
    if holes:
        verdict = ("FAILED", "fail", f"{holes} rule(s) broken",
                   "Something that must be blocked was reachable. The red rows below show where, what answered, and what to fix.")
    elif counts["failed"]:
        verdict = ("ATTENTION", "fail", "An approved service is not working",
                   "No forbidden path was open, but a service that must work did not answer. See the red rows.")
    elif denies and all(r["outcome"] == "proven" for r in denies):
        verdict = ("PASSED", "pass", "Blocked, and proven",
                   "Everything that must be blocked stayed blocked, and the firewall's own logs prove each block.")
    elif denies:
        verdict = ("NO HOLE FOUND", "unproven", "Nothing forbidden answered, but it is not proven",
                   "Nothing that must be blocked answered. Without firewall logs SegCheck cannot prove the firewall blocked it: "
                   "the service may simply be off. Connect the firewall's logs (Step 3) for proof.")
    elif counts["passed"]:
        verdict = ("PASSED", "pass", "Approved services work", "Every service that must work answered. This run had no 'must be blocked' rules.")
    else:
        verdict = ("NOTHING RUN", "unproven", "Nothing was tested from this PC", "All rules start in other networks.")

    problems = run_problems(environment, details if isinstance(details, list) else [], boundary, counts)
    measured = [d for d in details if isinstance(d, dict)] if isinstance(details, list) else []
    if measured and all(str(d.get("reason", "")).split(";")[0].strip() in LOCAL_FAILURE_CODES for d in measured):
        verdict = ("COULD NOT TEST", "fail", "Nothing reached the network",
                   "Every attempt failed on this PC before it reached the network, so this report says nothing about the "
                   "firewall. Fix the problem below and run the audit again.")

    uses_pci = any(r for r in report.get("results", []) if isinstance(r, dict) and (
        r.get("pci_requirements") or any(isinstance(m, dict) and m.get("framework") == "pci_dss" for m in r.get("framework_mappings") or [])))
    standards = sorted({str(m.get("framework")) for r in report.get("results", []) if isinstance(r, dict)
                        for m in r.get("framework_mappings") or [] if isinstance(m, dict) and m.get("framework")})
    return {"verdict": {"word": verdict[0], "tone": verdict[1], "title": verdict[2], "sentence": verdict[3]},
            "counts": counts, "rules": rules, "uses_pci": uses_pci, "standards": standards, "problems": problems,
            "firewall_connected": firewall_connected, "analysis": analysis,
            "source_ip": environment.get("source_ip", ""), "source_zone": assessment.get("source_zone") or environment.get("source_zone", ""),
            "networks": networks}


LOCAL_FAILURE_CODES = {
    "socket_error_source_address_unavailable": (
        "This PC's Step 1 address was not available for {n} attempt(s) (the PC changed network or lost its connection).",
        "Open New audit, Step 1, pick the network this PC is in now, then run the audit again."),
    "socket_error_access_denied_by_local_policy": (
        "Security software on this PC refused to send {n} attempt(s).",
        "Allow Python / SegCheck in this PC's firewall or antivirus, then run the audit again."),
}


def run_problems(environment: dict, details: list, boundary: dict, counts: dict) -> list:
    """What limited this run, in plain words, each with what to do: shown at the top of the report."""
    problems = []
    devices = [d for d in environment.get("devices", []) if isinstance(d, dict)] if isinstance(environment, dict) else []
    logging_device = next((d for d in devices if d.get("logging")), None)
    firewall = next((d for d in devices if d.get("kind") not in (None, "none")), None)
    summary = boundary.get("summary", {}) if isinstance(boundary.get("summary"), dict) else {}
    logged = int(summary.get("logged_block", 0) or 0) + int(summary.get("logged_pass", 0) or 0)
    unmatched = int(summary.get("no_matching_log", 0) or 0) + int(summary.get("not_connected", 0) or 0)
    codes = [str(d.get("reason", "")).split(";")[0].strip() for d in details if isinstance(d, dict)]

    for code, (what, fix) in LOCAL_FAILURE_CODES.items():
        if code in codes:
            problems.append({"tone": "fix", "title": "Some attempts never reached the network",
                             "text": what.format(n=codes.count(code)), "fix": fix})
    no_route = "socket_error_network_unreachable"  # not a broken setup: that network is just not routed from this PC
    if no_route in codes:
        hosts = sorted({str(d.get("destination_host")) for d in details if isinstance(d, dict)
                        and str(d.get("reason", "")).startswith(no_route)})
        problems.append({"tone": "info", "title": "No route from this PC to some targets",
                         "text": f"{codes.count(no_route)} attempt(s) to {', '.join(hosts[:6])}{' …' if len(hosts) > 6 else ''} "
                                 "never left this PC: it has no route to them. That network is not reachable from here, which "
                                 "keeps it apart, but the firewall itself was not tested on those paths.",
                         "fix": "If that network should be reachable through the firewall, check this PC's connection and "
                                "routes (and Step 2), then run the audit again."})
    if logging_device and not logged and unmatched:
        problems.append({"tone": "fix", "title": "The firewall's logs did not arrive",
                         "text": "Step 3 says the firewall sends its logs to this PC, but no log line matched any attempt. "
                                 "So nothing that stayed silent could be proven as blocked.",
                         "fix": "Do Step 3b on the firewall (send its logs to this PC, log its block rules), wait until Step 3 "
                                "shows 'Logs arriving', then run the audit again."})
    elif logging_device and logged and int(summary.get("no_matching_log", 0) or 0):
        problems.append({"tone": "fix", "title": "The firewall logged only some attempts",
                         "text": f"{logged} attempt(s) were found in the firewall's log, {summary.get('no_matching_log')} were "
                                 "not: some of its rules do not write a log line.",
                         "fix": "Turn on logging for every rule between this PC's network and the targets (including the final "
                                "block rule), then run the audit again."})
    elif firewall and not logging_device and counts.get("unproven"):
        problems.append({"tone": "fix", "title": "No firewall log feed, so blocks cannot be proven",
                         "text": "The firewall's logs were not connected in Step 3, so attempts that stayed silent are reported as "
                                 "'not proven' rather than passed." + (" SegCheck cannot read logs from the firewall type chosen "
                                 "('Other')." if firewall.get("kind") == "other" else ""),
                         "fix": "In Step 3a choose the firewall's type and tick 'Connect its logs', do Step 3b, then run the "
                                "audit again." if firewall.get("kind") != "other" else
                                "Nothing to fix in SegCheck: keep these results as 'not proven', or ask for the firewall's "
                                "logs another way and attach them to the audit file."})
    elif not firewall and counts.get("unproven"):
        problems.append({"tone": "fix", "title": "No firewall declared, so blocks cannot be proven",
                         "text": "Step 3 says there is no firewall (or it is unknown), so silent attempts stay 'not proven'.",
                         "fix": "If a firewall separates these networks, choose 'There is a firewall' in Step 3, connect its "
                                "logs (3b), then run the audit again."})
    if int(summary.get("contradictions", 0) or 0):
        problems.append({"tone": "fix", "title": "The firewall's log and the result disagree",
                         "text": f"{summary.get('contradictions')} attempt(s) were logged as blocked, yet the target answered. "
                                 "Another path (a second router, VPN or NAT) may lead around this firewall.",
                         "fix": "Check for other routes between the two networks, then run the audit again."})
    second = sum("answered on the 2nd try" in str(d.get("reason", "")) for d in details if isinstance(d, dict))
    if second:
        problems.append({"tone": "info", "title": "The network was slow or lost packets",
                         "text": f"{second} attempt(s) answered only on the second try. The results are still right "
                                 "(SegCheck tries a silent attempt twice), but the network was slow during this run.",
                         "fix": ""})
    return problems


def map_data(record) -> dict:
    """The run as a map: this PC, its target networks and hosts, each host's outcome, and the attempts in order."""
    view = build(record.report)
    networks = view["networks"]
    snapshot = record.policy_version.snapshot if record.policy_version is not None and isinstance(record.policy_version.snapshot, dict) else {}
    names = {z.get("id"): z.get("name") for z in snapshot.get("zones", []) if isinstance(z, dict)}
    environment = ((record.report or {}).get("assessment") or {}).get("environment") or {}
    zones = {}
    worst = {"fail": 3, "unproven": 2, "pass": 1, "skipped": 0}
    for rule in view["rules"]:
        zone = zones.setdefault(rule["zone"], {"key": rule["zone"], "name": names.get(rule["zone"]) or rule["zone"],
                                                "role": networks.get(rule["zone"], {}).get("role", "custom"),
                                                "cidr": networks.get(rule["zone"], {}).get("cidr", ""), "hosts": {}})
        host = zone["hosts"].setdefault(rule["host"], {"ip": rule["host"], "tone": "skipped", "rules": []})
        host["rules"].append({"name": rule["name"], "service": rule["service"], "expected": rule["expected"],
                              "outcome": rule["outcome_label"], "tone": rule["tone"], "why": rule["why"], "fix": rule["fix"]})
        if worst[rule["tone"]] > worst[host["tone"]]:
            host["tone"] = rule["tone"]
    details = (record.report.get("probe_measurement") or {}).get("details", []) if isinstance(record.report, dict) else []
    attempts = []
    for detail in details if isinstance(details, list) else []:
        if isinstance(detail, dict):
            reading = explain(detail.get("reason", ""), detail.get("protocol", ""))
            attempts.append({"host": detail.get("destination_host"), "port": detail.get("port"), "protocol": detail.get("protocol"),
                             "observed": detail.get("observed"), "label": reading["label"]})
    return {"id": record.id, "name": record.policy.name if record.policy else f"Audit {record.id}",
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "verdict": view["verdict"], "source_ip": view["source_ip"], "source_zone": view["source_zone"],
            "source_name": names.get(view["source_zone"]) or environment.get("site") or view["source_zone"],
            "zones": [{**zone, "hosts": list(zone["hosts"].values())} for zone in zones.values()],
            "attempts": attempts[:400], "url": f"/assessments/{record.id}"}


BAD_OUTCOMES = {"fail", "open", "down"}


def _rule_key(rule):
    ports = tuple(sorted({a["port"] for a in rule["attempts"] if isinstance(a.get("port"), int) and a.get("protocol") != "icmp"}))
    protocol = next((a["protocol"] for a in rule["attempts"]), "")
    return (rule.get("host"), protocol, ports, rule["expected"])


def compare(older: dict, newer: dict) -> dict:
    """Drift and regression between two audits: what was fixed, what broke, what stayed the same."""
    before = {_rule_key(r): r for r in build(older)["rules"] if r["outcome"] != "skipped"}
    after_view = build(newer)
    after = {_rule_key(r): r for r in after_view["rules"] if r["outcome"] != "skipped"}
    rows = {"regression": [], "fixed": [], "still_failing": [], "unchanged": [], "new": [], "gone": []}
    for key in list(dict.fromkeys(list(before) + list(after))):
        old, new = before.get(key), after.get(key)
        if old and new:
            old_bad, new_bad = old["outcome"] in BAD_OUTCOMES, new["outcome"] in BAD_OUTCOMES
            kind = ("regression" if new_bad and not old_bad else "fixed" if old_bad and not new_bad
                    else "still_failing" if new_bad else "unchanged")
        else:
            kind = "new" if new else "gone"
        item = new or old
        ports = ", ".join(str(p) for p in key[2]) or "ping"
        rows[kind].append({"what": f"{item['host']} · {key[1].upper()} {ports}", "expected": key[3],
                           "before": old["outcome_label"] if old else "not tested", "before_tone": old["tone"] if old else "skipped",
                           "after": new["outcome_label"] if new else "not tested", "after_tone": new["tone"] if new else "skipped"})
    if rows["regression"]:
        headline = ("REGRESSION", "fail", f"{len(rows['regression'])} path(s) got worse since the earlier audit",
                    "Something that held before now fails: a change (firewall rule, new service, routing) opened it. See the red rows.")
    elif rows["fixed"] and not rows["still_failing"]:
        headline = ("FIXED", "pass", f"{len(rows['fixed'])} finding(s) fixed, nothing got worse",
                    "The retest proves the remediation: every path that failed before now holds.")
    elif rows["still_failing"]:
        headline = ("STILL FAILING", "fail", f"{len(rows['still_failing'])} finding(s) not fixed yet",
                    "No new problems, but earlier findings are still open.")
    else:
        headline = ("NO DRIFT", "pass", "Same results as the earlier audit", "Nothing changed between the two audits.")
    return {"headline": {"word": headline[0], "tone": headline[1], "title": headline[2], "sentence": headline[3]},
            "rows": rows, "counts": {key: len(value) for key, value in rows.items()}}
