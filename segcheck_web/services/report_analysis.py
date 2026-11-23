"""Analyst view of one saved assessment: summary, control matrix, heatmap, guidance.

Computed on read from the immutable stored report; nothing here changes a saved
result. Firewall evidence informs the narrative but never the PASS/FAIL/INCONCLUSIVE
decision, which stays exactly as evaluated.
"""

from __future__ import annotations

from collections import OrderedDict

from segcheck_web.services.standard_packs import PROBE_GROUPS

FRAMEWORK_NAMES = {"pci_dss": "PCI DSS", "nist_sp800_53": "NIST SP 800-53", "iso27002": "ISO/IEC 27002",
                   "cis_controls": "CIS Controls", "nist_csf": "NIST CSF"}
METHOD_ORDER = ["remote_admin", "database", "web_app", "file_directory", "infra_udp", "icmp", "mgmt_plane", "mgmt_plane_udp"]
SHORT = {"remote_admin": "Remote admin", "database": "Databases", "web_app": "Web/app", "file_directory": "File/directory",
         "infra_udp": "Infra UDP", "icmp": "ICMP", "mgmt_plane": "Mgmt plane", "mgmt_plane_udp": "Mgmt SNMP"}

FAIL_ACTION = {
    "remote_admin": "Remove any rule that lets {source} reach remote administration on {host}. Administration should only come from a hardened jump host in an approved management zone.",
    "database": "Block direct database access from {source} to {host}. Only the application tier that needs it should reach database ports, never user or guest networks.",
    "web_app": "Restrict the web/application ports on {host} to approved sources. If {source} has no business need, deny it at the boundary.",
    "file_directory": "Block SMB, NetBIOS, LDAP and NFS from {source} to {host}. These protocols enable lateral movement and credential theft.",
    "infra_udp": "Deny DNS/NTP/SNMP from {source} to {host}, or point {source} at its own approved infrastructure servers.",
    "icmp": "Drop ICMP echo from {source} to {host}. Reachability by ping helps attackers map the protected network.",
    "mgmt_plane": "The firewall's admin service answered {source} on its address {host}. Allow firewall management (SSH/HTTP/HTTPS) only from the management network, on every firewall address, not just the one facing {source}.",
    "mgmt_plane_udp": "The firewall's SNMP answered {source} on its address {host}. Disable SNMP on that address or restrict it to the monitoring server.",
}


def _method(row):
    """Name the probe group a check belongs to (each group's protocol + port set is unique)."""
    ports = sorted(row.get("ports") or [])
    protocol = row.get("protocol")
    for key in METHOD_ORDER:
        group = PROBE_GROUPS[key]
        if group["protocol"] == protocol and sorted(group["ports"]) == ports:
            return key
    if protocol == "icmp":
        return "icmp"
    return "custom:" + f"{(protocol or '?').upper()} {', '.join(str(p) for p in ports)}".strip()


def method_label(key):
    return SHORT.get(key, key.split(":", 1)[-1])


def _evidence_by_check(report):
    out = {}
    boundary = report.get("boundary_evidence") if isinstance(report.get("boundary_evidence"), dict) else {}
    for attempt in boundary.get("attempts", []) or []:
        if isinstance(attempt, dict):
            bucket = out.setdefault(attempt.get("check_id"), {})
            bucket[attempt.get("evidence", "unknown")] = bucket.get(attempt.get("evidence", "unknown"), 0) + 1
    return out


def _evidence_state(counts):
    """Summarise per-check firewall evidence into one label."""
    if not counts:
        return "none"
    if counts.get("logged_pass"):
        return "passed"
    total = sum(counts.values())
    if counts.get("logged_block") == total:
        return "corroborated"
    if counts.get("same_zone") == total:
        return "same_zone"
    if counts.get("logged_block"):
        return "partial"
    if counts.get("not_connected"):
        return "not_connected"
    return "no_log"


def guidance(row, method, evidence, skipped):
    source, host = row.get("source_zone", "source"), row.get("destination_host", "target")
    result = str(row.get("result", "")).upper()
    if skipped:
        return ["Not exercised from this probe. Run SegCheck on a host inside the "
                f"'{source}' zone to test this path; until then it is an open question, not coverage."]
    if result == "FAIL":
        steps = [FAIL_ACTION.get(method, "Remove the rule that allows {source} to reach {host} on these ports.").format(source=source, host=host)]
        if evidence == "passed":
            steps.append("The firewall log shows it passed this traffic, so the gap is in the boundary rules.")
        elif evidence in {"none", "not_connected"}:
            steps.append("Check whether another route or NAT bypasses the declared boundary.")
        steps.append("Retest after the change. A FAIL means this source is effectively connected to the target's network segment.")
        return steps
    if result == "PASS":
        return ["Approved connectivity works as intended. Keep the business justification for this flow on record."]
    if row.get("expected") == "allow":
        return ["The approved service did not answer. Check that it's running and that the boundary allows this approved flow."]
    return {
        "corroborated": ["Deny enforced: the firewall logged a block for every attempt. Keep this report as segmentation-test evidence."],
        "passed": ["The firewall passed this traffic but the target did not answer, so the deny rule is missing or not applied. "
                   "Add an explicit deny for this path and retest."],
        "partial": ["Only some attempts were logged as blocked. Enable logging on every relevant deny rule and retest."],
        "no_log": ["No firewall decision was logged. Enable logging on the deny rule between these zones, then retest to corroborate."],
        "not_connected": ["No answer from the target, but the boundary's logs aren't connected. Connect its syslog feed, or attach a "
                          "firewall rule export, to prove the deny is enforced."],
        "same_zone": ["Same-zone path: no boundary applies. Silence here may mean the service is simply closed."],
    }.get(evidence, ["No answer from the target. On its own that doesn't prove segmentation. Add firewall evidence before relying on it."])


def _severity(item):
    if item["result"] == "FAIL":
        return 4
    if item["result"] == "INCONCLUSIVE" and item["evidence"] == "passed":
        return 3
    if item["result"] == "INCONCLUSIVE" and item["evidence"] != "corroborated":
        return 2
    return 1 if item["result"] in {"INCONCLUSIVE", "PASS"} else 0


def analyse(report: dict, networks: dict | None = None) -> dict:
    report = report if isinstance(report, dict) else {}
    scope = (report.get("assessment") or {}).get("scope") if isinstance(report.get("assessment"), dict) else None
    skipped_ids = set(scope.get("not_evaluated_check_ids") or []) if isinstance(scope, dict) else set()
    networks = networks or {}
    evidence = _evidence_by_check(report)
    details = (report.get("probe_measurement") or {}).get("details", []) if isinstance(report.get("probe_measurement"), dict) else []
    reached = {}
    for detail in details if isinstance(details, list) else []:
        if isinstance(detail, dict) and detail.get("observed") == "reachable":
            reached.setdefault(detail.get("check_id"), []).append(detail.get("port"))

    checks, controls, heat_rows, methods_seen = [], OrderedDict(), OrderedDict(), []
    for row in report.get("results", []) if isinstance(report.get("results"), list) else []:
        if not isinstance(row, dict):
            continue
        skipped = row.get("check_id") in skipped_ids
        method = _method(row)
        state = _evidence_state(evidence.get(row.get("check_id"), {}))
        result = "NOT EXERCISED" if skipped else str(row.get("result", "")).upper()
        cde = networks.get(row.get("destination_zone"), {}).get("role") == "cde" or "11.4.5" in (row.get("pci_requirements") or [])
        item = {"row": row, "method": method, "method_label": method_label(method), "evidence": state, "result": result,
                "cde": cde, "reached_ports": reached.get(row.get("check_id"), []), "guidance": guidance(row, method, state, skipped)}
        checks.append(item)
        if not skipped:
            # The heatmap shows what this run exercised. If two checks land in one cell,
            # keep the more serious outcome so a FAIL is never hidden.
            if method not in methods_seen:
                methods_seen.append(method)
            target = (row.get("destination_host"), row.get("destination_zone"))
            cells = heat_rows.setdefault(target, {})
            if method not in cells or _severity(item) > _severity(cells[method]):
                cells[method] = item
        for mapping in row.get("framework_mappings") or []:
            if not isinstance(mapping, dict):
                continue
            key = (mapping.get("framework"), mapping.get("control_id"))
            entry = controls.setdefault(key, {"framework": FRAMEWORK_NAMES.get(mapping.get("framework"), mapping.get("framework")),
                                             "control_id": mapping.get("control_id"), "title": mapping.get("title"),
                                             "checks": 0, "PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "NOT EXERCISED": 0, "corroborated": 0})
            entry["checks"] += 1
            entry[result] = entry.get(result, 0) + 1
            entry["corroborated"] += state == "corroborated"
    methods = sorted(methods_seen, key=lambda key: METHOD_ORDER.index(key) if key in METHOD_ORDER else 99)

    exercised = [item for item in checks if item["result"] != "NOT EXERCISED"]
    # Only deny checks prove (or disprove) segmentation. Allow checks show approved flows still work.
    denies = [item for item in exercised if item["row"].get("expected") != "allow"]
    allows_ok = [item for item in exercised if item["row"].get("expected") == "allow" and item["result"] == "PASS"]
    allows_down = [item for item in exercised if item["row"].get("expected") == "allow" and item["result"] != "PASS"]
    fails = [item for item in exercised if item["result"] == "FAIL"]
    open_boundary = [item for item in denies if item["result"] == "INCONCLUSIVE" and item["evidence"] == "passed"]
    corroborated = [item for item in denies if item["result"] == "INCONCLUSIVE" and item["evidence"] == "corroborated"]
    unproven = [item for item in denies if item["result"] == "INCONCLUSIVE" and item["evidence"] not in {"corroborated", "passed"}]
    source = report.get("assessment", {}).get("source_zone") if isinstance(report.get("assessment"), dict) else None
    cde_fail = any(item["cde"] for item in fails)
    flows = f" {len(allows_ok)} approved flow(s) work as intended." if allows_ok else ""
    if fails or open_boundary:
        status = "violation"
        headline = f"Segmentation violation: {len(fails)} check(s) reachable" + (f", {len(open_boundary)} passed by the firewall" if open_boundary else "")
        meaning = (f"'{source}' can reach protected services. For PCI DSS, treat '{source}' as connected to the CDE and in scope "
                   "until the boundary is fixed and a retest passes (Req. 1.3, 11.4.5)." if cde_fail else
                   "Traffic that the policy denies is getting through. Fix the boundary rules listed below and retest.")
    elif denies and len(corroborated) == len(denies):
        status = "enforced"
        headline = "Deny enforced and corroborated by firewall logs"
        meaning = ("No target answered on a denied path, and the boundary firewall logged a block for every attempt. Results stay "
                   "INCONCLUSIVE by design, but this report is strong segmentation-test evidence for the tested paths." + flows)
    elif denies:
        status = "unproven"
        headline = "No reachability observed, but not proven"
        meaning = (f"{len(unproven)} deny check(s) got no answer without firewall corroboration. Silence can mean a closed service "
                   "rather than an enforced deny. Connect the boundary's logs or enable rule logging, then retest." + flows)
    elif exercised:
        status = "unproven"
        headline = "Only approved flows were exercised"
        meaning = "This run contained no deny checks, so it says nothing about segmentation." + flows
    else:
        status = "unproven"
        headline = "Nothing exercised from this probe"
        meaning = "All checks require a probe in another source zone."
    if allows_down and status != "violation":
        # Same as the report's top verdict (ATTENTION): an approved service that does not work needs action too.
        status = "attention"
        headline = f"Approved service not working: {len(allows_down)} check(s)" + (
            "; every forbidden path stayed blocked" if denies and not unproven else "")
        meaning = ("A service that must work did not answer: a rule may block an approved flow, or the service is down. "
                   "Check the red rows, fix the rule or the service, and retest. " + meaning)
    findings = ([{"level": "critical", "item": item, "text": f"{item['row'].get('source_zone')} → {item['row'].get('destination_host')} "
                  f"{item['method_label']} reachable" + (f" on {', '.join(str(p) for p in item['reached_ports'])}" if item["reached_ports"] else "")}
                 for item in fails]
                + [{"level": "high", "item": item, "text": f"{item['row'].get('source_zone')} → {item['row'].get('destination_host')} "
                    f"{item['method_label']}: firewall passed the traffic"} for item in open_boundary]
                + [{"level": "medium", "item": item, "text": f"Approved flow not working: {item['row'].get('source_zone')} → "
                    f"{item['row'].get('destination_host')} {item['method_label']}"} for item in allows_down]
                + ([{"level": "medium", "item": None, "text": f"{len(unproven)} deny check(s) without firewall corroboration"}] if unproven else [])
                + ([{"level": "info", "item": None, "text": f"{len(skipped_ids)} check(s) need a probe in another zone"}] if skipped_ids else []))
    return {
        "status": status, "headline": headline, "meaning": meaning, "source_zone": source,
        "counts": {"checks": len(checks), "exercised": len(exercised), "fail": len(fails), "open_boundary": len(open_boundary),
                   "denies": len(denies), "allowed_ok": len(allows_ok), "allowed_down": len(allows_down),
                   "corroborated": len(corroborated), "unproven": len(unproven), "not_exercised": len(skipped_ids)},
        "controls": list(controls.values()), "methods": [{"key": key, "label": method_label(key)} for key in methods],
        "heatmap": [{"host": host, "zone": zone, "cde": networks.get(zone, {}).get("role") == "cde",
                     "cells": [cells.get(key) for key in methods]} for (host, zone), cells in heat_rows.items()],
        "checks": checks, "findings": findings,
    }
