"""Audit the PaySecure office lab (lab/office) with the guided audit, like an auditor visiting each department.

    cd lab/office && docker compose down && docker compose up -d --build
    python scripts/e2e_office.py

The lab's "auditor" container plays the department PCs: it has an address in Corporate, Guest, DMZ
and CDE, and the core firewall sends its decisions to 10.40.0.100:5514.

1. Corporate PC: Step 1-3 (targets: card systems, HR, servers, DMZ; Linux firewall with log feed,
   sender learned from the first log). The PCI DSS CDE-isolation standard must find the hidden legacy
   rule (Corporate -> card DB 5432) with the firewall logging it as passed; own rules check that
   approved flows work and the HR database is blocked.
2. Guest PC: the same standard is enforced and corroborated by firewall logs; untrusted-to-CDE too.
3. DMZ PC (a target network becomes "where you are"): checkout reaches the payment API, the card
   database stays blocked.
4. The network team removes the legacy rule; the Corporate retest proves the fix.
Writes reports/e2e-office-<timestamp>.json.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e_audit as e2e  # noqa: E402
from e2e_audit import Browser, check, flashes, run_to_report, section, verdicts  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OFFICE = ROOT / "lab" / "office"
BASE = "http://127.0.0.1:5091"
TOKEN = os.environ.get("SEGCHECK_SETUP_TOKEN", "office-setup-token-change-me-0123456789abcdef")
TARGETS = [("Card systems", "10.30.0.0/24", "cde", "10.30.0.10 10.30.0.20"), ("HR department", "10.50.0.0/24", "hr", "10.50.0.10"),
           ("Internal servers", "10.70.0.0/24", "server", "10.70.0.10"), ("DMZ public web", "10.60.0.0/24", "dmz", "10.60.0.10")]


def firewall(mode):
    result = subprocess.run(["docker", "compose", "exec", "-T", "firewall", "/lab/rules.sh", mode], cwd=OFFICE,
                            capture_output=True, text=True, timeout=60, env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    return f"mode: {mode}" in result.stdout


def evidence(report):
    out = {}
    for attempt in report.get("boundary_evidence", {}).get("attempts", []):
        out.setdefault((attempt["host"], attempt["port"]), set()).add(attempt["evidence"])
    return out


def here(browser, name, kind, octet):
    saved = browser.post("/audit/here", {"name": name, "type": kind, "cidr": f"10.{octet}.0.0/24", "ip": f"10.{octet}.0.100",
                                         "gateway": f"10.{octet}.0.1", "organization": "PaySecure Ltd"})
    return check(f"Step 1: this PC is in {name} (10.{octet}.0.100)", "Step 1 saved" in flashes(saved), flashes(saved))


def host_ids(browser):
    return dict((ip, number) for number, ip in re.findall(r'<option value="(\d+)"[^>]*>([0-9.]+)', browser.get("/audit/").text))


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    browser = Browser(BASE)
    try:
        section("Sign in")
        for _ in range(90):
            try:
                if browser.get("/api/health").status == 200:
                    break
            except OSError:
                pass
            time.sleep(1)
        if browser.get("/setup", follow=False).status == 200:
            password = "Office-" + os.urandom(12).hex()
            browser.request("POST", "/setup", data={"csrf_token": browser.get("/setup").csrf(), "setup_token": TOKEN, "username": "auditor",
                                                    "password": password, "confirm_password": password})
            (OFFICE / ".office-admin").write_text(f"auditor\n{password}\n", encoding="utf-8")
        password = (OFFICE / ".office-admin").read_text(encoding="utf-8").splitlines()[1]
        signed = browser.request("POST", "/login", data={"csrf_token": browser.get("/login").csrf(), "username": "auditor", "password": password})
        check("Auditor signed in", "Overview" in signed.text)
        check("Office firewall at its 'as found' state", firewall("office"))

        section("Corporate PC: Step 1, Step 2, Step 3")
        here(browser, "Corporate staff LAN", "corporate", 40)
        added = browser.post("/audit/targets", {"t_name": [t[0] for t in TARGETS], "t_cidr": [t[1] for t in TARGETS],
                                                "t_type": [t[2] for t in TARGETS], "t_hosts": [t[3] for t in TARGETS]})
        check("Step 2: four target networks with their systems added at once", "added 4 target network(s)" in flashes(added), flashes(added))
        fw = browser.post("/audit/firewall", {"mode": "firewall", "kind": "iptables", "firewall_ip": "", "logs": "on"})
        check("Step 3: Linux firewall with log feed on UDP 5514", "UDP port 5514" in flashes(fw), flashes(fw))
        learned = {}
        for _ in range(30):
            browser.get("/audit/")  # the firewall logs every new connection; any traffic produces a log
            learned = next(iter(browser.get("/audit/firewall/status").json().values()), {})
            if learned.get("listening"):
                break
            time.sleep(0.5)
        check("Log listener running on this PC (10.40.0.100:5514)", learned.get("listening") and learned.get("address") == "10.40.0.100:5514", learned)

        section("Corporate PC: Step 4 - PCI DSS CDE isolation")
        report, html = run_to_report(browser, "PCI DSS CDE isolation from Corporate", {"mode": "standard", "pack": "pci-cde-isolation"})
        status = next(iter(browser.get("/audit/firewall/status").json().values()), {})
        check("The firewall's address was learned from its logs", status.get("learned_sender") == "10.40.0.1", status.get("learned_sender"))
        if report:
            fails = {(d["destination_host"], d["port"]) for d in report["probe_measurement"]["details"] if d["observed"] == "reachable"}
            check("Finding: only the card database on 5432 is reachable (the legacy rule)", fails == {("10.30.0.20", 5432)}, sorted(fails))
            check("The firewall logged that leak as passed", evidence(report).get(("10.30.0.20", 5432)) == {"logged_pass"})
            check("Report verdict: Violation", "Segmentation violation" in html)

        section("Corporate PC: Step 4 - own rules (the company's access matrix)")
        ids = host_ids(browser)
        report, _ = run_to_report(browser, "Own rules from Corporate", {
            "mode": "custom",
            "r_target": [ids.get("10.60.0.10"), ids.get("10.70.0.10"), ids.get("10.50.0.10"), ids.get("10.30.0.10")],
            "r_service": ["web", "custom", "db", "admin"], "r_must": ["allow", "allow", "deny", "deny"],
            "r_protocol": ["tcp"] * 4, "r_ports": ["", "445, 389", "", ""]})
        if report:
            got = verdicts(report)
            check("Approved flows work (web, file shares, LDAP); HR database and payment API admin are blocked",
                  got == {"CHK-001": "PASS", "CHK-002": "PASS", "CHK-003": "INCONCLUSIVE", "CHK-004": "INCONCLUSIVE"}, got)
            ev = evidence(report)
            check("Every blocked attempt has a logged firewall block",
                  all(ev.get(("10.50.0.10", p)) == {"logged_block"} for p in (1433, 1521, 3306, 5432, 6379, 27017)),
                  {p: sorted(ev.get(("10.50.0.10", p), [])) for p in (5432, 445)})

        section("Guest PC")
        here(browser, "Guest Wi-Fi", "guest", 20)
        for pack in ("pci-cde-isolation", "pci-untrusted-to-cde"):
            report, html = run_to_report(browser, f"{pack} from Guest", {"mode": "standard", "pack": pack})
            if report:
                summary = report["boundary_evidence"]["summary"]
                check(f"{pack} from Guest: nothing reachable, every attempt a logged block → Enforced",
                      "Deny enforced and corroborated" in html and summary["logged_block"] == len(report["probe_measurement"]["details"]), summary)

        section("DMZ PC (a target network becomes 'where you are')")
        here(browser, "DMZ public web", "dmz", 60)
        page = browser.get("/audit/").text
        check("DMZ is no longer a target; its web server is now a host in this PC's own network",
              'class="target-card own-network"' in page and "10.60.0.10" in page.split('class="target-card own-network"')[1].split("</article>")[0])
        ids = host_ids(browser)
        report, _ = run_to_report(browser, "Own rules from DMZ", {
            "mode": "custom", "r_target": [ids.get("10.30.0.10"), ids.get("10.30.0.20")],
            "r_service": ["custom", "db"], "r_must": ["allow", "deny"], "r_protocol": ["tcp", "tcp"], "r_ports": ["8443", ""]})
        if report:
            got = verdicts(report)
            check("Checkout reaches the payment API (PASS); the card database stays blocked", got.get("CHK-001") == "PASS"
                  and got.get("CHK-002") == "INCONCLUSIVE", got)

        section("Remediate and retest from Corporate")
        check("Network team removes the legacy rule", firewall("fixed"))
        here(browser, "Corporate staff LAN", "corporate", 40)
        report, html = run_to_report(browser, "Retest PCI DSS CDE isolation from Corporate", {"mode": "standard", "pack": "pci-cde-isolation"})
        if report:
            check("Retest: nothing reachable any more", not any(d["observed"] == "reachable" for d in report["probe_measurement"]["details"]))
            check("Retest: Deny enforced and corroborated by firewall logs", "Deny enforced and corroborated" in html)

        section("History")
        history = browser.get("/assessments/").text
        check("History lists the visit's audits with verdicts", history.count("/delete") >= 6 and "Violation" in history and "Enforced" in history)
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check("Office scenario finished without an unexpected error", False, repr(exc))
    finally:
        firewall("office")
    passed = sum(r["status"] == "PASS" for r in e2e.RESULTS)
    failed = sum(r["status"] == "FAIL" for r in e2e.RESULTS)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "reports" / f"e2e-office-{stamp}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"generated_at": stamp, "summary": {"passed": passed, "failed": failed}, "results": e2e.RESULTS}, indent=2), encoding="utf-8")
    print(f"\nRESULT: {passed} passed · {failed} failed  →  {out.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
