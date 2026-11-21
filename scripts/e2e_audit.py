"""End-to-end run of the guided audit against a real, fresh SegCheck server.

    python scripts/e2e_audit.py             # fresh isolated instance (nothing else is touched)
    python scripts/e2e_audit.py --keep      # leave the instance running afterwards

What it does
------------
* Starts the real application (run_review_instance.py) on loopback with a throw-away data folder.
* Drives it over HTTP exactly like a browser: forms, CSRF tokens, cookies, redirects, JSON.
* Step 1 uses one of this PC's private addresses as "where you are". Step 2 uses a SECOND local
  address (another adapter of this PC) as a "lab services" network with real TCP listeners, plus
  documentation-only addresses (RFC 5737, never real hosts).
* Step 3 connects a firewall log feed; firewall decisions are simulated with real syslog datagrams.
* Step 4 runs every standard, the probe selection, own rules, cancel, the report, the evidence ZIP
  checksums and History delete.
Writes reports/e2e-audit-<timestamp>.json.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_CDE = "198.51.100.20"   # RFC 5737 TEST-NET-2: documentation only
DOC_OFFICE = "203.0.113.9"  # RFC 5737 TEST-NET-3: documentation only
RESULTS: list[dict] = []
RUN_URLS: dict[str, str] = {}


# --------------------------------------------------------------------------- helpers
class LoopbackSecureCookies(http.cookiejar.DefaultCookiePolicy):
    """Browsers treat http://127.0.0.1 as a secure context; mirror that for Secure cookies."""

    def return_ok_secure(self, cookie, request):
        host = urllib.parse.urlparse(request.get_full_url()).hostname
        return True if host in {"127.0.0.1", "localhost"} else super().return_ok_secure(cookie, request)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Response:
    def __init__(self, status, headers, payload, url):
        self.status, self.headers, self.payload, self.url = status, headers, payload, url

    @property
    def text(self):
        return self.payload.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.payload)

    def csrf(self):
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', self.text)
        if not match:
            raise AssertionError(f"No CSRF token on {self.url}")
        return match.group(1)

    def path(self):
        return urllib.parse.urlparse(self.url).path


class Browser:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar(policy=LoopbackSecureCookies())
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, method, path, data=None, headers=None, follow=True):
        url = path if path.startswith("http") else self.base + path
        body, hdrs = None, {"User-Agent": "SegCheck-E2E/2.0", "Referer": self.base + "/"}
        hdrs.update(headers or {})
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            response = self.opener.open(req, timeout=60)
            status, rheaders, payload = response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            status, rheaders, payload = error.code, error.headers, error.read()
        if follow and status in (301, 302, 303) and rheaders.get("Location"):
            return self.request("GET", urllib.parse.urljoin(url, rheaders["Location"]), follow=True)
        return Response(status, rheaders, payload, url)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, data, page="/audit/", follow=True):
        """POST like the page's form: take the CSRF token from the page first."""
        token = self.get(page).csrf()
        return self.request("POST", path, data={"csrf_token": token, **data}, follow=follow)


def check(name, condition, detail=""):
    RESULTS.append({"use_case": name, "status": "PASS" if condition else "FAIL", "detail": str(detail)[:300]})
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}{(' — ' + str(detail)[:160]) if detail else ''}", flush=True)
    return condition


def section(title):
    print(f"\n== {title}", flush=True)


def local_private_addresses():
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except OSError:
        pass
    usable = []
    for ip in sorted(set(found), key=lambda ip: (not ip.startswith("192.168.56."), ip)):
        address = ipaddress.ip_address(ip)
        if address.is_private and not address.is_loopback and not address.is_link_local:
            try:
                with socket.socket() as probe:
                    probe.bind((ip, 0))
                usable.append(ip)
            except OSError:
                continue
    return usable


def free_port(ip):
    with socket.socket() as sock:
        sock.bind((ip, 0))
        return sock.getsockname()[1]


def start_listener(ip, port, stop):
    server = socket.socket()
    server.bind((ip, port))
    server.listen(16)
    server.settimeout(0.3)

    def loop():
        while not stop.is_set():
            try:
                connection, _ = server.accept()
                connection.close()
            except OSError:
                continue
        server.close()
    threading.Thread(target=loop, daemon=True).start()


def send_syslog(source_ip, target_ip, port, line):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((source_ip, 0))
        sock.sendto(line.encode(), (target_ip, port))


class SimulatedFirewall:
    """Sends iptables DROP log lines for every probe to `target` while a run is active."""

    PORTS_TCP = (22, 23, 3389, 5900, 5985, 5986, 1433, 1521, 3306, 5432, 6379, 27017, 80, 443, 8080, 8443, 139, 445, 389, 636, 2049)
    PORTS_UDP = (53, 123, 161)

    def __init__(self, sender_ip, listen_ip, port, probe_ip, target):
        self.sender_ip, self.listen_ip, self.port, self.probe_ip, self.target = sender_ip, listen_ip, port, probe_ip, target
        self.stop = threading.Event()

    def __enter__(self):
        lines = [f"<4>kernel: SEGCHECK-DROP IN=eth1 OUT=eth2 SRC={self.probe_ip} DST={self.target} PROTO=TCP SPT=40000 DPT={p}" for p in self.PORTS_TCP]
        lines += [f"<4>kernel: SEGCHECK-DROP IN=eth1 OUT=eth2 SRC={self.probe_ip} DST={self.target} PROTO=UDP SPT=40000 DPT={p}" for p in self.PORTS_UDP]
        lines.append(f"<4>kernel: SEGCHECK-DROP IN=eth1 OUT=eth2 SRC={self.probe_ip} DST={self.target} PROTO=ICMP TYPE=8 CODE=0")

        def loop():
            while not self.stop.is_set():
                for line in lines:
                    send_syslog(self.sender_ip, self.listen_ip, self.port, line)
                self.stop.wait(0.5)
        threading.Thread(target=loop, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.stop.set()


def flashes(response):
    import html
    return " | ".join(html.unescape(re.sub(r"\s+", " ", m)) for m in re.findall(r'class="flash-message flash-\w+">([^<]+)<', response.text))


def wait_job(browser, job_id, timeout=420):
    deadline, data = time.time() + timeout, {}
    while time.time() < deadline:
        data = browser.get(f"/jobs/{job_id}/status").json()
        if data["status"] not in ("queued", "running"):
            return data
        time.sleep(0.5)
    return data


def launch(browser, fields):
    response = browser.post("/audit/launch", {**fields, "authorized": "yes"}, follow=False)
    location = response.headers.get("Location") or ""
    match = re.search(r"/jobs/(\d+)", location)
    if not match:
        return None, flashes(browser.get(location or "/audit/"))
    return int(match.group(1)), ""


def run_to_report(browser, label, fields, timeout=420):
    job, why = launch(browser, fields)
    if not check(f"{label}: launched", job is not None, why):
        return None, None
    final = wait_job(browser, job, timeout)
    if not check(f"{label}: completed", final.get("status") == "completed", f"{final.get('completed')}/{final.get('total')} {final.get('message')}"):
        return None, None
    url = final["assessment_url"]
    RUN_URLS[label] = url
    return browser.get(url + "/report.json").json(), browser.get(url).text


def verdicts(report):
    return {row["check_id"]: row["result"] for row in report["results"]}


# --------------------------------------------------------------------------- scenario
def run(base, here_ip, lab_ip, setup_token):
    browser = Browser(base)
    here_net = ipaddress.ip_network(f"{here_ip}/24", strict=False)
    lab_net = ipaddress.ip_network(f"{lab_ip}/24", strict=False)

    section("Platform and security")
    health = browser.get("/api/health")
    check("Health endpoint answers", health.status == 200 and health.json()["database"] == "available")
    for path in ["/", "/audit/", "/assessments/", "/api/dashboard", "/jobs/1", "/audit/firewall/status"]:
        response = browser.get(path, follow=False)
        check(f"Signed out: {path} goes to sign-in", response.status in (302, 401) and "/login" in (response.headers.get("Location") or "/login"), response.status)
    for path in ["/environment/", "/policies/", "/policy-builder/", "/assessment-preview/1"]:
        check(f"Removed page {path} is gone", browser.get(path, follow=False).status in (302, 404))
    login_page = browser.get("/login")
    csp = login_page.headers.get("Content-Security-Policy", "")
    check("Security headers (CSP, frame denial, nosniff)", "default-src 'self'" in csp and login_page.headers.get("X-Frame-Options") == "DENY"
          and login_page.headers.get("X-Content-Type-Options") == "nosniff")

    section("First start: account")
    username, password = "e2e-auditor", "E2E-" + secrets.token_urlsafe(18)
    wrong = browser.request("POST", "/setup", data={"csrf_token": browser.get("/setup").csrf(), "setup_token": "x" * 40, "username": username,
                                                    "password": password, "confirm_password": password}, follow=False)
    check("Setup refuses a wrong setup token", wrong.status == 404, wrong.status)
    created = browser.request("POST", "/setup", data={"csrf_token": browser.get("/setup").csrf(), "setup_token": setup_token, "username": username,
                                                      "password": password, "confirm_password": password})
    check("Setup creates the account", "Initial administrator created" in created.text)
    bad = browser.request("POST", "/login", data={"csrf_token": browser.get("/login").csrf(), "username": username, "password": "wrong-password-1"}, follow=False)
    check("Wrong password is refused", bad.status == 401)
    ok = browser.request("POST", "/login", data={"csrf_token": browser.get("/login").csrf(), "username": username, "password": password})
    check("Sign-in reaches the overview", "Overview" in ok.text and "Audits on this PC" in ok.text)
    page = browser.get("/audit/")
    check("New audit page shows Step 1 to Step 4", all(f"Step {n}" in page.text for n in (1, 2, 3, 4)))
    check("Step 1 lists this PC's networks", here_ip in page.text)
    no_csrf = browser.request("POST", "/audit/here", data={"name": "x"}, follow=False)
    check("Forms without CSRF token are refused", no_csrf.status == 400 and "This form expired" in no_csrf.text)

    section("Step 1: where you are")
    wrong_ip = browser.post("/audit/here", {"name": "Guest Wi-Fi", "type": "guest", "cidr": str(here_net), "ip": "10.254.254.254"})
    check("An IP outside the subnet is explained", "is not inside" in flashes(wrong_ip), flashes(wrong_ip))
    bad_net = browser.post("/audit/here", {"name": "Guest Wi-Fi", "type": "guest", "cidr": "not-a-net", "ip": here_ip})
    check("A bad subnet is explained", "Enter this network's subnet" in flashes(bad_net))
    saved = browser.post("/audit/here", {"name": "Guest Wi-Fi (E2E)", "type": "guest", "cidr": str(here_net), "ip": here_ip,
                                         "gateway": "", "organization": "PaySecure (E2E)"})
    check("Step 1 saved", "Step 1 saved" in flashes(saved), flashes(saved))
    check("Top bar shows where the audit runs from", f"Testing from <span class=\"mono\">{here_ip}</span>" in saved.text)

    section("Step 2: what to test")
    bad_hosts = browser.post("/audit/targets", {"t_name": ["Bad"], "t_cidr": [""], "t_type": ["custom"], "t_hosts": ["10.9.9.x"]})
    check("A bad host address is explained", "Not an IP address: 10.9.9.x" in flashes(bad_hosts))
    overlap = browser.post("/audit/targets", {"t_name": ["Overlap"], "t_cidr": [str(here_net)], "t_type": ["custom"], "t_hosts": [""]})
    check("A target overlapping this PC's network is refused", "must not overlap" in flashes(overlap))
    added = browser.post("/audit/targets", {
        "t_name": ["Lab services (E2E)", "Card systems (E2E)", "Office (E2E)"],
        "t_cidr": [str(lab_net), "198.51.100.0/24", ""],
        "t_type": ["server", "cde", "corporate"],
        "t_hosts": [lab_ip, DOC_CDE, DOC_OFFICE]})
    check("Three target networks added in one go", "added 3 target network(s)" in flashes(added), flashes(added))
    check("A missing subnet is derived from the first host", "203.0.113.0/24" in added.text)
    keys = dict(re.findall(r'data-target="([^"]+)"[^>]*>\s*<div class="target-top">\s*<div><h3>([^<]+)</h3>', added.text))
    keys = {name: key for key, name in keys.items()}
    lab_key, cde_key = keys.get("Lab services (E2E)"), keys.get("Card systems (E2E)")
    known = browser.get(f"/audit/targets/{lab_key}/known")
    check("Known-hosts lookup answers (no traffic sent)", known.status == 200 and known.headers.get("Cache-Control") == "no-store")
    refused = browser.request("POST", f"/audit/targets/{lab_key}/sweep", data={"csrf_token": browser.get("/audit/").csrf()})
    check("Ping sweep needs explicit permission", refused.status == 400 and "Tick the box" in refused.json()["error"])
    swept = browser.request("POST", f"/audit/targets/{lab_key}/sweep", data={"csrf_token": browser.get("/audit/").csrf(), "authorized": "yes"})
    sweep = swept.json() if swept.status == 200 else {}
    check("Ping sweep covers the whole /24 and never offers this PC itself", sweep.get("pinged") == 254 and
          lab_ip not in {h["address"] for h in sweep.get("hosts", [])}, f"{sweep.get('pinged')} pinged, {len(sweep.get('hosts', []))} found")
    big = browser.post("/audit/targets", {"t_name": ["Big"], "t_cidr": ["100.64.0.0/16"], "t_type": ["custom"], "t_hosts": [""]})
    big_key = re.findall(r'data-target="([^"]+)"', big.text)[-1]
    too_big = browser.request("POST", f"/audit/targets/{big_key}/sweep", data={"csrf_token": browser.get("/audit/").csrf(), "authorized": "yes"})
    check("A sweep of more than a /24 is refused with the reason", too_big.status == 400 and "at most 256" in too_big.json()["error"])
    removed = browser.post(f"/audit/targets/{big_key}/remove", {})
    check("A target network can be removed", "target network removed" in flashes(removed))

    section("Step 3: firewall with a log feed")
    launch_early, _ = launch(browser, {"mode": "standard", "pack": "pci-cde-isolation"})
    check("Launch before Step 3 is refused", launch_early is None)
    fw = browser.post("/audit/firewall", {"mode": "firewall", "kind": "iptables", "firewall_ip": "", "logs": "on"})
    match = re.search(r"UDP port (\d+)", flashes(fw))
    check("Firewall saved; SegCheck picked a free log port", match is not None, flashes(fw))
    log_port = int(match.group(1)) if match else 0
    check("Exact firewall instructions are shown with this PC's address and port", f"@{here_ip}:{log_port}" in fw.text and "SEGCHECK-DROP" in fw.text)
    status = {}
    for _ in range(30):
        status = next(iter(browser.get("/audit/firewall/status").json().values()), {})
        if status.get("listening"):
            break
        time.sleep(0.2)
    check("Log listener is running", status.get("listening") is True, status.get("address"))
    send_syslog(here_ip, here_ip, log_port, f"<4>kernel: SEGCHECK-DROP IN=eth1 OUT=eth2 SRC={here_ip} DST=198.51.100.99 PROTO=TCP SPT=1 DPT=1")
    time.sleep(0.6)
    status = next(iter(browser.get("/audit/firewall/status").json().values()), {})
    check("The firewall's address is learned from its first log", status.get("learned_sender") == here_ip and status.get("parsed", 0) >= 1, status)
    confirmed = browser.post("/audit/firewall/sender", {"sender_ip": here_ip})
    check("Learned sender confirmed", "sender confirmed" in flashes(confirmed))

    section("Step 4: standards, probe choice, own rules")
    no_auth = browser.post("/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation"})
    check("Launch without the permission tick is refused", "Tick the authorisation box" in flashes(no_auth))
    with SimulatedFirewall(here_ip, here_ip, log_port, here_ip, DOC_CDE):
        report, html = run_to_report(browser, "PCI DSS CDE isolation (all probes)", {"mode": "standard", "pack": "pci-cde-isolation"})
    if report:
        check("All 25 probes went to the card system", len(report["probe_measurement"]["details"]) == 25)
        check("Every deny corroborated by firewall logs → Enforced", "Deny enforced and corroborated" in html,
              (report.get("boundary_evidence") or {}).get("summary"))
        check("Report shows PCI 11.4.5 in the control matrix", "11.4.5" in html)

    stop = threading.Event()
    p_open, p_allowed, p_closed = free_port(here_ip), free_port(here_ip), free_port(here_ip)
    start_listener(here_ip, p_open, stop)
    start_listener(here_ip, p_allowed, stop)
    page = browser.get("/audit/")
    here_key = re.search(r'class="target-card own-network" data-target="([^"]+)"', page.text).group(1)
    own = browser.post(f"/audit/targets/{here_key}/hosts", {"hosts": here_ip})
    check("A host in this PC's own network can be added", "added 1 host" in flashes(own), flashes(own))
    own_host = re.search(rf'<option value="(\d+)"[^>]*>{re.escape(here_ip)}', browser.get("/audit/").text)
    own_host = own_host.group(1) if own_host else ""
    report, html = run_to_report(browser, "Own rules", {
        "mode": "custom", "r_target": [own_host, own_host, own_host, f"net:{cde_key}", "text"],
        "r_service": ["custom", "custom", "custom", "rdp", "custom"], "r_must": ["deny", "allow", "deny", "deny", "deny"],
        "r_protocol": ["tcp", "tcp", "tcp", "tcp", "tcp"],
        "r_ports": [str(p_open), str(p_allowed), str(p_closed), "", f"{p_closed}, {p_open}"],
        "r_targets": ["", "", "", "", f"{here_ip}-{here_ip.rsplit('.', 1)[1]}"],
        "r_reason": ["", "", "", "", "E2E: typed range rule with its own reason"]})
    stop.set()
    if report:
        results = verdicts(report)
        check("A reachable 'must be blocked' service is a FAIL", results.get("CHK-001") == "FAIL", results)
        check("A reachable 'must work' service is a PASS", results.get("CHK-002") == "PASS", results)
        check("A closed port is INCONCLUSIVE, never PASS", results.get("CHK-003") == "INCONCLUSIVE", results)
        typed = next((r for r in report["results"] if r["check_id"] == "CHK-005"), {})
        check("A typed address range with a port list becomes a rule (FAIL: one port answered)",
              typed.get("result") == "FAIL" and sorted(typed.get("ports", [])) == sorted([p_closed, p_open]), typed.get("ports"))
        check("The rule's reason is shown in the report", "Rule reason:" in html and "E2E: typed range rule with its own reason" in html)
        check("Report verdict is Violation", "Segmentation violation" in html)
        assessment_url = RUN_URLS["Own rules"]
        pdf = browser.get(assessment_url + "/report.pdf")
        check("PDF report downloads", pdf.status == 200 and pdf.payload[:4] == b"%PDF")
        bundle = browser.get(assessment_url + "/evidence.zip")
        ok_manifest = False
        if bundle.status == 200:
            archive = zipfile.ZipFile(io.BytesIO(bundle.payload))
            folder = archive.namelist()[0].split("/", 1)[0] + "/"
            manifest = archive.read(folder + "MANIFEST.sha256").decode()
            ok_manifest = all(hashlib.sha256(archive.read(folder + name)).hexdigest() == digest
                              for digest, name in (line.split("  ", 1) for line in manifest.splitlines() if line))
        check("Evidence ZIP: every file matches its SHA-256 in the manifest", ok_manifest)

    for key, group, protocol, ports in [("pci-untrusted-to-cde", "database", "tcp", 6), ("nist-sc7-boundary", "remote_admin", "tcp", 6),
                                        ("nist-sc7-deny-default", "icmp", "icmp", 1), ("iso-8-22-segregation", "file_directory", "tcp", 5),
                                        ("cis-12-13-filtering", "infra_udp", "udp", 3)]:
        report, _ = run_to_report(browser, f"Standard {key} (probe: {group})", {"mode": "standard", "pack": key, "groups": [group]})
        if report:
            details = report["probe_measurement"]["details"]
            targets = {d["destination_host"] for d in details}
            check(f"{key}: only the ticked probe was sent", {d["protocol"] for d in details} == {protocol}
                  and len(details) == ports * len(targets), f"{len(details)} attempts to {len(targets)} host(s)")
    unavailable = browser.post("/audit/launch", {"mode": "standard", "pack": "pci-cde-egress", "authorized": "yes"})
    check("A standard that does not fit this network explains why", "Run with the local probe inside a CDE zone" in flashes(unavailable), flashes(unavailable))

    section("Cancel and one run at a time")
    job, _ = launch(browser, {"mode": "standard", "pack": "nist-sc7-boundary"})
    busy = browser.post("/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation", "authorized": "yes"})
    check("A second launch while one runs is refused with the reason", "Another assessment is running" in flashes(busy), flashes(busy))
    if job:
        browser.request("POST", f"/jobs/{job}/cancel", data={"csrf_token": browser.get(f"/jobs/{job}").csrf()})
        final = wait_job(browser, job, 60)
        check("Cancelled run stops without a report", final.get("status") == "cancelled" and not final.get("assessment_url"), final.get("status"))

    section("History")
    history = browser.get("/assessments/")
    rows = re.findall(r'/assessments/(\d+)/delete', history.text)
    check("History lists every finished audit", len(rows) >= 7, len(rows))
    check("History shows verdicts", "Violation" in history.text and "Enforced" in history.text)
    check("The cancelled run is listed without a report", "no report" in history.text)
    first = rows[-1]
    deleted = browser.post(f"/assessments/{first}/delete", {}, page="/assessments/")
    check("One audit deleted", f"Audit #{first} deleted" in flashes(deleted))
    check("The deleted report is gone", browser.get(f"/assessments/{first}", follow=False).status == 404)
    refused = browser.post("/assessments/delete-all", {"confirm": "yes"}, page="/assessments/")
    check("Delete all needs DELETE typed", "Type DELETE" in flashes(refused))
    everything = browser.post("/assessments/delete-all", {"confirm": "DELETE", "firewall_logs": "on"}, page="/assessments/")
    check("Delete all removes every audit", "Every audit was deleted" in flashes(everything) and "No audits yet" in everything.text, flashes(everything))


# --------------------------------------------------------------------------- main
def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="SegCheck guided audit, end to end")
    parser.add_argument("--port", type=int, default=5062)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    addresses = local_private_addresses()
    pairs = [(a, b) for a in addresses for b in addresses
             if ipaddress.ip_network(f"{a}/24", strict=False) != ipaddress.ip_network(f"{b}/24", strict=False)]
    if not pairs:
        print("This PC needs two private addresses in different /24 networks (e.g. a VirtualBox or VMware adapter).", file=sys.stderr)
        return 2
    here_ip, lab_ip = pairs[0]
    data_dir = Path(tempfile.mkdtemp(prefix="segcheck-e2e-audit-"))
    setup_token = secrets.token_urlsafe(40)
    env = {**os.environ, "SEGCHECK_SETUP_TOKEN": setup_token, "SEGCHECK_SECRET_KEY": secrets.token_urlsafe(48)}
    log = open(data_dir / "server.log", "w", encoding="utf-8")
    server = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "run_review_instance.py"), "--data-dir", str(data_dir), "--port", str(args.port)],
                              env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{args.port}"
    try:
        for _ in range(150):
            try:
                with urllib.request.urlopen(base + "/api/health", timeout=2):
                    break
            except OSError:
                if server.poll() is not None:
                    print((data_dir / "server.log").read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
                    return 2
                time.sleep(0.4)
        print(f"SegCheck guided audit E2E · {base} · here {here_ip} · lab network {lab_ip} · data {data_dir}")
        try:
            run(base, here_ip, lab_ip, setup_token)
        except Exception as exc:  # noqa: BLE001 (record crashes as a failure)
            import traceback
            traceback.print_exc()
            check("Scenario finished without an unexpected error", False, repr(exc))
    finally:
        if not args.keep:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
    passed = sum(r["status"] == "PASS" for r in RESULTS)
    failed = sum(r["status"] == "FAIL" for r in RESULTS)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "reports" / f"e2e-audit-{stamp}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"generated_at": stamp, "here": here_ip, "lab": lab_ip,
                               "summary": {"passed": passed, "failed": failed}, "results": RESULTS}, indent=2), encoding="utf-8")
    print(f"\nRESULT: {passed} passed · {failed} failed  →  {out.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
