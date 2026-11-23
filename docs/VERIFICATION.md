# Verification

What has been tested, how to repeat it, and what is still open. Last full run: 23 November 2026 (Windows and Linux suites), after the
proposal follow-up (firewall rule attribution, verdict per standard, several standards in one run, compare
audits, admin network) and the lab reorganisation.

## How to repeat

| Test | Command | Last result |
|---|---|---|
| Regression suite (Windows) | `python -m pytest -q` | **608 passed**, 17 skipped (Linux-only) |
| Regression suite (Linux, inside the lab's auditor container, non-root) | `docker compose -f lab/docker/docker-compose.yml exec auditor python -m pytest -q` | **625 passed** |
| Guided audit end to end (fresh instance, browser-style HTTP client) | `python scripts/e2e_audit.py` | **78/78** |
| Office lab with a real Linux firewall (Docker), every department, fix, retest, compare | `lab/Reset lab (fresh, with loophole).cmd` (or `docker compose -f lab/docker/docker-compose.yml up -d --build`), then `python scripts/e2e_office.py` | **49/49** |
| Lab buttons | `lab/Firewall - fix loophole.cmd`, `lab/Firewall - add loophole.cmd` | switch the running firewall both ways; audits kept |
| Start-up | `python start_segcheck.py --data-dir <empty folder> --no-browser` | database created, setup page and health answer |

## What these cover

- **Firewall types (`tests/test_vendor_firewalls.py`):** log lines in the documented formats of FortiGate (traffic
  log), Cisco ASA/FTD (106023, 106100, 106001, 106006, 302013), Sophos Firewall and MikroTik (firewall topic) are read
  into block/allow, protocol, addresses, port and rule name; each firewall type gets its own setup steps in Step 3.
  Only pfSense/OPNsense and Linux have been tested against a running firewall (VirtualBox and Docker labs); the other
  four are verified against their documented log formats, not yet against real devices.
- **Firewall's own addresses (`tests/test_firewall_addresses.py`):** the addresses listed in Step 3a are stored,
  refused when wrong (not an IP, this PC, this PC's own network, outside every target network) without touching the
  saved Step 3, and removed when taken out of the list. Only the ISO 8.20 / NIST SC-7 management check tries them
  (admin ports only); the other standards and *My own rules* never treat them as servers. Attempts aimed at the
  firewall are attributed to the Linux INPUT chain (filter table only), or to pfSense's anti-lockout and
  *This firewall (self)* rules. In the Docker lab, the firewall's addresses are dropped and logged from every
  network except Admin.
- **Waiting for answers (`tests/test_patience.py`, lab runs):** an answer (connected, refused, port closed) is final.
  A silent attempt is tried once more with a longer wait (first 1–3 s, then 3–6 s, adapted to the slowest real answer
  seen in the run), unless the firewall's log shows it blocked that exact attempt; SegCheck gives that log line up to
  2 s to arrive (firewalls batch their logs). Lab, normal network: 50 attempts in 68 s, 0 second tries, 11 checks
  proven by logs. Lab with a 1.5 s delay added on the firewall's card-network side: the open card database
  (5432) answered only on the 2nd try and was still reported as FAIL; with a single 1 s wait it would have shown
  "no reply". Silence is never reported as passed without a firewall log.
- **Every setup, end to end (`tests/test_setup_matrix.py`):** 5 Step 3 setups (no firewall; firewall 'Other'; logs
  ticked but never arriving; logs working; logs plus rule export) x 3 results (all silent; card database open;
  everything refused) x 3 launches (one standard; several standards; own rules with a deny and an allow rule) = 45
  runs from launch to the saved report, PDF and JSON. Each report loads, has the right verdict, never claims proof
  without logs, explains every attempt, and lists what limited the run with the fix; clean proven runs show no
  problems. Half-finished or wrong Step 3 setups cannot launch and say what is missing.
- **Early stop (`tests/test_patience.py`, lab run):** 3 attempts in a row that never leave the PC (address gone,
  local security software) stop the run with the cause and fix; no route never stops it (reported as a note); logs set up but none arriving stops it after 8
  silent attempts, unless something already answered. Lab, with the firewall's log sender paused: stopped after 8 of
  20 attempts with "Stopped early: fix the setup and run again", the port it listened on and both fixes.
- **Launch and run (`tests/test_run_interruptions.py`, lab runs):** a second launch is refused and Step 4 links to the
  running audit; SegCheck restarted mid-run marks the run interrupted at once with a plain explanation; cancel stops
  it with no report.
- **Wrong entries (`tests/test_input_errors.py`):** every field of Step 1–4 refuses wrong input with a message that
  says what is wrong and what to do: names too long, junk or oversized networks (e.g. a `/2` typo), hosts outside
  their network or equal to its network/broadcast address, junk firewall/log addresses, an empty "Add hosts", and
  "Type addresses…" left empty. Messages also pop up in the corner of the screen, so they are seen even when the page
  jumps to a step further down.
- **Proposal follow-up (office lab, real firewall):**
  - rule attribution: the leak is named *legacy-reporting* from the firewall log and, independently, from the
    loaded `iptables-save` export (FORWARD rule 7); pfSense `config.xml` parsing (interfaces, aliases, port
    aliases, disabled rules, default deny) is unit-tested; exports saved as UTF-16 or with a BOM are read;
  - several standards in one run: PCI DSS, NIST, ISO and CIS in one launch, each probe sent once, at most 400
    attempts; the verdict per standard lists every chosen standard;
  - verdict per standard: standards that disagree (one control met, another not) are explained; standards no
    rule touches are left out; own-rules audits are checked against every standard;
  - compare audits: the retest after the fix shows FIXED with no regression; regressions are unit-tested;
  - admin network: SSH to the payment API works (approved management path, attributed to its allow rule),
    everything else from the admin network is blocked.

- **Steps 1–4 over real HTTP:** CSRF, sign-in, and pages refused when signed out.
- **Step 1:** detection; wrong IP or subnet explained; moving into a target network.
- **Step 2:**
  - several networks at once;
  - subnet derived from the first host;
  - overlap refused;
  - known hosts;
  - ping sweep (needs its tick; at most a /24; finds hosts);
  - hosts in this PC's own network.
- **Step 3:**
  - free UDP port picked;
  - instructions with this PC's address and port;
  - listener running;
  - sender learned from the first log;
  - the same port reopened at once after an edit (a bug found and fixed here);
  - every feed problem explained.
- **Step 4:**
  - all applicable standards, with only the ticked probes sent;
  - a standard that doesn't fit explains why;
  - own rules with real reachability: Failed / Passed / No answer;
  - own rules with typed address ranges, port lists/ranges and a reason (shown in the report);
    a typed address outside every network refused; parsers explain backwards ranges, too many
    addresses or ports, and bad tokens;
  - a second launch while one runs refused;
  - cancel → no report.
- **Reports:** FAILED, PASSED, NO HOLE FOUND, ATTENTION and COULD NOT TEST verdicts, firewall cross-check, PDF, evidence ZIP where every file
  matches `MANIFEST.sha256`.
- **History:**
  - list with verdicts; delete one; delete all (needs DELETE typed);
  - on a migrated database, saved reports cannot be changed or deleted except through History;
  - deleted data no longer appears in the database file.
- **Office lab (real firewall):**
  - **Corporate** finds the hidden legacy rule: only the card DB on 5432 reachable, logged as passed →
    Violation; approved flows PASS and blocked ones are logged.
  - **Guest:** 50/50 attempts logged blocks → Enforced (CDE isolation and untrusted-to-CDE).
  - **DMZ:** checkout → payment API PASS, card DB blocked.
  - **After the fix,** the Corporate retest is Enforced.

## Verified by hand

- **Plain-language report, live page and map (22 November):**
  - home audit: FAILED with counts and per-rule rows ("TCP 80 Connected", "TCP 443 No reply", with why and
    what to do); every live-page attempt explained;
  - Step 4 shows what each rule and standard will send, and the attempt total;
  - the map with names, failing host highlighted, host details on click, Replay attempts, and the
    Overview run strip;
  - office lab reports read correctly: Corporate FAILED (1 rule broken); Guest, DMZ and the retest
    PASSED "Blocked, and proven"; own-rules audits show no PCI wording;
  - discovery never offers this PC itself, and hosts found in your own network are not pre-ticked.

- **Own rules CSV (22 November, browser):** a client matrix with rows for three departments loaded on
  the HR PC: 3 rules kept (its own and `*`), 2 skipped; a range, a bundle and custom port ranges mapped
  correctly with their reasons and attempt previews; *Save rules as CSV* wrote the same rows back.

- **SegCheck.exe from a fresh clone:**
  - set up and served the setup page in 69 s;
  - later starts take about 5 s;
  - a double-click while running only opens the browser;
  - busy port 5000 → moves to 5001;
  - read-only folder → environment in `%LOCALAPPDATA%\SegCheck\venv`;
  - opened inside a ZIP → explained.
- **New audit in the browser (desktop and phone widths, no sideways scrolling):** Lab 2 on a real home
  router: Web must be blocked → **FAIL**, DNS must work → **PASS**, verdict Violation, all through
  "Hosts in your own network" and own rules.
- **Upgrade of real data:** a copy of the existing installation was upgraded `e7a1c3f9b250 →
  f3a9c1d7e2b4` with a verified backup and all records preserved. Every existing report (page, PDF and
  evidence ZIP) still opens and appears in History.

## Not yet verified

- A complete run on a client's department PC (Python install through SmartScreen, a company proxy).
- The VirtualBox pfSense / Kali / CDE lab ([VIRTUALBOX_LAB.md](VIRTUALBOX_LAB.md)): add the results here.
