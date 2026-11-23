<p align="center"><img src="scripts/launcher/segcheck-256.png" width="96" alt="SegCheck icon"></p>

<h1 align="center">SegCheck</h1>

<p align="center"><b>Network segmentation testing with proof: does the network really keep sensitive systems apart?</b></p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="Flask" src="https://img.shields.io/badge/web-Flask-black">
  <img alt="Tests" src="https://img.shields.io/badge/tests-608%20passing-brightgreen">
  <img alt="Standards" src="https://img.shields.io/badge/standards-PCI%20DSS%20%7C%20NIST%20%7C%20ISO%20%7C%20CIS-informational">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
</p>

<p align="center"><img src="docs/screenshots/overview.png" alt="SegCheck overview: 10 audits, latest PASSED, 91% of 170 checks passed, results across runs" width="900"></p>

SegCheck answers questions like *"can a PC in HR reach the card database?"* You run it **on a PC inside the
department you are testing**. It sends small, harmless connection attempts (TCP, UDP, ping) toward the
systems that department must **not** reach, compares every answer with the policy, checks the
**firewall's own log** of each attempt, names the **exact firewall rule** behind each result, and judges
the run against **PCI DSS, NIST SP 800-53, ISO/IEC 27002 and CIS v8**, control by control.

> SegCheck supports a PCI DSS segmentation test (Req. 11.4.5). It does not certify a company as compliant.
> Only test networks you own or have **written permission** to test.

---

## Contents

- [Why SegCheck](#why-segcheck)
- [How it works](#how-it-works)
- [A tour: find the hole, fix it, prove it](#a-tour-find-the-hole-fix-it-prove-it)
- [Quick start](#quick-start)
- [Try it on a whole fake company (Docker lab)](#try-it-on-a-whole-fake-company-docker-lab)
- [The four steps of an audit](#the-four-steps-of-an-audit)
- [Reading the report](#reading-the-report)
- [Standards covered](#standards-covered)
- [Security design](#security-design)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Documentation](#documentation)
- [License](#license)

---

## Why SegCheck

Most scanners report "port closed" and stop there. Silence is not proof: the firewall may have blocked the
attempt, or the service may simply be switched off. SegCheck is built around that difference.

| | What it means in practice |
|---|---|
| **Silence is never a pass** | A reply on a forbidden path is a **failure**. No reply is only *not proven*, until the firewall's own log shows it blocked that exact attempt. Then it is **proven**. |
| **Firewall-log proof** | Reads the firewall's syslog (pfSense/OPNsense, Linux iptables/nftables, FortiGate, Cisco ASA/FTD, Sophos, MikroTik) and matches every attempt to a log line. A logged *pass* on a silent attempt is caught as a hole too. |
| **Names the guilty rule** | With an optional read-only rule export (pfSense `config.xml` or `iptables-save`), it replays the firewall's first-match logic: *"Let through by rule legacy-reporting (FORWARD rule 7)"*. |
| **Verdict per standard** | An offline compliance assistant (retrieval over its own control knowledge base, no AI model) gives *Met, proven*, *Not met* and similar results per control, with the fix and the evidence an assessor expects. Same run, same answer, every time. |
| **Patient, but honest** | Answers are final. A silent attempt is retried once with a longer wait that adapts to the network's real speed, so a lost packet cannot hide an open door. A run whose setup is broken stops early and says what to fix, rather than saving a misleading report. |
| **Tamper-evident evidence** | Saved reports cannot be edited (enforced in the database). Each audit exports a PDF and an evidence ZIP with a `MANIFEST.sha256`. |
| **Simple to run** | Double-click `SegCheck.exe`. No admin rights, and nothing listens on the network (the dashboard is `127.0.0.1` only). |

## How it works

```mermaid
flowchart LR
    PC["Department PC<br/>running SegCheck"] -- "1. test attempts<br/>TCP / UDP / ping" --> FW{{"Firewall"}}
    FW -- "allowed?" --> T["Target systems<br/>e.g. card database"]
    FW -. "2. syslog: BLOCK / PASS<br/>for each attempt" .-> PC
    PC --> R["3. Rule attribution<br/>which rule decided"]
    R --> V["4. Verdict per check<br/>and per standard control"]
    V --> E["Report · PDF ·<br/>evidence ZIP (SHA-256)"]
```

1. **Test:** attempts leave from the PC you sit at and cross the real switches and firewall. SegCheck never
   relays them, so the real path is tested.
2. **Prove:** each attempt is matched to the firewall's log. A logged block turns "no answer" into proof.
3. **Explain:** the decisive firewall rule is named from the rule export or the log's rule label.
4. **Judge:** results are mapped to the controls of every chosen standard. The worst result for a control wins.

## A tour: find the hole, fix it, prove it

Every screenshot below is from a real run in the [Docker lab](#try-it-on-a-whole-fake-company-docker-lab): a
staff PC (10.40.0.100) is tested against the card-data network, behind a real Linux firewall that has one
forgotten rule.

**1 · Set up the audit.** Four guided steps. Step 3 connects the firewall's logs (the status turns green when
they arrive) and can load its rule export; Step 4 picks the standard and shows exactly what will be sent.

<p align="center"><img src="docs/screenshots/step3-firewall.png" alt="Step 3: Linux firewall chosen, logs arriving, setup instructions for the firewall's administrator, 9 firewall rules loaded" width="900"></p>

**2 · Watch it run.** Each attempt appears live. Here 23 of 50 are done and every one is already *blocked, in
the firewall's log*: proof, not just silence.

<p align="center"><img src="docs/screenshots/live-run.png" alt="Live run at 23 of 50 connections, 23 blocked and proven by the firewall log" width="900"></p>

**3 · The verdict.** One rule failed: something that must be blocked answered.

<p align="center"><img src="docs/screenshots/report-failed.png" alt="Report: FAILED, 1 rule broken, 12 rules tested, 11 passed, 1 failed" width="900"></p>

**4 · Exactly what failed, and which firewall rule did it.** TCP 5432 on the card database connected; the
firewall's own log says it *let it through*, and the rule export names the culprit:
`legacy-reporting (FORWARD rule 7)`. The card also says what to do.

<p align="center"><img src="docs/screenshots/rule-failed.png" alt="Failed rule card: TCP 5432 connected, firewall let it through, rule legacy-reporting FORWARD rule 7" width="900"></p>

**5 · What it means for each standard.** The offline compliance assistant judges every control of every
chosen standard, with the fix, an acceptable alternative and the evidence an assessor expects.

<p align="center"><img src="docs/screenshots/verdict-per-standard.png" alt="Verdict per standard: PCI DSS 4.0.1 1.3.1 and 11.4.5 not met on 10.30.0.20 TCP 5432" width="900"></p>

**6 · Fix it, run again, and prove the fix.** After the rule is removed, the same audit passes: blocked, and
proven by the firewall's log. *Compare two audits* shows it as **FIXED**, with nothing worse.

<p align="center"><img src="docs/screenshots/report-passed.png" alt="Report after the fix: PASSED, blocked and proven, 12 of 12 passed" width="900"></p>

<p align="center"><img src="docs/screenshots/compare-fixed.png" alt="Compare two audits: FIXED, 1 finding fixed, nothing got worse" width="900"></p>

<details>
<summary><b>More screenshots</b>: map of a run, dashboard charts, Step 4, New audit, History</summary>
<br>

| | |
|---|---|
| <img src="docs/screenshots/map-run.png" alt="Map of a run: this PC to the card systems, one open path on TCP 5432" width="440"> | <img src="docs/screenshots/dashboard-charts.png" alt="Dashboard: pass rate gauge, results across runs, segmentation map" width="440"> |
| <img src="docs/screenshots/step4-checks.png" alt="Step 4: choose one standard or several, with what each tests" width="440"> | <img src="docs/screenshots/new-audit.png" alt="New audit page: four steps, Step 1 done" width="440"> |
| <img src="docs/screenshots/history.png" alt="History: every audit with its verdict, PDF and evidence bundle" width="440"> | |

</details>

## Quick start

**Requirements:** Windows 10/11 (the launcher) or any OS with **Python 3.11+**. Internet is needed once, for
the first install of the Python packages.

```powershell
git clone https://github.com/MMoizSiddiqui/SegCheck.git
```

Then **double-click `SegCheck.exe`** in the folder (or download the ZIP from GitHub, *Extract All…*, and
double-click it there). It does the rest:

- If Python 3.11+ is missing, it offers to install Python 3.12 for your user (no admin rights).
- The first start creates a private environment (`.venv`) and installs the packages, in about 2 minutes.
- The dashboard opens in your browser at `http://127.0.0.1:5000`. The first time, paste the **one-time
  setup token** shown in the black window, then create your account.

Without the exe, on any OS:

```powershell
python start_segcheck.py
```

Keep the black window open while you work. Closing it stops SegCheck; your work is already saved.

## Try it on a whole fake company (Docker lab)

[`lab/`](lab/README.md) builds **"PaySecure Ltd"**, a small payment company, in Docker Desktop. It has seven
department networks, five business systems, a **real Linux firewall** that logs every decision, and
SegCheck inside the network as the auditor's PC. The firewall contains **one planted mistake**, a forgotten
rule that lets staff PCs reach the card database:

```
legacy-reporting:  staff PCs (10.40.0.0/24)  →  card database 10.30.0.20 : 5432   ALLOWED (it should not be)
```

Double-click the buttons in `lab/`:

| Button | What it does |
|---|---|
| `Reset lab (fresh, with loophole).cmd` | Builds and starts everything fresh and opens SegCheck at `http://127.0.0.1:5091` |
| `Start lab (keep audits).cmd` | Starts the lab again and keeps your audits |
| `Firewall - fix loophole.cmd` / `Firewall - add loophole.cmd` | Removes or restores the planted rule |

**The demo story:** SegCheck finds the hole → names the exact firewall rule → the "network team" fixes it →
SegCheck proves the fix (*Compare two audits* shows it as **FIXED**).

## The four steps of an audit

Open **New audit**. Each step saves automatically and is ticked off as you finish it.

| Step | Question it answers | Example |
|---|---|---|
| **1 · Where you are** | Which network is this PC in? (detected for you) | Corporate staff LAN, this PC 10.40.0.100 |
| **2 · What to test** | Which networks and hosts must this department not reach? | Card systems 10.30.0.0/24: .10 and .20 |
| **3 · Firewall** | Is there a firewall, does it send logs, and can you load its rules? | Linux firewall, logs to this PC on UDP 5514 |
| **4 · Checks & launch** | Which standards, or your own rules / the client's access-matrix CSV? | PCI DSS CDE isolation, all probe groups |

Step 4 shows exactly what will be sent (every probe, port and target), the number of attempts and the
estimated time before you click **Launch audit**. Progress is shown live, and you can cancel at any time;
a cancelled run never saves a half report.

The full walkthrough, with every option and every error message, is in **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**.

## Reading the report

| Report verdict | Meaning |
|---|---|
| **FAILED** | At least one forbidden path is open: it answered, or the firewall logged it as passed. |
| **ATTENTION** | Nothing forbidden is open, but an approved business service is not working. |
| **PASSED** | Every forbidden path was blocked **and the firewall's log proves it**. |
| **NO HOLE FOUND** | Nothing forbidden answered, but it is not proven. Connect the firewall's logs and run again. |
| **COULD NOT TEST** | Nothing reached the network. The *Problems in this run* box says what to fix. |

Each rule card then shows what was sent, what came back on every port, the firewall's log entry, the rule
that decided it, **why**, and **what to do**. There is also a map of the run with a replay, a heatmap,
control results per standard, the compliance assistant's explanation, and a *Compare two audits* view
(fixed / regression / still failing).

## Standards covered

| Standard | Controls | Built-in test packs |
|---|---|---|
| **PCI DSS 4.0.1** | 1.3.1, 1.3.2, 1.4.2, 11.4.5 | CDE isolation from out-of-scope networks · Untrusted/DMZ networks to CDE · CDE outbound restriction |
| **NIST SP 800-53 Rev. 5** | SC-7, SC-7(5), AC-4 | Boundary protection between zones · Deny-by-default to sensitive zones |
| **ISO/IEC 27002:2022** | 8.22, 8.20 | Segregation of networks · Firewall management plane protection |
| **CIS Controls v8** | 12.2, 13.4 | Traffic filtering between segments |

Several standards can run together: each probe is sent once and counts for every standard that asks for it.
Packs that do not fit the current network are greyed out, with the reason. The control summaries are in
SegCheck's own words, with links to the official texts ([docs/FRAMEWORK_REFERENCES.md](docs/FRAMEWORK_REFERENCES.md)).

## Security design

- **Loopback only:** the dashboard binds to `127.0.0.1`. Firewall connectors only *listen* for syslog and
  read exports; SegCheck never logs in to or changes a device.
- **Explicit consent:** nothing is sent until you review the exact targets and click Launch. At most 400
  attempts per run, and a ping sweep runs only after its own tick box.
- **Web hardening:** scrypt password hashing, sign-in throttling, CSRF tokens on every form, a strict
  Content-Security-Policy (no inline scripts), and a one-time setup token for the first account.
- **Integrity:** reports are immutable (database triggers block edits), and evidence bundles carry SHA-256
  manifests. Deleting is explicit, and deleted data is removed from the database file.
- **Known limitation:** classic UDP syslog is unauthenticated. The report says so, and SegCheck accepts logs
  only from the firewall's learned address.

## Project layout

```
SegCheck.exe            Windows launcher: double-click to set up and start
start_segcheck.py       the same start-up on any OS
segcheck/               engine: probes (TCP/UDP/ICMP), policies, firewall-log evidence, storage
segcheck_web/           Flask web app
  routes/               pages (audit steps, assessments, dashboard, history)
  services/             the logic: audit_setup (the 4 steps), assessment_execution + patience (running),
                        firewall_connector + vendor_logs (log proof), rule_attribution (which rule),
                        compliance_assistant (verdict per standard), report_view / assessment_pdf (report)
  knowledge/            controls.json: the offline compliance knowledge base
  migrations/           database schema, upgraded automatically at start
  templates/, static/   HTML, CSS and JavaScript (no inline scripts)
lab/                    Docker lab "PaySecure Ltd" with a real firewall (see lab/README.md)
docs/                   user guide, hands-on labs, VirtualBox lab, verification, roadmap, references
scripts/                end-to-end tests, database upgrade, launcher source (C#) and icon
tests/                  automated test suite (tests/fixtures = test data)
```

## Testing

```powershell
python -m pytest -q
```

The regression suite has **608 passed** on Windows (17 Linux-only tests skipped) and **625 passed** on Linux,
run inside the lab's auditor container as a non-root user.

```powershell
python scripts/e2e_audit.py
```

```powershell
python scripts/e2e_office.py
```

`e2e_audit.py` starts a fresh, isolated SegCheck and drives the whole guided audit over HTTP. It needs two
private addresses on this PC, such as a VirtualBox adapter. `e2e_office.py` audits the Docker lab department
by department (start the lab first). Results and the manual acceptance tests are recorded in
[docs/VERIFICATION.md](docs/VERIFICATION.md).

## Limitations and roadmap

- SegCheck tests the paths you define, from the PC it runs on. Run it once per department.
- Without firewall logs, "no answer" stays *not proven*. That is by design.
- Approved business flows are not yet exempted from the broad NIST/ISO/CIS packs (use own rules or the
  access-matrix CSV for those). This is planned.
- `SegCheck.exe` is not code-signed, so Windows SmartScreen may warn (*More info → Run anyway*).

Planned: a combined report across departments, approved exceptions for standards, path trace for failed
rules, banner grabbing and re-audit reminders. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Documentation

| Document | For |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Every step and option, reading results, troubleshooting, removing SegCheck from a PC |
| [docs/HANDS_ON_GUIDE.md](docs/HANDS_ON_GUIDE.md) | Learn SegCheck through guided labs |
| [lab/README.md](lab/README.md) | The Docker office lab: networks, firewall, demo script |
| [docs/VIRTUALBOX_LAB.md](docs/VIRTUALBOX_LAB.md) | Manual test with VirtualBox VMs (Guest / pfSense / CDE) |
| [docs/VERIFICATION.md](docs/VERIFICATION.md) | What was tested and how |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Done and future work |
| [docs/FRAMEWORK_REFERENCES.md](docs/FRAMEWORK_REFERENCES.md) | Standards mapping and official sources |

**Maintainers:** rebuild `SegCheck.exe` after changing `scripts/launcher/SegCheck.cs` with
`python scripts/build_launcher.py` (a test fails until you do). Upgrade a database by hand with
`python scripts/upgrade_local_database.py` (`--check` is read-only); the launcher normally does this itself.

## License

[MIT](LICENSE) © 2026 Moiz Siddiqui.
Use it only on networks you own or have written permission to test.
