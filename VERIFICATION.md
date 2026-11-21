# Verification

What has been tested, how to repeat it, and what is still open. Last full run: 21 November 2026, after
the redesign into the guided **New audit** (Step 1 · Where you are, Step 2 · What to test, Step 3 ·
Firewall, Step 4 · Checks & launch) and **History**.

## How to repeat

| Test | Command | Last result |
|---|---|---|
| Regression suite (Windows) | `python -m pytest -q` | **452 passed**, 17 skipped (Linux-only) |
| Regression suite (Linux, in the lab container, non-root) | `pytest -q` | **458 passed** |
| Guided audit end to end (fresh instance, browser-style HTTP client) | `python scripts/e2e_audit.py` | **80/80** |
| Office lab with a real Linux firewall (Docker), department by department | `cd lab/office && docker compose up -d --build`, then `python scripts/e2e_office.py` | **35/35** |

## What these cover

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
  - own rules with real reachability: FAIL / PASS / INCONCLUSIVE;
  - own rules with typed address ranges, port lists/ranges and a reason (shown in the report);
    a typed address outside every network refused; parsers explain backwards ranges, too many
    addresses or ports, and bad tokens;
  - launch without the permission tick refused;
  - a second launch while one runs refused;
  - cancel → no report.
- **Reports:** Violation and Enforced verdicts, firewall cross-check, PDF, evidence ZIP where every file
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
- The VirtualBox pfSense / Kali / CDE lab ([docs/LAB_TEST_GUIDE.md](docs/LAB_TEST_GUIDE.md)): add the results here.
