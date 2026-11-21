<p align="center"><img src="launcher/segcheck-256.png" width="96" alt="SegCheck icon"></p>

# SegCheck: network segmentation testing (PCI DSS first)

SegCheck checks whether a network really keeps sensitive systems separated. For example: *can a PC in
HR reach the card database?*

You run SegCheck **on a PC inside the department you are testing**. From that PC it sends small,
harmless connection attempts (TCP, UDP and ping) toward the systems that department must **not** reach,
and compares the answers with the company's policy. If the firewall sends its logs, SegCheck also checks
the firewall's own record of each attempt. You get a report and a tamper-evident evidence bundle.

- **Standards built in:** PCI DSS 4.0.1 (1.3.1, 1.3.2, 1.4.2, 11.4.5), NIST SP 800-53 (SC-7, AC-4),
  ISO/IEC 27002 (8.20, 8.22), CIS v8 (12.2, 13.4), plus your own access-matrix policies.
- **Honest results:** a reply on a forbidden path is a **FAIL**. Silence is **never** counted as a pass;
  it becomes "proven" only when the firewall logged the block.
- **Safe:** nothing is sent until you review the exact targets and tick an authorisation box. Reports
  cannot be edited afterwards.

> SegCheck tests the paths you define. It supports a PCI DSS segmentation test (Req. 11.4.5); it does
> not certify a company as PCI DSS compliant. Always have the network owner's written permission.

---

## 1. How it is used

```
  Department PC (e.g. HR, 10.50.0.23)                                Card database (CDE)
 ┌───────────────────────────────────────┐                          ┌──────────────────┐
 │ SegCheck installed here               │   attempts go through    │ 10.30.0.20:5432  │
 │ • dashboard in this PC's browser      │ ──► real switches ──►    │                  │
 │ • attempts leave from this PC         │     and FIREWALL         └──────────────────┘
 │ • results saved on this PC            │         │ log: "blocked 10.50.0.23 → 10.30.0.20:5432"
 └───────────────────────────────────────┘ ◄───────┘ (optional, makes "no answer" provable)
```

**One PC per department, start to end on that PC.** In each department you sit at one of its PCs
(usually with the client's IT person), install SegCheck, set it up, run the audit, take the evidence
bundle, and remove SegCheck. Then you move to the next department and do the same.

- SegCheck runs only on that PC. The dashboard is at `http://127.0.0.1:5000`, and nothing listens on
  the network.
- The attempts start from that PC's own address, so they meet exactly the firewall rules that apply to
  that department.
- Everything is saved on that PC until you remove it.

## 2. Install and start (on the department PC)

1. **Get SegCheck onto the PC.** Either clone it:
   ```bash
   git clone <repository URL> SegCheck
   ```
   or download the ZIP from GitHub and **extract it** (right-click → *Extract All…*), for example to
   `C:\SegCheck`.
2. **Double-click `SegCheck.exe`** (the two-rings icon). That is all; it does the rest by itself.
   - **If Python 3.11+ is missing,** it offers to install Python 3.12 for the signed-in user (no
     administrator rights).
   - **The first start** creates a private environment (`.venv`) and installs SegCheck's packages. This
     needs internet once and takes about 2 minutes.
   - **Then** a black **SegCheck** window opens and the dashboard opens in the browser.
   - **Every later double-click** starts SegCheck in about 5 seconds, or just opens the browser if it
     is already running.
   - **If something is wrong,** the window stays open with `PROBLEM:` and numbered steps to fix it.
   - Without the exe, `python start_segcheck.py` does exactly the same.
3. **Create your account.** The first time, the window shows a **one-time setup token**. Paste it into
   the setup page, then choose a username and password.

Keep the black window open while you work. Closing it stops SegCheck; your work is already saved.

## 3. Run the audit: New audit, Step 1 to Step 4

Open **New audit** in the menu. The page walks you through four steps; each one is ticked off as you
finish it.

**Step 1 · Where you are.** SegCheck lists the networks of this PC (the one with a gateway is usually
the Wi-Fi or Ethernet) and picks it. Give the network a name (e.g. *HR department*), say what kind of
network it is (office, guest, card data/CDE, servers, HR, DMZ…), optionally the client's name, and click
**Use this network**. Wrong addresses are explained (for example *this PC's address is not inside that
subnet*). *Set the addresses myself* lets you type them.

**Step 2 · What to test.** Add the networks this department must not reach, several at once: one row
each with a name, the network (e.g. `10.30.0.0/24`, or leave it empty and SegCheck uses the first host's
/24), its kind, and the host addresses. Per network you can then:
- **Show hosts this PC already knows** (reads this PC's neighbour table; sends nothing);
- **Ping sweep** (after you tick *I may ping every address*; at most a /24, one ping per address);
- tick what was found and **Add ticked hosts**, or type addresses; remove hosts or whole networks.

*Hosts in your own network* (same subnet as this PC, e.g. the router) can be added too. The standards
skip them (no firewall in between), but your own rules can test them.

**Step 3 · Firewall.**
- **No firewall, or I don't know:** one click. Attempts go straight through the router; anything that
  answers is a FAIL, silence is reported as *unproven*, never as passed.
- **There is a firewall:** choose pfSense/OPNsense, Linux (iptables/nftables) or Other. Its address is
  pre-filled with the gateway. With **Connect its logs** ticked, SegCheck picks a free UDP port on this PC
  and shows exactly what to set on the firewall, with this PC's address and port already filled in. It
  learns the firewall's sending address from the first log, and the status turns green when logs arrive.
  Problems (port in use, logs from another address, unknown format, nothing arriving) are shown with
  numbered fixes. SegCheck only listens; it never logs in to the firewall or changes it.

**Step 4 · Checks & launch.**
- **A standard:** PCI DSS 4.0.1 (CDE isolation, untrusted/DMZ to CDE, CDE outbound), NIST SP 800-53
  (SC-7 boundary, deny by default), ISO/IEC 27002 (8.22 segregation, 8.20 firewall management plane),
  CIS v8 (12.2/13.4). Standards that do not fit this network are greyed out with the reason.
- **Which probes:** remote administration, databases, web, file sharing/directory, infrastructure UDP,
  ping, firewall management. All are ticked; untick what you don't need. *What will be sent* lists every
  probe group with its ports and targets, and the number of attempts and the time are shown live.
- **Or My own rules:** rows of *to this host (or all hosts of a network) · this service (web, RDP, SSH,
  databases, file sharing, DNS, ping… or your own ports) · must be blocked / must work*. Each rule shows
  exactly what it will send (e.g. *Sends TCP 80, 443 to 192.168.1.1 → 2 attempts; must NOT answer*).
  For real office networks:
  - **Targets** can be typed: single addresses, ranges and subnets (`10.30.0.20  10.30.0.10-20
    10.30.0.0/28`, at most 256 per rule). Each typed address is added as a host of the Step 1/Step 2
    network that contains it; an address outside every network is refused with the reason.
  - **Ports** can be lists and ranges (`8080, 9000-9010`, at most 400 per rule), and there are service
    bundles: *Windows domain*, *Email*, *Printing*, *Web admin / alternate web ports*.
  - **Reason:** each rule can carry one (e.g. *HR must not reach card data — PCI DSS 1.3.1*); the report
    shows it on that rule's card.
  - **CSV (the client's access matrix):** *Example CSV* downloads a template with the columns
    `from, to, service, protocol, ports, must, reason`. *Load rules from CSV…* keeps only the rows for
    this PC's network (`from` = the Step 1 name, or `*`/empty for every department) and says how many it
    skipped. *Save rules as CSV* writes the current rules, so the same file travels from department to
    department.
- Tick **I have written permission** and click **Launch audit**.

**Then** SegCheck does the rest: it checks everything is ready (and explains anything missing), sends the
attempts from this PC (1-second timeout each, at most 400), shows each one live (you can cancel; a
cancelled run never produces a half report), cross-checks the firewall's logs, decides the verdict, and
saves the report.

**The report** opens with a plain verdict (**FAILED**, **PASSED: blocked and proven**, **NO HOLE FOUND but
not proven**, or **ATTENTION: approved service not working**) and counts (rules tested, passed, failed, no answer).
Then **Rule by rule**: the target, the probe that was sent, what was expected, what happened on every
port (e.g. *TCP 80 Connected*, *TCP 443 No reply*, each explained in plain words), the result, why, and
what to do. A **map of the run** shows this PC and every host coloured by its result (click a host for
its rules; **Replay attempts** plays the run in order). Below that: the summary and findings, the firewall
cross-check, and for standards the heatmap and control results. The PCI wording appears only when PCI
checks were part of the audit. The **Overview** has the same map for all audits, with a strip to step
through past runs and **Play history**. Download the **PDF** or the **Evidence bundle (.zip)**
(PDF, exact JSON, policy, environment, firewall evidence and `MANIFEST.sha256`, so anyone can check
nothing was altered). Copy it off the PC the client's approved way.

**History** lists every audit on this PC with its verdict: open, PDF, evidence, **Delete**, or **Delete
everything** (type DELETE; optionally also the firewall logs and the automatic backups). Deleted data is
removed from the database file itself. Saved reports can never be changed, only deleted.

**Fix and retest:** after the client changes the firewall, run the audit again; the new report proves
the fix. Then remove SegCheck from the PC (section 6) and go to the next department.

## 4. Reading the results

| Per check | Meaning |
|---|---|
| **FAIL** | A forbidden service answered: the segmentation has a hole. Fix the rule named in the guidance. |
| **PASS** | An *allowed* (business) flow works as intended. |
| **INCONCLUSIVE** | No answer. On its own this is not proof: the firewall may have blocked it, or the service may be off. |

| Report summary | Meaning |
|---|---|
| **Violation** | At least one forbidden path is open (or the firewall logged it as passed). |
| **Enforced** | Nothing forbidden answered **and** the firewall logged a block for every attempt. This is strong evidence. |
| **Unproven** | Nothing answered, but there are no firewall logs to prove why. Connect the firewall's syslog and retest. |
| **Untested zones** | The dashboard lists departments no run has started from yet. Untested is never passed. |

## 5. Troubleshooting

### SegCheck fixes these by itself
It prints `Fixed automatically: …` with what it did and the next step.

| Situation | What SegCheck does |
|---|---|
| Port 5000 is used by another program | Uses the next free port (5001, 5002, …) and opens the browser there |
| SegCheck is already running (even on a port it moved to) | Opens the running one; no second copy starts |
| The database file is damaged (power loss while running) | Restores the newest automatic backup and keeps the damaged file next to it |
| The private environment (`.venv`) stopped working (Python upgraded or removed) | Rebuilds it; your data is not affected |
| A package download was interrupted | Tries once more; if there is no internet it says so |
| An impossible port (`--port 80`) | Uses port 5000 |
| The SegCheck folder is read-only for your account (e.g. under Program Files) | Keeps its private environment in `%LOCALAPPDATA%\SegCheck\venv` instead |
| The browser does not open by itself | Prints the address to open in the black window |

SegCheck's dashboard uses port **5000** (not 8080), and only on this PC. If 5000 or the next ports are
taken by other programs, it simply moves on.

### What is left for you
| You see | What it means | What to do |
|---|---|---|
| Windows: *Windows protected your PC* | `SegCheck.exe` is not code-signed | *More info → Run anyway*, or start with `python start_segcheck.py` |
| *SegCheck.exe was opened from inside a ZIP file* | The ZIP was opened, not extracted | Right-click the ZIP → *Extract All…*, then double-click SegCheck.exe in the extracted folder |
| *SegCheck.exe must stay inside the SegCheck folder* | The exe was moved on its own | Put it back; for a desktop icon use *Send to → Desktop (create shortcut)* |
| *SegCheck is already starting* | You double-clicked during the first-time setup | Wait; the browser opens by itself when it is ready |
| `needs Python 3.11 or newer` | No suitable Python on this PC | Double-click SegCheck.exe and accept the Python install, or install it from python.org |
| `packages could not be downloaded` | No internet, or a proxy blocks it | Connect once; behind a proxy run `set HTTPS_PROXY=http://proxy:8080` first |
| `PROBLEM: SegCheck cannot write to its data folder` | Disk full or no permission | Free space, or use `--data-dir D:\SegCheckData` |
| `PROBLEM: The database could not be opened or upgraded` | Damaged and no automatic backup | Follow the printed steps (rename the file to start empty; nothing is deleted) |
| `PROBLEM: The database is in use by another program` | A second SegCheck window has it open | Use or close the other window |
| `SegCheck could not start: …` | Unexpected | Try once more; details are in the data folder's `logs\launcher-error.log` |

### In the browser
| You see | What to do |
|---|---|
| **This form expired** | Reload the page and submit again (forms expire for security). |
| **Step 1: … is not inside …** / **is not an address of this PC** | Pick the network SegCheck found in Step 1, or check `ipconfig`. |
| **Step 1: … no longer an address of this PC** | The PC changed network or got a new DHCP address: choose this PC's network in Step 1 again. |
| **Step 2: must not overlap** | That network overlaps this PC's network or another target; use a different subnet, or remove the other one. |
| **Step 4: Not ready yet: …** | Each part names the missing piece and where to fix it. |
| **Step 4: Another assessment is running** | Wait for it to finish, or cancel it from its live page. |
| **Too many attempts** at sign-in | Wait a few minutes (password-guessing protection). |
| **Something went wrong… Reference: ABCD1234** | Retry. If it repeats, look in `logs\errors.log` in the data folder. |

### Firewall log feed (Step 3)
Step 3 shows the feed's state and, when something is wrong, a numbered list of fixes:

| Tile says | What to do |
|---|---|
| *UDP port 5514 is already used by another program on this PC* | Save Step 3 again: SegCheck picks the next free port and shows it; set that port in the firewall's remote logging |
| *… is not an address of this PC* | Leave *This PC receives logs on* empty, or redo Step 1 if the PC's address changed |
| *Logs are arriving from X, but the sender IP is set to Y* | If X is the firewall, save Step 3 with *Logs come from* empty (SegCheck learns it) or set X |
| *Logs arrive but their format is not recognised* | pfSense/OPNsense: log format *BSD (RFC 3164)*; Linux: iptables/nftables `LOG` rules |
| *Nothing has arrived for a minute* | Check the firewall's remote-logging target (this PC's IP and port), switch on *Log* for the deny rules, and allow inbound UDP on that port in Windows Firewall (the tile shows the exact command for an administrator) |

### Results
| Situation | Why | What to do |
|---|---|---|
| Everything **Unproven** | No firewall logs connected | Step 3: choose *There is a firewall* with its logs; enable logging on its deny rules |
| An allowed flow shows **Approved flow not working** | The business service did not answer | Check the service is running, or that a rule is not blocking an approved flow |
| A standard is greyed out | It needs another kind of network here (e.g. *CDE outbound* needs this PC inside the CDE) | Run it from a PC in such a network, or choose another standard |

## 6. Where the data is, and removing SegCheck from a PC

All data is in **`%LOCALAPPDATA%\SegCheck`** on that PC: the database, the signing secret
(`secret.key`), evidence, logs, and `backups` (made automatically before every upgrade).

To leave the PC clean after the audit:
1. **Download the evidence bundles** you need and copy them off the PC.
2. **Close the black SegCheck window.**
3. **Delete the SegCheck folder** (for example `C:\SegCheck`).
4. **Delete `%LOCALAPPDATA%\SegCheck`:** paste that into the File Explorer address bar.
5. **If SegCheck installed Python for this visit,** remove it in *Settings → Apps*.

## 7. Safety and permission

- Get **written permission** (scope, address ranges, dates, which PCs) before testing any network you
  do not own.
- SegCheck only sends the attempts shown in the preview, after you tick the authorisation box: 1-second
  timeout each, at most 400 attempts per run. A ping sweep only runs after its own tick box.
- The dashboard listens on this PC only (`127.0.0.1`); nothing on the network can reach it.
- Firewall connectors are **read-only**: SegCheck never changes devices.
- No administrator rights are needed.

---

## For maintainers

| Topic | Where |
|---|---|
| **Learn SegCheck hands-on (labs, every option, every error)** | [docs/HANDS_ON_GUIDE.md](docs/HANDS_ON_GUIDE.md) |
| Rebuild SegCheck.exe after changing `launcher/SegCheck.cs` (a test fails until you do) · redraw the icon | `python scripts/build_launcher.py` · `python launcher/make_icon.py` |
| Docker lab (six-department office with a real firewall and a hidden misconfiguration) | [docs/CONTAINER_LABS.md](docs/CONTAINER_LABS.md) |
| Manual VirtualBox test (Guest / pfSense / CDE VMs) | [docs/LAB_TEST_GUIDE.md](docs/LAB_TEST_GUIDE.md) |
| What was tested and what is still open | [VERIFICATION.md](VERIFICATION.md) · [ROADMAP.md](ROADMAP.md) |
| Framework mappings | [docs/FRAMEWORK_REFERENCES.md](docs/FRAMEWORK_REFERENCES.md) |

**Tests**
```bash
python -m pytest -q
```
```bash
python scripts/e2e_audit.py
```
```bash
python scripts/e2e_office.py
```
The first runs the regression suite. `e2e_audit.py` starts a fresh, isolated SegCheck and drives the whole
guided audit over HTTP (needs two private addresses on this PC, e.g. a VirtualBox or VMware adapter).
`e2e_office.py` audits the Docker office lab department by department (start the lab first).

**Upgrading an existing database by hand:** `python scripts/upgrade_local_database.py` backs up,
upgrades and compares records (`--check` for read-only). The launcher does this automatically.

**Separate review instance:** `python scripts/run_review_instance.py --data-dir <absolute folder>` runs
against its own data and secret, on loopback only.

**Project layout:**
- `segcheck/` is the engine (policies, probes, evidence) and `segcheck_web/` the web app
  (`routes/audit.py` + `services/audit_setup.py` = the four steps, `services/history.py` = History);
- `migrations/` holds the database schema;
- `launcher/` holds SegCheck.exe's source and its icon;
- `lab/office/` is the Docker office lab;
- `tests/`, `fixtures/` and `scripts/` hold the tests, test data and build tools.
