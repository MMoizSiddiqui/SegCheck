# SegCheck user guide

The complete walkthrough of an audit, how to read every result, and what to do when something goes wrong.
For the overview and quick start, see the [README](../README.md).

**Contents:** [1. Run the audit](#1-run-the-audit-new-audit-step-1-to-step-4) ·
[2. Reading the results](#2-reading-the-results) · [3. Troubleshooting](#3-troubleshooting) ·
[4. Data and removal](#4-where-the-data-is-and-removing-segcheck-from-a-pc) ·
[5. Safety and permission](#5-safety-and-permission)

## 1. Run the audit: New audit, Step 1 to Step 4

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
- **Ping sweep** (at most a /24, one ping per address);
- tick what was found and **Add ticked hosts**, or type addresses; remove hosts or whole networks.

*Hosts in your own network* (same subnet as this PC, e.g. the router) can be added too. The standards
skip them (no firewall in between), but your own rules can test them.

**Step 3 · Firewall.**
- **No firewall, or I don't know:** one click. Attempts go straight through the router; anything that
  answers is a FAIL, silence is reported as *unproven*, never as passed.
- **There is a firewall:** choose its type: pfSense/OPNsense, Linux (iptables/nftables), Fortinet FortiGate,
  Cisco ASA / Firepower (FTD), Sophos Firewall, MikroTik RouterOS, or Other (tested without logs). Its address is
  pre-filled with the gateway; left empty, SegCheck fills it in from the firewall's first log line (the firewall
  sends its logs from that address). Step 3 is in order: **3a** choose, **3b** connect its logs (setup steps written for
  that firewall type, for its administrator), **3c** optional rule export. With **Connect its logs** ticked, SegCheck picks a free UDP port on this PC
  and shows exactly what to set on the firewall, with this PC's address and port already filled in. It
  learns the firewall's sending address from the first log, and the status turns green when logs arrive.
  Problems (port in use, logs from another address, unknown format, nothing arriving) are shown with
  numbered fixes. SegCheck only listens; it never logs in to the firewall or changes it.
- **Its addresses in the other networks (optional):** a firewall is one box with an address in every network it
  connects (e.g. 10.40.0.1 for staff, 10.30.0.1 in the card network). ISO/IEC 27002 8.20 and NIST SC-7 require
  that staff networks cannot reach the firewall's own admin services on *any* of them, and many firewalls answer
  on all. List them here (or click the suggestions taken from a loaded pfSense `config.xml` or a network's
  gateway) and the Step 4 *Firewall management plane* check tries SSH, web admin and SNMP on every one. These
  addresses are used by that check only: they do not change how logs reach this PC, and the other standards
  never treat them as servers. A wrong entry is refused and the saved Step 3 stays as it was.
- **Firewall rules (optional):** load a read-only rule export: pfSense/OPNsense `config.xml`
  (*Diagnostics → Backup & Restore*) or Linux `iptables-save` output. SegCheck evaluates it in the firewall's
  own order (first match wins; for attempts aimed at the firewall itself: the Linux INPUT chain, or pfSense's
  anti-lockout and *This firewall* rules) and the report then names the exact rule behind each result, e.g.
  *Let through by firewall rule: legacy-reporting (FORWARD rule 7: pass 10.40.0.0/24 → 10.30.0.20/32 tcp 5432)*.
  Even without an export, the rule is named from the firewall's log (pfSense tracker or log prefix).

**Step 4 · Checks & launch.**
- **A standard:** PCI DSS 4.0.1 (CDE isolation, untrusted/DMZ to CDE, CDE outbound), NIST SP 800-53
  (SC-7 boundary, deny by default), ISO/IEC 27002 (8.22 segregation, 8.20 firewall management plane),
  CIS v8 (12.2/13.4). Standards that do not fit this network are greyed out with the reason.
  Choose **One standard**, or **Several standards in one run** (*Tick every applicable standard*): each
  probe is then sent once and counts for every standard that asks for it.
- **Waiting for answers:** attempts run one after another. An answer is final. A silent attempt is tried once
  more with a longer wait (1–3 s, then 3–6 s, following how fast this network really answers), unless the
  firewall's log already shows it blocked that attempt; so a lost packet or a slow network does not hide an open
  door. The estimated time is shown before launch.
- **Stops early when the setup makes the run pointless,** and says what to fix: this PC's address disappeared or
  local security software blocks sending (3 attempts in a row); or Step 3 expects firewall logs, none has arrived and
  nothing has answered after 8 silent attempts. No misleading report is saved. (No route to a network does not stop
  the run: that network is simply not reachable from this PC, and the report notes it.)
- **Every report says what limited it** in a *Problems in this run: fix and run again* box (logs missing or partial,
  no log feed, no firewall declared, log and result disagreeing, network errors, a slow network), with the exact fix.
  If nothing reached the network at all, the verdict is *COULD NOT TEST*.
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
- Click **Launch audit**.

**Then** SegCheck does the rest: it checks everything is ready (and explains anything missing), sends the
attempts from this PC (at most 400; a silent attempt is retried once with a longer wait), shows each one live (you can cancel; a
cancelled run never produces a half report), cross-checks the firewall's logs, decides the verdict, and
saves the report.

**The report** opens with a plain verdict (**FAILED**, **PASSED: blocked and proven**, **NO HOLE FOUND but
not proven**, or **ATTENTION: approved service not working**) and counts (rules tested, passed, failed, no answer).
Then **Rule by rule**: the target, the probe that was sent, what was expected, what happened on every
port (e.g. *TCP 80 Connected*, *TCP 443 No reply*, each explained in plain words), the result, why, and
what to do. A **map of the run** shows this PC and every host coloured by its result (click a host for
its rules; **Replay attempts** plays the run in order). Below that: the summary and findings, the firewall
cross-check, and for standards the heatmap and control results. The PCI wording appears only when PCI
checks were part of the audit.

**Verdict per standard (compliance assistant).** The report also judges the run against every chosen
standard, control by control: e.g. *PCI DSS 1.3.1: Not met (10.30.0.20 TCP 5432)*, *ISO 8.22: Met, proven*.
One control can be met while another fails, so standards can disagree, and the report says why. Each control
shows what failed, the fix, an acceptable alternative and the evidence an assessor expects. It works offline:
a retrieval step matches each result to the relevant controls in SegCheck's own knowledge base
(`segcheck_web/knowledge/controls.json`: short summaries in SegCheck's own words, with links to the official
standards), and the verdict comes only from the measured results; no AI model, so the same run always gives
the same answer. Own-rules audits are checked against every standard; a standard none of the rules touches is
left out. The **Overview** has the same map for all audits, with a strip to step
through past runs and **Play history**. Download the **PDF** or the **Evidence bundle (.zip)**
(PDF, exact JSON, policy, environment, firewall evidence and `MANIFEST.sha256`, so anyone can check
nothing was altered). Copy it off the PC the client's approved way.

**History** lists every audit on this PC with its verdict: open, PDF, evidence, **Compare two audits**
(drift and regression: what got fixed, what got worse, what stayed the same), **Delete**, or **Delete
everything** (type DELETE; optionally also the firewall logs and the automatic backups). Deleted data is
removed from the database file itself. Saved reports can never be changed, only deleted.

**Fix and retest:** after the client changes the firewall, run the audit again; the new report proves
the fix, and *Compare with the previous audit from this network* shows it as **FIXED** (or a
**REGRESSION** if a change opened something new). Then remove SegCheck from the PC (section 4) and go to the next department.

## 2. Reading the results

Each rule card shows one of these results:

| Per check | Meaning |
|---|---|
| **Failed** | It must be blocked, but it answered: the segmentation has a hole. The card names the firewall rule to fix. |
| **Failed: firewall let it through** | Nothing answered, but the firewall's own log shows it passed the attempt: the path is open at the boundary. |
| **Failed: approved service not working** | It must work (an approved business flow), but it did not answer. |
| **Passed: blocked, proven by firewall log** | Nothing answered, and the firewall logged a block for every attempt. This is proof. |
| **Passed: works as approved** | It must work, and every port answered. |
| **No answer: not proven** | Nothing answered, but no firewall log proves why (a block, or a service that is simply off). Connect the logs in Step 3 to turn this into proof. |
| **Not run from this PC** | The rule starts in another department; run the audit from a PC there. |

The report opens with one verdict for the whole run:

| Report verdict | Meaning |
|---|---|
| **FAILED** | At least one forbidden path is open (it answered, or the firewall logged it as passed). |
| **ATTENTION** | Nothing forbidden is open, but an approved service is not working. |
| **PASSED** | Every forbidden path was blocked **and** the firewall's log proves it (or, for allow-only rules, every approved service works). |
| **NO HOLE FOUND** | Nothing forbidden answered, but it is not proven: connect the firewall's logs and run again. |
| **COULD NOT TEST** | Nothing reached the network (for example this PC lost its address); the *Problems in this run* box says what to fix. |

The dashboard also lists **untested zones**: departments no run has started from yet. Untested is never passed.

## 3. Troubleshooting

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
| **Step 4: Another audit is still running** | Open it from the banner at the top of Step 4, then wait for it or cancel it. |
| **Too many attempts** at sign-in | Wait a few minutes (password-guessing protection). |
| **Something went wrong… Reference: ABCD1234** | Retry. If it repeats, look in `logs\errors.log` in the data folder. |

### Firewall log feed (Step 3)
Step 3 shows the feed's state and, when something is wrong, a numbered list of fixes:

| Tile says | What to do |
|---|---|
| *UDP port 5514 is already used by another program on this PC* | Save firewall choice again: SegCheck picks the next free port and shows it; set that port in the firewall's remote logging |
| *… is not an address of this PC* | Leave *This PC receives logs on* empty, or redo Step 1 if the PC's address changed |
| *Logs are arriving from X, but the sender IP is set to Y* | If X is the firewall, save Step 3 with *Logs come from* empty (SegCheck learns it) or set X |
| *Logs arrive but their format is not recognised* | pfSense/OPNsense: log format *BSD (RFC 3164)*; Linux: iptables/nftables `LOG` rules |
| *Nothing has arrived for a minute* | Check the firewall's remote-logging target (this PC's IP and port), switch on *Log* for the deny rules, and allow inbound UDP on that port in Windows Firewall (the tile shows the exact command for an administrator) |

### Results
| Situation | Why | What to do |
|---|---|---|
| Everything **No answer: not proven** | No firewall logs connected | Step 3: choose *There is a firewall* with its logs; enable logging on its deny rules |
| An allowed flow shows **Approved flow not working** | The business service did not answer | Check the service is running, or that a rule is not blocking an approved flow |
| A standard is greyed out | It needs another kind of network here (e.g. *CDE outbound* needs this PC inside the CDE) | Run it from a PC in such a network, or choose another standard |

## 4. Where the data is, and removing SegCheck from a PC

All data is in **`%LOCALAPPDATA%\SegCheck`** on that PC: the database, the signing secret
(`secret.key`), evidence, logs, and `backups` (made automatically before every upgrade).

To leave the PC clean after the audit:
1. **Download the evidence bundles** you need and copy them off the PC.
2. **Close the black SegCheck window.**
3. **Delete the SegCheck folder** (for example `C:\SegCheck`).
4. **Delete `%LOCALAPPDATA%\SegCheck`:** paste that into the File Explorer address bar.
5. **If SegCheck installed Python for this visit,** remove it in *Settings → Apps*.

## 5. Safety and permission

- Get **written permission** (scope, address ranges, dates, which PCs) before testing any network you
  do not own.
- SegCheck only sends the attempts shown in the preview, after you click Launch: at most
  400 attempts per run, each waiting a few seconds at most. A ping sweep only runs after its own tick box.
- The dashboard listens on this PC only (`127.0.0.1`); nothing on the network can reach it.
- Firewall connectors are **read-only**: SegCheck never changes devices.
- No administrator rights are needed.
