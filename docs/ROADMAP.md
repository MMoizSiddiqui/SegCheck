# Roadmap

## How SegCheck is meant to be used
One PC per department: clone or extract SegCheck there, double-click `SegCheck.exe`, run **New audit**
(Step 1 · Where you are, Step 2 · What to test, Step 3 · Firewall, Step 4 · Checks & launch), take the
evidence bundle, remove SegCheck. Remote agents, a USB edition, a network server mode and the old
multi-page policy management were removed on purpose (20–21 November 2026) to keep the tool simple.

## Done
- **SegCheck.exe:** double-click setup and start, plain-language errors, and self-repair (busy port,
  damaged database, broken environment, read-only folder, ZIP not extracted…).
- **Step 1:** this PC's networks detected and pre-selected; moving into a target network converts it.
- **Step 2:**
  - several target networks at once (subnet derived from the first host if empty);
  - hosts this PC already knows;
  - ping sweep (authorised, at most a /24);
  - hosts in this PC's own network.
- **Step 3:**
  - "no firewall" in one click;
  - or pfSense/OPNsense or Linux with a read-only log feed: free UDP port picked automatically, exact
    firewall instructions with values filled in, sender learned from the first log;
  - FortiGate, Cisco ASA/FTD, Sophos and MikroTik log formats (verified against documented formats);
  - the firewall's addresses in the other networks, for the management-plane check;
  - every feed problem explained with fixes;
  - optional read-only rule export (pfSense/OPNsense `config.xml` or `iptables-save`): the report names the
    rule behind each result, also named from the firewall's own log.
- **Step 4:**
  - 8 standards (PCI DSS 4.0.1, NIST SP 800-53, ISO/IEC 27002, CIS v8) with tick-box probe groups and a
    live attempt count;
  - or own rules: hosts, whole networks, or typed addresses, ranges and subnets; services, bundles or
    port ranges; must be blocked / must work; a reason per rule shown in the report;
  - the client's access matrix as a CSV (load keeps this department's rows; save for the next PC);
  - one standard or several standards in one run (each probe sent once, counted for every standard);
  - one launch: up to 400 attempts as one run;
  - patient probing: answers are final, a silent attempt is retried once with an adaptive longer wait,
    and a logged block ends the wait early;
  - early stop with a plain reason when the setup makes the run pointless (address lost, sending blocked,
    no firewall logs arriving).
- **Run and report:**
  - live progress, cancel, one run at a time;
  - immutable report (verdict, findings, heatmap, control matrix, firewall cross-check), PDF;
  - evidence ZIP with SHA-256 manifest;
  - verdict per standard and per control (offline retrieval over SegCheck's own control knowledge base),
    with fix, alternative and expected evidence;
  - a *Problems in this run* box with the exact fix for anything that limited the run;
  - firewall rule attribution on every rule card.
- **History:**
  - every audit with its verdict;
  - delete one or all (optionally firewall logs and backups); deleted data removed from the file;
  - saved reports can never be changed;
  - compare two audits: fixed, regression, still failing, unchanged.
- **Docker office lab:** seven networks (including an admin network that may reach the CDE only over SSH), a
  real firewall, a hidden misconfiguration, and double-click reset / fix / add-loophole files.

## Future work
| Item | Why |
|---|---|
| Combined client report across departments | One overview from all departments' evidence bundles |
| Path trace (traceroute) for failed rules | Show which hop let forbidden traffic through |
| Banner grab on reachable ports | Name the service that answered, not just the port |
| Re-audit reminders | PCI DSS expects segmentation tests at least every 12 months (6 for service providers) |
| Approved exceptions for standards | Let NIST/ISO/CIS standards skip flows the client's access matrix approves, instead of flagging them |
| Optional AI wording for the assistant | A local or API model could phrase explanations; verdicts would still come only from measurements |
| Code-signed SegCheck.exe | Avoid the SmartScreen warning on client PCs |
