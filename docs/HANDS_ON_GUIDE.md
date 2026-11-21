# SegCheck hands-on guide: learn it by using it

Short labs, from your first double-click to auditing a fake company with a real firewall in Docker.
Every lab says what to do, what you should see, and why.

| Lab | You learn | Needs | Time |
|---|---|---|---|
| 0 | The picture: how SegCheck works | Nothing | 10 min |
| 1 | Start SegCheck.exe, create your account, tour the screens | This PC | 10 min |
| 2 | Your first real audit: your home router | This PC and your home router | 20 min |
| 3 | Audit a six-department company with a real firewall: find the hole, fix it, prove the fix | Docker Desktop | 45–60 min |
| 4 | Rehearse a client visit: install on a "fresh" PC, audit, take the evidence, leave the PC clean | This PC | 30 min |
| 5 | Break it on purpose: every error message and what it fixes by itself | This PC | 30 min |
| 6 | The automated tests: what they prove | This PC (+ Docker) | 20 min |
| 7 | Optional: the VirtualBox pfSense lab | VirtualBox VMs | see [VIRTUALBOX_LAB.md](VIRTUALBOX_LAB.md) |

Only ever test networks you own or have written permission to test. Everything here uses your own PC,
your own home network, or a fake network inside Docker.

---

## Lab 0: the picture

### The question SegCheck answers
PCI DSS (Requirement 11.4.5) says: if you use segmentation to keep systems *out of* PCI scope, prove at
least once a year that it works. In other words, prove that a PC in HR, Guest Wi-Fi or the staff LAN
**cannot** reach the card systems (the CDE).

### What actually happens

```
   Department network (e.g. Corporate 10.40.0.0/24)              CDE 10.30.0.0/24
  ┌──────────────────────────────┐                            ┌───────────────────────┐
  │ PC with SegCheck (Step 1)    │  1. TCP/UDP/ping attempts  │ Card database          │
  │ 10.40.0.100                  │ ─────────────┐            │ 10.30.0.20 :5432       │
  └──────────────────────────────┘              ▼            └───────────────────────┘
                                         ┌──────────────┐              ▲
                                         │  FIREWALL    │──────────────┘ forwarded? (hole)
                                         │  (Step 3)    │──X dropped?  (good)
                                         └──────┬───────┘
                       2. firewall log (syslog) │ "BLOCK 10.40.0.100 → 10.30.0.20:5432"
                                                ▼
                     ┌─────────────────────────────────────────────┐
                     │ SegCheck compares 1 + 2 with the checks     │
                     │ (Step 4: a standard or your own rules)      │
                     │ → FAIL / PASS / INCONCLUSIVE per check      │
                     │ → report: Violation / Enforced / Unproven   │
                     │ → evidence bundle (.zip with SHA-256 list)  │
                     └─────────────────────────────────────────────┘
```

1. The attempts **leave from the PC you sit at** and go through the real switches, routers and
   firewall. SegCheck never relays them: you test the real path.
2. If a forbidden service **answers**, the boundary has a hole: **FAIL**.
3. If nothing answers, that alone proves nothing: the firewall may have blocked it, or the service may
   be switched off. So the result stays **INCONCLUSIVE**. It becomes proof only when the firewall's own
   log says it blocked exactly that attempt. That is why Step 3 offers to connect the firewall's logs.

### The four steps

| Step | Question | Example |
|---|---|---|
| **Step 1 · Where you are** | Which network is this PC in? | Corporate staff LAN, this PC 10.40.0.100 |
| **Step 2 · What to test** | Which networks and hosts must this department not reach? | Card systems 10.30.0.0/24: 10.30.0.10, 10.30.0.20 |
| **Step 3 · Firewall** | Is there a firewall in between, and does it send logs? | Linux firewall, logs to this PC on UDP 5514 |
| **Step 4 · Checks & launch** | Which standard (or own rules) and which probes? | PCI DSS CDE isolation, all probes |

### Results

| Per check | Meaning |
|---|---|
| **FAIL** | A *must be blocked* service answered: a hole. |
| **PASS** | A *must work* (approved) service works. |
| **INCONCLUSIVE** | No answer. Not proof on its own. |

| Report verdict | Meaning |
|---|---|
| **Violation** | At least one forbidden path is open. |
| **Enforced** | Nothing forbidden answered *and* the firewall logged a block for every attempt. Strong evidence. |
| **Unproven** | Nothing answered, but there are no firewall logs to prove why. |

---

## Lab 1: start SegCheck and look around

### 1.1 Start it
Double-click **SegCheck.exe** in the SegCheck folder (the two-rings icon). It comes with the clone;
there is nothing to build or install first.

**What you should see**
- A black window titled **SegCheck**.
- The first time only, it creates `.venv` and installs packages (about 2 minutes). If Python is missing,
  a window offers to install Python 3.12 for your account.
- The window prints `Database ready.`, the data folder, and the **setup address and token**.
- Your browser opens the *Initial setup* page.

### 1.2 Create your account
Paste the token, choose a username and a strong password, sign in. The **Overview** is empty: SegCheck
never shows fake numbers.

### 1.3 Tour
| Menu | What it is for |
|---|---|
| **Overview** | Your results: pass rate, recent runs, map of tested paths, PCI coverage, audits on this PC |
| **New audit** with **Step 1 … Step 4** under it | The whole audit, one step after the other |
| **History** | Every audit on this PC: open, PDF, evidence ZIP, delete one or all |

### 1.4 Two launcher behaviours
1. Double-click **SegCheck.exe** again: it only opens the browser; no second copy starts.
2. Close the black window, then double-click again: it starts in about 5 seconds and your account is
   still there.

---

## Lab 2: your first real audit (your home router)

**Goal:** the full cycle on a network you own. You will see a real **FAIL**, a real **PASS** and real
**inconclusive** silence.

### Step 1 · Where you are
Open **New audit**. SegCheck lists this PC's networks and picks the one with a gateway (your Wi-Fi or
Ethernet). Name it `Home LAN`, kind **Office / staff PCs**, click **Use this network**.
**You should see:** "Step 1 saved", a summary (network, this PC's IP, subnet), and Step 1 ticked.

### Step 2 · What to test
Your router is in the same network as your PC, so use the card **Hosts in your own network**:
1. Click **Show hosts this PC already knows**. Your router (the gateway) appears; tick it, then **Add
   ticked hosts**. Or type its address (see `ipconfig`) and click **Add hosts**.
2. Optional: tick *I may ping every address* and click **Ping sweep**. Every device that answers on your
   home network is listed (phones, TV, printer…). This shows what discovery does; you don't need to add them.

**Why "own network":** no firewall separates them from your PC, so the standards skip them; your own
rules can still test them. Step 3 therefore says *Not needed*.

### Step 4 · My own rules
Step 4 opens on **My own rules** (no standard fits a single home network). Add two rules:
1. To the router · **Web (HTTP/HTTPS)** · must **be blocked** ("an ordinary PC should not reach the
   router's admin page").
2. **+ Another rule** · to the router · **DNS** · must **work (approved)** ("PCs need DNS").

Tick *I have written permission* and **Launch audit**. The live page shows every attempt.

### The report
What we saw on a normal home router (yours may differ):
- **Web must be blocked → FAIL**, because the router's admin page answers on 80. Verdict **Violation**.
  On a real client network that would be a finding: restrict the admin interface to a management network.
- **DNS must work → PASS.**
- Port 443 often times out → inside the same check, but one answering port is enough for FAIL.

Then: **Download PDF report**, **Evidence bundle (.zip)**.

### Check the evidence bundle
Extract the ZIP and open `MANIFEST.sha256`: one SHA-256 per file. In PowerShell:
```powershell
Get-FileHash .\report.json -Algorithm SHA256
```
The hash matches the manifest. Change one character in `report.json` and run it again: it no longer
matches. That is how an assessor knows the evidence was not altered. Saved reports can never be edited in
SegCheck either; a fix is proven by a new run.

---

## Lab 3: audit "PaySecure Ltd", a fake company with a real firewall (Docker)

**Goal:** the real auditor workflow, department by department. Six networks, a Linux firewall enforcing
the company's rules and logging every decision, and **one hidden misconfiguration**.

```
 Guest 10.20 ─┐                                  ┌─ HR 10.50 (HR database .10)
 Corporate 10.40 ─┤   CORE FIREWALL (x.x.x.1)    ├─ DMZ 10.60 (public website .10)
 DMZ ─────────┤   iptables + logs → 10.40.0.100  ├─ Servers 10.70 (file/LDAP/intranet .10)
 CDE 10.30 ───┘          UDP 5514                └─ CDE 10.30 (payment API .10 · card DB .20)

 The "auditor" container runs SegCheck and has an address in Guest, Corporate, DMZ and CDE: it plays
 the department PCs you would sit at.  UI: http://127.0.0.1:5091
```

### 3.1 Start the lab (fresh)
1. Start **Docker Desktop** and wait for *Engine running*.
2. From the SegCheck folder:
   ```bash
   cd lab/office
   ```
   ```bash
   docker compose down
   ```
   ```bash
   docker compose up -d --build
   ```
3. Open http://127.0.0.1:5091/setup. The lab's setup token is
   `office-setup-token-change-me-0123456789abcdef` (lab only). Create an account.

### 3.2 First department: Corporate
**Step 1:** pick the `10.40.0.100` network. Name `Corporate staff LAN`, kind **Office / staff PCs**,
client `PaySecure Ltd`.

**Step 2:** fill four rows and save them together:

| Name | Network | Kind | Hosts |
|---|---|---|---|
| Card systems | 10.30.0.0/24 | Card data environment (CDE) | 10.30.0.10 10.30.0.20 |
| HR department | 10.50.0.0/24 | HR / personal data | 10.50.0.10 |
| Internal servers | 10.70.0.0/24 | Internal servers | 10.70.0.10 |
| DMZ public web | 10.60.0.0/24 | DMZ / public-facing servers | 10.60.0.10 |

**Step 3:** *There is a firewall*, **Linux (iptables / nftables)**, leave the address empty, keep
*Connect its logs* ticked, **Save Step 3**. SegCheck picks UDP 5514 and shows the Linux instructions
(the lab's firewall is already set up that way). After the first audit the status shows *Logs arriving*
and *Learned the firewall's address from its logs: 10.40.0.1*.

**Step 4:** standard **PCI DSS · CDE isolation from out-of-scope networks**, all probes (50 attempts),
tick permission, **Launch audit**.

**What you should find:** one hole. **Card database 10.30.0.20 on 5432 is reachable**, and the firewall
logged it as **passed**. Verdict **Violation**. Everything else: blocked, and the firewall logged the block.
That is the hidden *legacy reporting* rule in `lab/office/firewall/rules.sh`.

**Own rules (the company's access matrix):** **My own rules** with:
- Public website · Web · must work;
- File server · Other ports TCP `445, 389` · must work;
- HR database · Databases · must be blocked;
- Payment API · Any remote admin · must be blocked.

Expect PASS, PASS, INCONCLUSIVE, INCONCLUSIVE, each block confirmed by the firewall's log.

### 3.3 Next department: Guest
**Step 1:** *Change where you are*, pick `10.20.0.100`, name `Guest Wi-Fi`, kind **Guest or visitor
Wi-Fi**. The targets stay. **Step 4:** run *CDE isolation*, then *Untrusted/DMZ networks to CDE* (only
available now: the PC is in a guest network).
**Expect:** nothing reachable and every attempt a logged block → **Enforced** (50/50 corroborated).

### 3.4 Next department: DMZ
**Step 1:** pick `10.60.0.100`, name `DMZ public web`, kind **DMZ**. The DMZ was a target; it now becomes
"where you are" and its web server moves to *Hosts in your own network*. **Step 4 · My own rules:**
- Payment API · Other ports TCP `8443` · must work → **PASS** (the approved checkout flow);
- Card database · Databases · must be blocked → blocked and logged.

### 3.4b The client's access matrix as a CSV (ranges, port ranges, reasons)
Real clients hand you a spreadsheet: *from which department, to what, which service, allowed or not, and
why*. SegCheck reads that as a CSV.
1. Step 4 · **My own rules** · **Example CSV**: open it in Excel or Notepad and look at the columns
   `from, to, service, protocol, ports, must, reason`.
2. Write `paysecure.csv`:
   ```
   from,to,service,protocol,ports,must,reason
   Corporate staff LAN,10.30.0.10-20,db,,,blocked,"Staff must not reach card data, PCI DSS 1.3.1"
   Corporate staff LAN,10.70.0.10,windows,,,work,Domain logon and file shares
   *,10.30.0.10,custom,tcp,8000-8002,blocked,No department reaches the API test ports
   Guest Wi-Fi,10.30.0.0/28,ping,,,blocked,Guests must not see card systems
   ```
3. On the Corporate PC: **Load rules from CSV…** → *Loaded 3 rule(s) for Corporate staff LAN; skipped 1
   for other departments*. The first row is a typed range (11 hosts × 6 database ports = 66 attempts):
   read each rule's preview line.
4. Launch. Every rule card in the report shows its **Rule reason**.
5. **Save rules as CSV** downloads the rules as they are now. On the Guest PC, load the same file: only the
   Guest row and the `*` row are used.

Try a mistake: put `192.168.99.5` in `to`. Launch explains that the address is not inside any network of
Step 1 or Step 2; add that network in Step 2 first.

### 3.5 The client fixes the firewall; you prove it
```bash
docker compose exec firewall /lab/rules.sh fixed
```
Step 1 back to Corporate (`10.40.0.100`), run *CDE isolation* again: nothing reachable, **Deny enforced
and corroborated by firewall logs**. The old report still says Violation: History keeps both, which is
what an assessor wants (finding → fix → proof). To put the hole back: `docker compose exec firewall
/lab/rules.sh office`.

### 3.6 Look at the logic yourself
- `docker compose logs -f firewall` shows the firewall deciding while you run an audit.
- `lab/office/firewall/rules.sh`: each `allow` line is an approved flow; `legacy-reporting` is the hole.

### 3.7 Stop the lab
```bash
docker compose stop
```
(`docker compose down` also deletes the lab's SegCheck data.)

---

## Lab 4: rehearse a real client visit (install → audit → evidence → remove)

Your own data from Labs 1–2 lives in `%LOCALAPPDATA%\SegCheck`. Put it aside first so the rehearsal starts
like a brand-new PC: close SegCheck, then in File Explorer rename `%LOCALAPPDATA%\SegCheck` to
`SegCheck-mine`.

1. **Arrive and install:** download the project ZIP (or `git clone`) and extract it to `C:\SegCheckVisit`.
   Double-click `C:\SegCheckVisit\SegCheck.exe`. First start: packages install (about 2 minutes), then the
   setup page opens.
2. **Set up:** account, Step 1 (this PC's network), Step 2 (targets), Step 3 (firewall or none).
3. **Audit:** Step 4, launch, read the report, download the **Evidence bundle** and **PDF** and copy them
   off the PC (in the rehearsal: `D:\Evidence\HR`).
4. **Leave the PC clean:** close the window, delete `C:\SegCheckVisit`, delete `%LOCALAPPDATA%\SegCheck`,
   and remove Python in *Settings → Apps* if it was installed only for this visit.
5. Rename `SegCheck-mine` back to `SegCheck`.

**On a real visit:** one PC per department, usually with the client's IT person logged in. Agree before
the visit how Python may be installed, that *More info → Run anyway* is allowed for SegCheck.exe, and how
you take the evidence off the PC. Your combined result is the set of evidence bundles, one per department.

---

## Lab 5: break it on purpose

SegCheck **fixes by itself** what it safely can (`Fixed automatically: …` plus the next step). Everything
else is explained with numbered steps. Try each:

| Do this | You should see |
|---|---|
| Start another program on port 5000 (`python -m http.server 5000`), then SegCheck.exe | `Fixed automatically: port 5000 is used…, so SegCheck uses port 5001 instead.` |
| Then double-click SegCheck.exe again | It finds SegCheck on 5001 and just opens it |
| `SegCheck.exe --port 80` | `Fixed automatically: port 80 cannot be used…, so SegCheck uses port 5000` |
| Close SegCheck, overwrite `segcheck.sqlite3` in the data folder with any text, start again (needs one automatic backup, made on upgrades) | `Fixed automatically: the database file was damaged… restored from the newest automatic backup`; the damaged file is kept |
| Open the downloaded ZIP in Explorer *without extracting* and double-click SegCheck.exe | A window explains it was opened inside a ZIP and how to extract it |
| Move SegCheck.exe alone to the Desktop and double-click | It must stay in its folder; use *Send to → Desktop (create shortcut)* |
| Double-click SegCheck.exe twice quickly on the very first start | "SegCheck is already starting" |
| Step 1: type an IP that is not in the subnet | `This PC's address … is not inside …` |
| Step 2: a host like `10.30.0.x` | `Not an IP address: 10.30.0.x` |
| Step 2: a target network that overlaps this PC's network | `must not overlap` |
| Step 2: *Ping sweep* without ticking the box | "Tick the box first…" |
| Step 2: *Ping sweep* on a /16 | It refuses: at most a /24 |
| Step 3: firewall logs, while another program uses UDP 5514 | SegCheck picks the next free port and shows it in the instructions |
| Step 3: firewall logs on, but nothing sends logs for a minute | The usual causes, incl. the Windows Firewall command for an administrator |
| Step 4: launch without the permission tick | "Tick the authorisation box…" |
| Step 4: launch while another audit runs | "Another assessment is running…" |
| Step 4: own rule with port 99999 | "ports between 1 and 65535" |
| History: Delete everything without typing DELETE | "Type DELETE to confirm" |
| Wait until a form expires (or sign out in another tab), then submit | **This form expired** |
| Sign in with a wrong password many times | **Too many attempts** |
| Cancel a running audit | It stops; no half report is saved |

---

## Lab 6: the automated tests

```bash
.venv\Scripts\python.exe -m pytest -q
```
About 470 tests: the four steps, discovery, firewall log parsing and learning (including a real pfSense
capture), the verdict logic, security (sign-in throttling, CSRF, the database's protection of saved
reports and the History delete), self-repair and error pages.

```bash
.venv\Scripts\python.exe scripts\e2e_audit.py
```
Starts a brand-new SegCheck and drives the whole guided audit over HTTP like a browser (about 80 checks).
It needs two private addresses on this PC (e.g. a VirtualBox or VMware adapter).

With the Docker lab running (Lab 3):
```bash
.venv\Scripts\python.exe scripts\e2e_office.py
```
Lab 3 automated: every department, the hole, the fix and the proof (35 checks). Each script writes its
results to `reports\`.

---

## Clean up after learning

| What | How |
|---|---|
| Office lab, keep for later | In `lab\office`: `docker compose stop` |
| Office lab, remove completely | In `lab\office`: `docker compose down`, then delete the `segcheck-office-*` images in Docker Desktop |
| Lab 4 rehearsal | Delete `C:\SegCheckVisit`; make sure `SegCheck-mine` was renamed back |
| Your own audits | **History → Delete everything** (or delete them one by one) |
