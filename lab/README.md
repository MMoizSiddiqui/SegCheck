# SegCheck office lab: a whole company network in Docker

This folder builds **"PaySecure Ltd"**, a small fake payment company, on any PC with Docker Desktop. It has
seven department networks, five business systems, a **real Linux firewall** that enforces the company's
rules and logs every decision, and **SegCheck** sitting inside the network like an auditor's PC.

Nothing is simulated: SegCheck sends real TCP/UDP/ICMP packets, they cross a real firewall, and the firewall's
real log lines come back to SegCheck. Everything runs only on your PC; nothing is exposed to your network.

---

## 1. Why this lab exists

SegCheck answers one question: *does the network really keep departments apart the way the company's
policy says?* It tests that against four standards' network-segmentation controls, and the report gives a
verdict per standard and per control:

| Standard | Controls SegCheck tests |
|---|---|
| **PCI DSS 4.0.1** | 1.3.1 inbound traffic to the CDE restricted · 1.3.2 outbound traffic from the CDE restricted · 1.4.2 traffic from untrusted networks restricted · 11.4.5 segmentation is tested |
| **NIST SP 800-53 Rev. 5** | SC-7 boundary protection · SC-7(5) deny by default, allow by exception · AC-4 information flow enforcement |
| **ISO/IEC 27002:2022** | 8.22 segregation of networks · 8.20 networks security (management access) |
| **CIS Controls v8** | 12.2 secure network architecture · 13.4 traffic filtering between segments |

PaySecure is a payment company, so the headline is **PCI DSS**: staff, guests and the public website must not
reach the **card data environment (CDE)**, and Requirement 11.4.5 says this must be *tested*, not just written
down. In SegCheck's Step 4 you can run one standard, several standards in one run, or the company's own rules
(its access matrix).

To show that SegCheck actually catches problems, the firewall contains **one deliberate mistake**, the kind
real audits find all the time: an old reporting project once needed access to the card database, someone
added a firewall rule, the project ended, and nobody removed the rule.

```
legacy-reporting:  staff PCs (10.40.0.0/24)  →  card database 10.30.0.20, port 5432   ALLOWED (it should not be)
```

The demo story is: **SegCheck finds the hole → names the exact firewall rule → the "network team" removes it
→ SegCheck proves it is fixed.** You can switch the mistake off and on at any time (section 6).

---

## 2. The company

| Network | Subnet | Real-life meaning | Systems in it (the targets) |
|---|---|---|---|
| guest | 10.20.0.0/24 | Visitor Wi-Fi | none |
| corporate | 10.40.0.0/24 | Staff PCs | none |
| hr | 10.50.0.0/24 | HR (personal data) | HR database `10.50.0.10` (5432, 445) |
| dmz | 10.60.0.0/24 | Public website zone | Website `10.60.0.10` (80, 443) |
| servers | 10.70.0.0/24 | Internal servers | File / LDAP / intranet server `10.70.0.10` (445, 389, 8080, DNS 53) |
| cde | 10.30.0.0/24 | Card data environment (PCI scope) | Payment API `10.30.0.10` (8443, SSH 22) · Card database `10.30.0.20` (5432) |
| admin | 10.80.0.0/24 | IT administrators | none |

**The company's policy** (what the firewall allows; everything else is blocked and logged):

| Rule name | From → to | Ports | Why |
|---|---|---|---|
| corp-web | Staff → website | 80, 443 | Staff use the public site |
| corp-servers | Staff → file server | 445, 389, 8080 | File shares, logon, intranet |
| corp-dns | Staff → file server | DNS 53 | Name resolution |
| hr-servers | HR → file server | 445, 389, 8080 | Same services for HR |
| checkout-payment-api | DMZ → payment API | 8443 | The website's checkout calls the payment API |
| admin-ssh-payment-api | Admin → payment API | SSH 22 | Admins manage the CDE only over SSH |
| **legacy-reporting** | **Staff → card database** | **5432** | **The planted mistake (office mode only)** |

Networks with no systems (guest, corporate, admin) are places to **test from**: SegCheck sits in them as the
department's PC. Networks with systems are what SegCheck **tests against**.

---

## 3. The building blocks: networks, images, containers

Three Docker ideas, each with a real-world equivalent:

| Docker thing | Real-world equivalent | In this lab |
|---|---|---|
| **Network** | A network switch / VLAN | 7 networks, one per department (section 2) |
| **Image** | A machine's installed disk, frozen | 7 images: firewall, auditor, and 5 business systems |
| **Container** | A running machine, plugged into switches | 7 containers started from those images |

You see the images on Docker Desktop's **Images** page and the containers grouped under **segcheck-office**
on its **Containers** page (a green dot means running). Networks have no page in Docker Desktop; list them with
`docker network ls`.

**`docker/docker-compose.yml` is the plan for all of it.** It says which networks exist, which images to build
from which recipe, which machine is plugged into which network with which address, and how each one starts.
Docker reads it when you run `docker compose up` (the Reset button does that for you).

```
                     guest    corporate    hr      dmz     servers    cde      admin        ← 7 virtual switches
                       │         │         │        │         │        │         │
  FIREWALL  ───────────●─────────●─────────●────────●─────────●────────●─────────●          .1 on every network
                       │         │         │        │         │        │         │
  AUDITOR (SegCheck) ──●─────────●─────────┼────────●─────────┼────────●─────────●          .100 on five networks
                                           │        │         │        │
                                        hr-db     web    file-server  payment-api, card-db  one network each
```

Every business system uses the firewall's `.1` address as its gateway, so **all traffic between departments
has to pass through the firewall**, exactly like a real office.

---

## 4. How each machine is built

| Machine | Recipe (image) | Started by | What it does |
|---|---|---|---|
| **firewall** | [`docker/firewall/Dockerfile`](docker/firewall/Dockerfile) | [`docker/firewall/start.sh`](docker/firewall/start.sh) | Alpine Linux with `iptables` (the firewall), `ulogd` (collects its decisions) and `syslogd` (sends them on). Routes between all 7 networks and enforces [`rules.sh`](docker/firewall/rules.sh). |
| **auditor** | [`docker/auditor/Dockerfile`](docker/auditor/Dockerfile) | [`docker/auditor/entry.sh`](docker/auditor/entry.sh) | SegCheck itself: Debian + Python + SegCheck's libraries + the SegCheck code from this repository. Plays the PC you sit at in each department. |
| **card-db, payment-api, hr-db, web, file-server** | [`docker/systems/Dockerfile`](docker/systems/Dockerfile) (one image, reused) | [`docker/systems/services.py`](docker/systems/services.py) | Stand-ins for real systems. Each opens the ports listed for it in `docker-compose.yml` and answers connections (DNS gets a minimal reply). They hold no data; SegCheck only needs to know whether a port answers. |

### The firewall, step by step
1. **Build:** `firewall/Dockerfile` installs the tools and copies `ulogd.conf`, `rules.sh` and `start.sh` into
   the image. At this point the rules are only a file inside the image.
2. **Plug in:** `docker-compose.yml` connects it to all 7 networks with address `.1`, turns on routing
   (`ip_forward=1`), and sets `MODE: office` and `SYSLOG_TARGET: 10.40.0.100:5514`.
3. **Start:** `start.sh` runs, in order:
   ```sh
   syslogd -n -R 10.40.0.100:5514 -L &   # forward every log line to SegCheck
   /lab/rules.sh office                  # load the company rules (with the planted mistake)
   exec ulogd -c /etc/ulogd.conf         # collect the firewall's decisions and pass them to syslog
   ```
4. **`rules.sh`:** default *block everything*; let replies to allowed connections back; for each approved
   flow, first a log rule (`SEGCHECK-ACCEPT <name>`) then an allow rule; in `office` mode also
   `legacy-reporting`; finally log everything else as `SEGCHECK-DROP` and drop it. The firewall also protects
   **itself** (ISO/IEC 27002 8.20): only the admin network may connect to its own addresses (10.x.0.1); from any
   other network, connections to them are logged as `SEGCHECK-DROP` and dropped (`firewall-self-protection`).
   To test this, enter `10.20.0.1 10.30.0.1 10.50.0.1 10.60.0.1 10.70.0.1 10.80.0.1` in Step 3a under *Its
   addresses in the other networks* and run *Firewall management plane protection*: PASS, proven by the logs.

Because the image holds its own copy of `rules.sh`, editing the file on your PC changes nothing until the
image is rebuilt (Reset).

### The auditor (SegCheck), step by step
1. **Build:** `docker-compose.yml` builds `docker/auditor/Dockerfile` with the **whole repository** as input, so the image
   always contains the current SegCheck code. It installs `iproute2` and `ping`, creates a non-root user, installs
   `requirements.txt` and copies `segcheck/`, `segcheck_web/`, `scripts/` and `tests/`.
2. **Plug in:** five networks with address `.100` (guest, corporate, dmz, cde, admin), and port
   `127.0.0.1:5091` on your PC forwarded to SegCheck's port 5000 inside.
3. **Start:** `entry.sh` does two things:
   - **Routes every department through the firewall.** For each address it creates a routing table and a rule:
     *anything sent from 10.40.0.100 goes to 10.40.0.1* (the firewall's corporate side), and so on for each
     network. Without this, Linux would take a shortcut (the auditor is also on the CDE network) and tests would
     bypass the firewall.
   - **Starts SegCheck** as the non-root user, with its data in `/home/segcheck/data` inside the container.

So choosing `10.40.0.100` in SegCheck's Step 1 really means *"I am a staff PC"*: every attempt leaves through the
staff network's door in the firewall.

---

## 5. Following one test from start to finish

*"Can a staff PC reach the card database on port 5432?"*

```
1. You (browser)  → http://127.0.0.1:5091 → SegCheck (auditor container). Step 1: 10.40.0.100. Launch.
2. SegCheck       → sends a TCP connection from 10.40.0.100 to 10.30.0.20:5432.
3. Routing        → entry.sh's routing rule sends it to the firewall at 10.40.0.1.
4. Firewall       → checks rules.sh top to bottom. In office mode "legacy-reporting" matches → ALLOW,
                    forwards it on the cde network to the card database.
5. card-db        → answers (its gateway is 10.30.0.1, so the reply goes back through the firewall).
6. Firewall log   → "SEGCHECK-ACCEPT legacy-reporting … SRC=10.40.0.100 DST=10.30.0.20 DPT=5432"
                    ulogd → syslogd → UDP to 10.40.0.100:5514 (SegCheck's Step 3 listener).
7. SegCheck       → result "reachable" + firewall "let through" + rule "legacy-reporting"
                    → the rule "must be blocked" FAILS. Report: what answered, why it matters, which rule to remove.
```

For a blocked attempt the firewall logs `SEGCHECK-DROP` instead, nothing answers, and SegCheck reports
*blocked, proven by the firewall's log*: silence alone is never counted as proof.

---

## 6. Using it

Docker Desktop must be installed. The **Start** and **Reset** buttons start it by themselves if it is closed
(and wait for its engine); for the commands below it must be running (*Engine running*).

### Windows: double-click
In `lab/`:

| Double-click | What it does |
|---|---|
| **Start lab (keep audits).cmd** | Starts the 7 containers (or keeps them running), waits until SegCheck answers, then **opens SegCheck in your browser** and shows a **Windows notification**. Audits and account are kept. About 15 seconds. |
| **Reset lab (fresh, with loophole).cmd** | Removes the old lab, builds the images, starts fresh containers, waits for SegCheck, saves `firewall-rules.txt`, opens SegCheck's setup page in your browser with a Windows notification, and prints the setup token. **Wipes the lab's audits.** First run 2–5 minutes, later about 30 seconds. |
| **Firewall - fix loophole.cmd** | Removes `legacy-reporting` from the running firewall immediately. Audits are kept. |
| **Firewall - add loophole.cmd** | Puts it back immediately. Audits are kept. |

These call [`tools/start-lab.ps1`](tools/start-lab.ps1), [`tools/reset-demo.ps1`](tools/reset-demo.ps1) and
[`tools/firewall.ps1`](tools/firewall.ps1). A container cannot open anything on your desktop, so the browser and
the notification come from these scripts on your PC, once the auditor container's SegCheck answers. Starting the
group with ▶ inside Docker Desktop works too, but then nothing opens by itself: go to http://127.0.0.1:5091.

### Any OS: commands
```bash
docker compose -f lab/docker/docker-compose.yml down                 # remove the old lab (wipes its audits)
docker compose -f lab/docker/docker-compose.yml up -d --build        # build and start it fresh
docker compose -f lab/docker/docker-compose.yml exec firewall /lab/rules.sh fixed    # remove the loophole
docker compose -f lab/docker/docker-compose.yml exec firewall /lab/rules.sh office   # put it back
docker compose -f lab/docker/docker-compose.yml exec -T firewall iptables-save > lab/firewall-rules.txt
```

### Then, in the browser
1. Open http://127.0.0.1:5091/setup, enter the setup token `office-setup-token-change-me-0123456789abcdef`
   (lab only) and create an account.
2. **New audit, Step 1:** pick `10.40.0.100`, kind *Office / staff PCs*.
3. **Step 2:** add the target networks (Card systems 10.30.0.0/24 with 10.30.0.10 10.30.0.20, HR 10.50.0.0/24 with
   10.50.0.10, Internal servers 10.70.0.0/24 with 10.70.0.10, DMZ 10.60.0.0/24 with 10.60.0.10).
4. **Step 3:** *There is a firewall* → *Linux (iptables / nftables)*, logs on. Optionally load
   `lab/firewall-rules.txt` under *Firewall rules* so the report can name each rule's number and contents.
5. **Step 4:** *PCI DSS · CDE isolation from out-of-scope networks* → Launch.
   Expected: **FAILED**, card database 5432 reachable, *let through by firewall rule: legacy-reporting*.
6. Fix the loophole, run it again: **PASSED**. *Compare with the previous audit* shows it as **FIXED**.

Other departments: in Step 1 choose *Change where you are* and pick `10.20.0.100` (guest), `10.60.0.100` (DMZ) or
`10.80.0.100` (admin, kind *Admin / management network*). [`paysecure-access-matrix.csv`](paysecure-access-matrix.csv)
is the company's access matrix (from, to, service, ports, must, reason); load it in Step 4 → *My own rules* and
each department's PC uses only its own rows.

The full guided walk-through is [Lab 3 of the hands-on guide](../docs/HANDS_ON_GUIDE.md#lab-3-audit-paysecure-ltd-a-fake-company-with-a-real-firewall-docker).

### Check everything automatically
Right after a fresh start, before creating an account yourself:
```bash
python scripts/e2e_office.py
```
It plays every department (Corporate, Guest, DMZ, Admin), fixes the firewall, re-tests and compares. Expected
last line: `RESULT: 49 passed · 0 failed`. It creates the account `auditor`; its password is saved in
`lab/.office-admin` (not part of the repository).

### Stop, start, reset

| Action | How | Keeps the audits? |
|---|---|---|
| Stop | Docker Desktop → *segcheck-office* → Stop, or `docker compose -f lab/docker/docker-compose.yml stop` | Yes. Port 5091 closes. |
| Start again | **Start lab (keep audits)** (opens the browser), or Docker Desktop → Start, or `… start` | Yes. The firewall starts **with** the loophole again. |
| Reset | The Reset button, or `down` + `up -d --build` | **No.** Fresh, empty SegCheck. |
| Remove completely | `docker compose -f lab/docker/docker-compose.yml down` (and delete the `segcheck-office-*` images if you like) | No |

---

## 7. Files

```
lab/
├── README.md                                this file
├── Start lab (keep audits).cmd              double-click: start the lab, open SegCheck in the browser, notify
├── Reset lab (fresh, with loophole).cmd     double-click: rebuild the whole lab from scratch (with the loophole)
├── Firewall - fix loophole.cmd              double-click: remove legacy-reporting from the running firewall
├── Firewall - add loophole.cmd              double-click: put it back
├── paysecure-access-matrix.csv              the company's access matrix, for Step 4 → My own rules
├── firewall-rules.txt                       created by Reset: copy of the firewall's rules for Step 3 (not in git)
├── tools/                                   what the double-click files run
│   ├── start-lab.ps1                        start without wiping, then open the browser and notify
│   ├── reset-demo.ps1                       remove the old lab, build, start, save firewall-rules.txt, open and notify
│   ├── firewall.ps1                         fixed | office | status for the running firewall
│   └── lab-common.ps1                       shared: wait for SegCheck, pick setup or sign-in page, notification
└── docker/                                  everything Docker builds and runs
    ├── docker-compose.yml                   the plan: 7 networks, 7 containers, addresses, ports, start-up
    ├── auditor/                             SegCheck inside the lab
    │   ├── Dockerfile                       image recipe: Python + SegCheck's code from this repository
    │   └── entry.sh                         start-up: route each department through the firewall, start SegCheck
    ├── firewall/                            the company's core firewall
    │   ├── Dockerfile                       image recipe: Alpine + iptables + ulogd + syslog
    │   ├── start.sh                         start-up: syslog forwarding, load rules, start ulogd
    │   ├── rules.sh                         the company policy (+ legacy-reporting in office mode)
    │   └── ulogd.conf                       turns firewall decisions into syslog lines
    └── systems/                             the five business systems (card DB, payment API, HR DB, web, file server)
        ├── Dockerfile                       one image recipe, reused for all five
        └── services.py                      opens the listed ports and answers connections
```

The Docker project is named `segcheck-office`, so Docker Desktop shows one group *segcheck-office* with seven
containers, and seven images named `segcheck-office-<machine>`.

---

## 8. Questions

| Question | Answer |
|---|---|
| Is the firewall real? | Yes: Linux iptables, the same engine used on real servers and routers. pfSense cannot run in Docker (it is FreeBSD), so this plays its role; SegCheck reads pfSense logs and its `config.xml` rule export the same way. A VirtualBox pfSense lab is in [docs/VIRTUALBOX_LAB.md](../docs/VIRTUALBOX_LAB.md). |
| Why is there a mistake in the firewall? | So the demo shows SegCheck finding something real, naming the rule, and proving the fix. |
| Why does SegCheck run inside Docker here? | The lab's networks exist only inside Docker. The auditor container is the way to stand inside them, the way an auditor sits at a PC in each department. At a real client you run SegCheck on a real PC instead (double-click `SegCheck.exe`). |
| Why are guest, corporate and admin empty? | Nothing there needs to answer; they are where tests start. The auditor is the PC in each of them. |
| Where are SegCheck's data and the firewall logs kept? | Inside the auditor container (`/home/segcheck/data`). The firewall forwards each log line as it happens; it does not need to store them. |
| Can other PCs on my network reach the lab? | No. Port 5091 is bound to `127.0.0.1` only, and the lab networks are internal to Docker. |

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| Reset says Docker is not running | Start Docker Desktop, wait for *Engine running*, try again. |
| http://127.0.0.1:5091 does not open | All 7 containers must be running: Docker Desktop → *segcheck-office*, or `docker compose -f lab/docker/docker-compose.yml ps`. Otherwise Reset. |
| The hole is not found | The firewall is in fixed mode: *Firewall - add loophole*. |
| Step 3 never shows *Logs arriving* | Run any audit once; the firewall logs every attempt and SegCheck learns its address. |
| `e2e_office.py` fails at sign-in | An account already exists. Reset, then run it first. |
| Signed out suddenly | The auditor container restarted; sign in again (data is kept until the next Reset). |
| `exec ... no such file or directory` in the auditor or firewall log | A `.sh` file got Windows line endings. The repository stores them with Unix endings (`.gitattributes`); re-checkout or convert, then Reset. |
