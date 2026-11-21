# SegCheck office lab (Docker)

A six-department company network you can run on any PC with Docker Desktop. It uses real routing and a
real Linux firewall, so SegCheck's results come from real packets. pfSense itself cannot run in Docker
(it is FreeBSD), so an iptables router plays its role: it forwards or drops between departments and
sends every decision to SegCheck by syslog. The VirtualBox pfSense lab stays the final manual test
([LAB_TEST_GUIDE.md](LAB_TEST_GUIDE.md)).

```bash
cd lab/office
```
```bash
docker compose up -d --build
```
SegCheck UI: http://127.0.0.1:5091 (setup token `office-setup-token-change-me-0123456789abcdef`, lab only).

| Department | Subnet | Systems |
|---|---|---|
| Guest Wi-Fi | 10.20.0.0/24 | — |
| Corporate staff | 10.40.0.0/24 | — |
| HR | 10.50.0.0/24 | HR database 10.50.0.10 (5432, 445) |
| DMZ | 10.60.0.0/24 | Public website 10.60.0.10 (80, 443) |
| Internal servers | 10.70.0.0/24 | File/LDAP/intranet 10.70.0.10 (445, 389, 8080, DNS 53) |
| CDE | 10.30.0.0/24 | Payment API 10.30.0.10 (8443, 22) · Card database 10.30.0.20 (5432) |

The core firewall (`lab/office/firewall/rules.sh`) enforces the company rules: staff → website and
internal servers, HR → internal servers, DMZ checkout → payment API, everything else dropped and logged.
In `office` mode it also contains a **legacy reporting rule** (Corporate → card database 5432): the hole
SegCheck must find. `rules.sh fixed` removes it.

The `auditor` container runs SegCheck and has an address in Guest, Corporate, DMZ and CDE (policy routing
sends each through the firewall): it plays the department PCs an auditor sits at. The firewall sends its
logs to 10.40.0.100:5514.

Walk through it by hand: [HANDS_ON_GUIDE.md, Lab 3](HANDS_ON_GUIDE.md#lab-3-audit-paysecure-ltd-a-fake-company-with-a-real-firewall-docker).
Or automated (35 checks):
```bash
python scripts/e2e_office.py
```
Expected: Corporate finds the card database on 5432 (Violation, logged as passed); Guest is Enforced with
every attempt a logged block; from the DMZ checkout reaches the payment API and the card database stays
blocked; after `rules.sh fixed` the Corporate retest is Enforced.

Stop: `docker compose stop` (keeps the lab) or `docker compose down` (removes it).
