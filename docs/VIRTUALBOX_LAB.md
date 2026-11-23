# SegCheck manual lab test guide (VirtualBox: Guest · pfSense · CDE)

This is the final, human acceptance test. Everything else (514+ automated tests, 94-check
end-to-end run, all 8 packs, and the containerised firewall lab) is already verified on
Windows and Linux. This test proves what only your real lab can: **pfSense** enforcing the
boundary and its **real filterlog** messages reaching SegCheck, with SegCheck running on **Kali**.

Tick each step and write the actual result next to the expected one.

---

## 0. What you need

| VM | Network adapter(s) | Address | RAM |
|---|---|---|---|
| SegCheck-pfSense | NIC1 NAT (WAN) · NIC2 Host-only (optional admin) · NIC3 intnet `SegCheck-Guest` · NIC4 intnet `SegCheck-CDE` | Guest IF **10.20.0.1/24**, CDE IF **10.30.0.1/24** | 1 GB is enough |
| SegCheck-Guest (Kali) | intnet `SegCheck-Guest` | **10.20.0.100/24**, gw 10.20.0.1 | 2 GB |
| SegCheck-CDE-Server | intnet `SegCheck-CDE` | **10.30.0.10/24**, gw 10.30.0.1 | 1 GB |

Your PC has ~8 GB free, so lower RAM first (VM powered off):

```bash
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SegCheck-Guest" --memory 2048
```
```bash
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SegCheck-CDE-Server" --memory 1024
```
```bash
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SegCheck-pfSense" --memory 1024
```

Start order: **pfSense → CDE server → Guest**.

## 1. CDE server: services to test against

On the CDE VM (any Debian/Kali), run these in separate terminals (or with `&`):

```bash
python3 -m http.server 8080
```
```bash
sudo apt install -y openssh-server && sudo systemctl start ssh
```
```bash
sudo apt install -y dnsmasq && sudo systemctl start dnsmasq
```

Expected: `ss -tulpn` shows listeners on TCP 8080, TCP 22 and UDP 53.

## 2. pfSense: rules and remote logging

1. **Status → System Logs → Settings → Remote Logging Options**: enable, server **10.20.0.100:5514**, contents **Firewall Events**. Save.
2. **Firewall → Rules → GUEST**: you'll switch between two states:
   - **Open state (Act 1):** a *pass* rule, source GUEST net → destination CDE net, any protocol, **Log** ticked.
   - **Deny state (Act 2):** a *block* rule, source GUEST net → destination CDE net, any protocol, **Log** ticked, placed above any pass rule.
3. Keep the GUEST rule that lets 10.20.0.100 reach the internet only if you need it for `apt`; it does not affect the test.

## 3. Guest (Kali): start SegCheck

```bash
cd /media/sf_SegCheckProject
```
```bash
/home/kali/.venvs/segcheck/bin/python start_segcheck.py
```

(If that environment doesn't exist and the VM has internet once: `python3 start_segcheck.py`.)
Run as the normal `kali` user, **not root**. The browser opens http://127.0.0.1:5000. Sign in
(or create the first admin on `/setup` with the token printed in the terminal).

| Check | Expected |
|---|---|
| Top bar | "Start with Step 1" (first time) or "Testing from 10.20.0.100" |

## 4. New audit: Step 1 to Step 3

1. **Step 1 · Where you are:** SegCheck lists `eth0 · 10.20.0.100 · 10.20.0.0/24 · gateway 10.20.0.1` and
   picks it. Name `Guest`, kind **Guest or visitor Wi-Fi** → **Use this network**.
2. **Step 2 · What to test:** one row: name `CDE`, network `10.30.0.0/24`, kind **Card data environment
   (CDE)**, hosts `10.30.0.10` → **Add these networks**.
3. **Step 3 · Firewall:** *There is a firewall*, **pfSense or OPNsense**, address `10.20.0.1` (pre-filled
   from the gateway), *Connect its logs* ticked → **Save firewall choice**. The page shows the port (5514 unless it
   is taken) and the exact pfSense settings with `10.20.0.100:5514` filled in.

| Check | Expected |
|---|---|
| Steps 1–3 | Ticked in the progress bar |
| Step 3 status | "Listening, waiting for the first log" → after any blocked/passed packet, **"Logs arriving"** with a rising count and *Learned the firewall's address from its logs: 10.20.0.1* |

If it keeps waiting: the numbered advice under the status tells you what to check (pfSense remote logging
target 10.20.0.100:5514, the rule's **Log** box, Windows/Kali firewall).

## 5. Act 1: firewall OPEN (prove SegCheck catches a broken boundary)

1. pfSense: enable the **pass** rule (open state). Apply.
2. **Step 4:** standard **PCI DSS · CDE isolation from out-of-scope networks**, all probes (25 attempts),
   **Launch audit**.

| Check | Expected |
|---|---|
| Live page | Lanes fill; 22, 8080 and DNS 53 show *reachable*; ping *reachable* |
| Report executive summary | **ACTION REQUIRED · Segmentation violation**, "treat 'guest' as connected to the CDE… in scope" |
| Results | Remote admin, web, infra UDP and ICMP checks **FAIL** (database FAILs only if you run PostgreSQL) |
| Heatmap | Red FAIL cells on 10.30.0.10 |
| Boundary cross-check | **Passed firewall** > 0 (pfSense logged `pass`) |
| PDF | Downloads; first page shows ACTION REQUIRED |

## 6. Act 2: firewall DENY (prove the fix)

1. pfSense: disable the pass rule, enable the **block** rule (with Log). Apply.
2. **Step 4:** same standard → **Launch audit** again.

| Check | Expected |
|---|---|
| Results | **All Passed: blocked, proven by firewall log** (silence alone is never a pass; the logged block proves it) |
| Executive summary | **DENY ENFORCED · Deny enforced and corroborated by firewall logs** |
| Boundary cross-check | **Block confirmed = 25** (or close: see note) |
| Control matrix | PCI DSS 11.4.5 / 1.3.1 → **Supported** |
| History | Both audits listed: FAILED (Act 1), PASSED (Act 2) |

Note: pfSense must log every blocked packet. If a few attempts show "no log match", check the rule's Log
box and that the GUEST interface's default block rule isn't catching them unlogged.

## 7. Extras (optional)

- **Untrusted standard:** Step 4 → *Untrusted/DMZ networks to CDE*: same expectations.
- **Firewall management plane:** Step 4 → *ISO 27002 8.20*: probes 10.20.0.1 on 22/80/443/161, plus the
  firewall's other addresses if you list them in Step 3a (*Its addresses in the other networks*). If the pfSense
  web GUI is reachable from GUEST on any of them, it reports **FAIL**: a real finding.
- **Probe choice:** untick everything but *Databases* and watch the attempt count change before launch.
- **Cancellation:** launch and press *Cancel remaining attempts*: the run stops, no report is saved.

## 8. Record the outcome

Add your results to [VERIFICATION.md](VERIFICATION.md) under a "Manual VM lab acceptance" heading: date,
Act 1 and Act 2 outcomes, the report numbers, and any deviations. Keep the PDFs from both acts
as evidence.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Step 4 "Not ready yet: … Declare the boundary…" | Save firewall choice (firewall or *No firewall*) |
| Step 1 "… is not an address of this PC" | Kali's IP isn't 10.20.0.100; fix the VM's address or pick the detected network |
| Step 3 "UDP port 5514 is already used…" | Save firewall choice again: SegCheck picks the next free port; set that port in pfSense |
| Everything *No answer* in Act 1 | The pass rule isn't applied, or CDE services aren't listening (`ss -tulpn`) |
