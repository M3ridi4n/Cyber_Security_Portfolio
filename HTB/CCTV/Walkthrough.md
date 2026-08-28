# HTB CCTV: Walkthrough

## Machine Info

| Field | Detail |
|-------|--------|
| Platform | Hack The Box |
| Machine | CCTV |
| Difficulty | Medium |
| OS | Linux |
| IP | 10.129.X.X |
| Status | Retired |
| CVEs exploited | CVE-2024-51482 (ZoneMinder SQL injection), CVE-2025-60787 (motionEye OS command injection) |

---

## Summary

CCTV is a five-step chain that begins with a factory-default password on the ZoneMinder surveillance console and ends with an authenticated RCE against a second, internal surveillance application (motionEye) running as root. The initial access is trivial (default `admin:admin` credentials); a SQL injection then dumps password hashes for host users. The bcrypt hash for user `mark` cracks in seconds against rockyou.txt, granting SSH access. Local enumeration reveals motionEye on `127.0.0.1:8765` with its admin credentials sitting in a readable configuration file. Tunnelling to the internal port and exploiting the motionEye RCE yields a root shell.

The through-line worth noting: no advanced technique required anywhere. Every step exploits either a known CVE in an outdated version or a basic credential-hygiene failure. The lesson is that surveillance and IoT platforms in particular tend to accumulate these failures because they are treated as appliances rather than software.

---

## Step 1: Reconnaissance

**Objective:** identify open services and enumerate the attack surface.

```bash
export IP=10.129.X.X
nmap -sV -sC -p- $IP -oN HTB_CCTV_Initial_Scan
```

Key results:

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH |
| 80/tcp | HTTP | ZoneMinder web console at `/zm/` |

Directory enumeration with ffuf against the web root revealed the ZoneMinder application at `/zm/` with a standard login form.

**What this told me:**
- ZoneMinder is a well-known open-source video-surveillance platform. Two immediate things to check: default credentials (common on surveillance software because operators often deploy without changing them), and version fingerprinting (ZoneMinder has had several critical CVEs over the years). Version identification would come from the console footer once inside.

**Screenshot:** Figure 1

![Figure1](/HTB/CCTV/images/02-InitialScan.png)

---

## Step 2: Initial Access via Default Credentials

**Objective:** attempt default credentials on the ZoneMinder console.

```
URL: http://cctv.htb/zm/
Username: admin
Password: admin
```

Login succeeded on the first attempt. Full administrative access to the ZoneMinder console was granted.

**What this told me:**
- Factory defaults on a public-facing security-monitoring platform is a Critical-severity finding in itself. On a real engagement this alone would trigger an immediate report. On a CTF, it was the foothold into the application layer, and the next question was what the console version allowed me to do beyond just browsing camera feeds.

Inspection of the console footer identified the version as **ZoneMinder 1.37.63**. A CVE search returned CVE-2024-51482: an authenticated SQL injection in the `removetag` action.

Additionally, inspection of the client-side JavaScript disclosed embedded credentials: a telemetry endpoint URL containing authentication tokens and the raw `ZM_DB_USER` and `ZM_DB_PASS` values used to connect to the ZoneMinder database. Both were noted for later use.

**Screenshot:** Figure 2

![](/HTB/CCTV/images/05-ZMInitialAccess.png)

---

## Step 3: SQL Injection to Recover Password Hashes

**Objective:** exploit CVE-2024-51482 to dump the ZoneMinder user table.

The vulnerability: the `tid` parameter passed to the `removetag` action is not sanitised before use in a SQL query, allowing boolean-based blind injection. With an authenticated session (trivially obtained via default credentials), the injection could extract arbitrary data from the database.

A public PoC script targeting CVE-2024-51482 was used to enumerate the `Users` table via boolean queries, recovering usernames and their bcrypt password hashes for three accounts: `superadmin`, `mark`, and `admin`.

**What this told me:**
- Three bcrypt hashes to work with. `superadmin` and `admin` were likely application-only accounts, but `mark` matched the naming pattern of a real system user, which meant that if the password hash could be cracked, it might grant SSH access to the host. This is the standard hash-recovery-to-credential-reuse pipeline; the question was whether `mark`'s password was weak enough to crack in a reasonable time.

**Screenshot:** Figure 3

![](/HTB/CCTV/images/08-CVE-2024-51482_ZM_User_Hashes.png)

---

## Step 4: Cracking mark's Hash and SSH Access

**Objective:** crack the bcrypt hash for `mark` and attempt SSH.

```bash
# Isolate mark's hash into a file
echo '$2y$10$...' > mark.hash

# Run hashcat with rockyou.txt against bcrypt mode 3200
hashcat -m 3200 -a 0 mark.hash /usr/share/wordlists/rockyou.txt
```

The hash cracked in approximately 37 seconds. The recovered password was a common dictionary word.

```bash
ssh mark@cctv.htb
# password: [REDACTED]
```

Shell as `mark`. User flag captured from `/home/mark/user.txt`.

**What this told me:**
- Bcrypt is a deliberately slow hash, and rockyou is a large wordlist, so a 37-second crack means the password was in the first 2,000 or so entries of the list. That is a genuinely weak password: not just found in rockyou, but near the top of it. On a real engagement this is a finding in its own right, because it indicates the user chose a password that would fall to any credential-stuffing attack. The password was also going to be my ticket to whatever came next; credential reuse across services is another pattern to test.

**Screenshot:** Figure 4

![](/HTB/CCTV/images/09-HashesCracked.png)

---

## Step 5: Internal Enumeration

**Objective:** identify a path from `mark` to root.

Standard local enumeration on the host:

```bash
sudo -l
# Sorry, user mark may not run sudo on cctv.

find / -perm -u=s -type f 2>/dev/null
# Nothing unusual
```

Neither returned anything interesting. Moving to network enumeration:

```bash
ss -tlnp
```

The output revealed several loopback-only services, including one on `127.0.0.1:8765`. Fingerprinting via `curl` identified it as **motionEye v0.43.1b4**, a second surveillance platform running internally.

A CVE search on motionEye returned CVE-2025-60787: an authenticated OS command injection in the config-management functions. The exploit required admin access to motionEye.

Searching for motionEye's configuration on the host:

```bash
find / -name "motion.conf" 2>/dev/null
# /etc/motioneye/motion.conf
```

The configuration file was readable to any local user and contained the admin credentials in commented plaintext:

```
# admin_username: admin
# admin_password: [REDACTED_SHA1_HASH_STRING]
```

Notably, the admin_password value was a SHA1 hash string used verbatim as a plaintext password (not a hash of a password). Reading it from the config file was all that was needed to authenticate.

**What this told me:**
- Three things came together here. First, motionEye was only reachable on loopback, so I would need to tunnel to it via SSH. Second, the admin credentials were readable to my current user in a config file, so no cracking was needed. Third, motionEye was running as root (visible via `ps`), which meant the RCE would land me a root shell directly, not just a compromise of another user.

---

## Step 6: SSH Tunnel and motionEye RCE

**Objective:** tunnel to the internal motionEye instance and exploit CVE-2025-60787 for root.

SSH port forward from Kali to the target's loopback:

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

This mapped Kali's local port 8765 to the target's `127.0.0.1:8765`, making motionEye reachable at `http://localhost:8765/` on the Kali side.

Authentication with the admin credentials from `motion.conf` succeeded. CVE-2025-60787 exploitation involved submitting a config-management request whose parameters injected shell metacharacters into a command that motionEye executed with `os.system()`. Because motionEye ran as root, the injected commands ran as root.

The exploit payload delivered a reverse shell:

```bash
nc -lvnp 4444
# then trigger the config injection via authenticated web request
```

Callback:

```
connect to [ATTACKER_IP] from (UNKNOWN) [10.129.X.X] [PORT]
root@cctv:/etc/motioneye#
```

Root flag captured from `/root/root.txt`.

**What this told me:**
- The internal-only binding of motionEye was security theatre: it was designed to prevent external attack but did nothing to stop a local user who already had shell access. The real problem was the combination of the RCE flaw plus running as root. Either fix independently would have blunted the impact: patch motionEye and the RCE is closed; run it as a dedicated non-privileged user and the RCE gets you into that user's context, not root. Both failing together is what made this a single-step escalation.

**Screenshot:** Figure 5

![](/HTB/CCTV/images/17-Root&UserFlag.png)

---

## Flags

| Flag | Method | Status |
|------|--------|--------|
| User | SSH as `mark` after cracking bcrypt hash recovered via SQL injection | [REDACTED] |
| Root | Authenticated motionEye RCE (CVE-2025-60787) via SSH tunnel; service ran as root | [REDACTED] |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| ffuf | Directory enumeration |
| curl | API interaction and version fingerprinting |
| CVE-2024-51482 PoC | SQL injection exploitation |
| hashcat | Offline bcrypt hash cracking |
| ssh (with `-L`) | Interactive access and port forwarding |
| CVE-2025-60787 PoC | motionEye RCE exploitation |
| netcat (nc) | Reverse shell listener |
| ss | Internal service enumeration |

---

## Lessons Learned

1. **Default credentials on a surveillance platform is a Critical finding.** ZoneMinder accepted `admin:admin` on the first try. That would be embarrassing on any deployed system, but it is particularly serious on a security-monitoring platform, because the software's purpose is to enforce security. When the surveillance is the compromise, the entire monitoring posture is inverted.
2. **Read the client-side source.** ZoneMinder's JavaScript disclosed telemetry credentials and database credentials in plaintext. Not through some clever attack, just by viewing the page source. Any web application should be treated as a source of credential leaks in its client-side code, because operators frequently embed secrets there and forget they are world-readable.
3. **Loopback binding is a hardening measure, not a security control.** motionEye was only reachable on `127.0.0.1:8765`, which prevents external attack. But once I had shell access as any local user, the loopback restriction did nothing. Combined with the service running as root, this was a straight-line path from a low-privilege user to root. Loopback binding is worth doing, but it should be one layer of a defence-in-depth model, not the only barrier.

---

## References

| Resource | URL |
|----------|-----|
| CVE-2024-51482 (ZoneMinder SQL injection) | https://nvd.nist.gov/vuln/detail/CVE-2024-51482 |
| CVE-2025-60787 (motionEye OS command injection) | https://nvd.nist.gov/vuln/detail/CVE-2025-60787 |
| hashcat modes reference | https://hashcat.net/wiki/doku.php?id=example_hashes |
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |

---

*This walkthrough documents a retired Hack The Box machine completed in an authorised lab environment for educational purposes. Flags are redacted. No unauthorised systems were accessed.*
