# Penetration Test Report: HTB CCTV

<!--
  Built to the v4 template standard.
  METADATA CONVENTIONS:
   - Dates: ISO 8601 (YYYY-MM-DD).
   - HTB IP addresses: obfuscated as 10.129.XX.XX.
   - Template version identifies the schema; Report version identifies this document's revision state.
  WRITING STYLE: no em-dashes anywhere. Colons introduce; commas or brackets for asides; semicolons join; "to" for ranges; "n/a" in empty cells.
-->

## Document Control

| Field | Detail |
|-------|--------|
| Report title | Penetration Test Report: HTB CCTV |
| Template version | v4 |
| Report version | 2.0 |
| Author | David Lumsden |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-05-XX |
| Classification | Confidential / Training Documentation |
| Distribution | Portfolio (public) |
| Redaction policy | Flags withheld. HTB IPs obfuscated as 10.129.XX.XX. Captured secrets, hashes, and passwords redacted in body. |

### Version history

| Report version | Date | Author | Notes |
|----------------|------|--------|-------|
| 1.0 | 2026-05-XX | David Lumsden | Initial v2 conversion |
| 1.1 | 2026-06-XX | David Lumsden | Re-stamped to v3 standard; em-dashes removed |
| 2.0 | 2026-05-XX | David Lumsden | Migrated to v4 template; Classification field corrected; metadata standardised |

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

An attacker with no prior access could take complete control of the organisation's video-surveillance platform and, from there, the server hosting it. The surveillance console was left protected only by its factory-default password; once inside, an attacker could read every camera feed and recover stored credentials. Reused and weakly protected passwords then granted direct access to the server, and a second surveillance application (running with the highest level of system privilege) was abused to obtain unrestricted administrative ("root") control.

No advanced skill or custom tooling was required at any stage. Every weakness exploited was either a known, patchable software flaw or a basic configuration failure: a default password, secrets left in plain view, two missing updates, and poor password practices, chained into an unbroken path from the public internet to full control of the surveillance estate.

Overall risk rating: CRITICAL

### Findings at a glance

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 3 |
| Medium | 2 |
| Low | 0 |
| Informational | 0 |

Most urgent action: patch both surveillance applications and replace all default and weak passwords immediately.

### Attack path summary

```
External recon
    |
    v
ZoneMinder default credentials (admin:admin) -> full admin access
    |
    v
CVE-2024-51482 (SQL injection) -> database dump including bcrypt hashes
    |
    v
Offline hash crack -> mark:opensesame -> SSH foothold  (USER FLAG)
    |
    v
Internal enumeration -> motionEye on 127.0.0.1:8765
    |
    v
Config file read -> admin credential for motionEye
    |
    v
SSH tunnel + CVE-2025-60787 (motionEye RCE) -> root shell  (ROOT FLAG)
```

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | 10.129.XX.XX (cctv.htb) and all open services |
| Out of scope | HTB infrastructure, other platform users |
| Authorisation | Hack The Box; machine assigned to tester account |
| Testing type | Black-box (no prior credentials or source) |
| Testing window | Single session, 2026-05-XX |
| Constraints | No denial-of-service testing |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to NIST SP 800-115 and the OWASP Web Security Testing Guide, across reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting.

Risk rating model: base severity uses CVSS v3.1 (vector per finding), labelled strictly by band (Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9). A contextual Risk rating is derived from Likelihood multiplied by Business Impact. Note F-03 (motionEye RCE): its CVSS base is High because it requires administrative authentication, but its operational Risk is Critical because it yields root. The overall engagement risk is Critical, driven by the end-to-end chain from default credentials to full root compromise.

---

## 4. Attack Narrative

### Phase 1: Reconnaissance
An `nmap -sC -sV` scan identified a web service hosting ZoneMinder at `http://cctv.htb/zm/` (Figure 1). Directory enumeration with `ffuf` mapped the application surface.

### Phase 2: Initial Access (ZoneMinder)
The ZoneMinder console accepted the factory-default credentials `admin:admin`, granting full administrative access (Figure 2). Inspection of the client-side JavaScript additionally exposed embedded service credentials: a telemetry endpoint and database credentials (values redacted).

### Phase 3: Database Compromise (SQL Injection)
The console version (1.37.63) was vulnerable to boolean-based SQL injection (CVE-2024-51482) via the `removetag` action's `tid` parameter. Exploitation dumped the user table, yielding bcrypt password hashes for `superadmin`, `mark`, and `admin` (hashes redacted, Figure 3).

### Phase 4: Foothold (SSH as mark)
The hash for `mark` was a common dictionary word, cracked offline in seconds against a standard wordlist. The recovered password granted SSH access as `mark` (Figure 4).

### Phase 5: Privilege Escalation (motionEye RCE)
Local enumeration (`ss -tlnp`) revealed a second surveillance application, motionEye, listening on `127.0.0.1:8765`, and a readable configuration file (`/etc/motioneye/motion.conf`) disclosing the admin credential (value redacted). After tunnelling to the internal port over SSH, motionEye (v0.43.1b4) was exploited via OS command injection (CVE-2025-60787). Because the service ran as root, this yielded a root shell and full system compromise (Figure 5).

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Default credentials grant full ZoneMinder admin | Critical | 9.8 | Critical | n/a |
| F-02 | SQL injection in ZoneMinder | Critical | 9.8 | Critical | CVE-2024-51482 |
| F-03 | Authenticated OS command injection in motionEye (root) | High | 7.2 | Critical | CVE-2025-60787 |
| F-04 | Service and database credentials in client-side source | High | 7.5 | High | n/a |
| F-05 | Weak, crackable SSH password | High | 7.5 | High | n/a |
| F-06 | Admin credential readable in configuration file | Medium | 6.0 | Medium | n/a |
| F-07 | SHA1 hash string used directly as a password | Medium | 5.4 | Medium | n/a |

---

## 6. Detailed Findings

### F-01: Default Credentials Grant Full ZoneMinder Admin

| Field | Detail |
|-------|--------|
| Severity | Critical (reconciled from the original High/7.5: unauthenticated network access yielding full admin scores 9.8) |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 |
| Likelihood | High |
| Business impact | High |
| Risk | Critical |
| CVE | n/a |
| Affected asset | ZoneMinder console (`/zm/`) |
| Authentication required | None |
| MITRE ATT&CK | T1078 (Valid Accounts) |

Description: the ZoneMinder console accepted the default credentials `admin:admin`, granting unrestricted administrative access to camera feeds, user management, and system configuration.

Evidence: successful login with `admin:admin` (Figure 2).

Business impact: complete control of the surveillance platform and the foothold enabling every subsequent finding.

Remediation: force a credential change on first login; enforce a strong password policy (minimum 14 characters, complexity); implement MFA for administrative accounts.

References: OWASP A07:2021 (Identification and Authentication Failures).

---

### F-02: SQL Injection in ZoneMinder

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 to 9.8 [verify on NVD] |
| Likelihood | High (authentication trivially met via F-01) |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2024-51482 |
| Affected asset | ZoneMinder 1.37.63, `removetag` action, `tid` parameter |
| Authentication required | User (trivially met via default credentials) |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |

Description: the `tid` parameter is passed unsanitised into a SQL query, enabling boolean-based blind injection and extraction of arbitrary database contents, including the full user table and password hashes.

Evidence: exploitation dumped bcrypt hashes for `superadmin`, `mark`, and `admin` (hashes redacted, Figure 3).

Business impact: full database compromise; all user credentials exposed and crackable offline.

Remediation: upgrade ZoneMinder to a patched release (1.37.65 or later); enforce parameterised queries; validate and sanitise all user-supplied input.

References: CVE-2024-51482 (NVD).

---

### F-03: Authenticated OS Command Injection in motionEye (Root)

| Field | Detail |
|-------|--------|
| Severity | High (reconciled from the original Critical/7.2: admin authentication is required, which caps the base score in the High band; see Risk) |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 7.2 [verify on NVD; advisory may apply S:C, raising the score] |
| Likelihood | Medium (requires admin auth, obtained via earlier findings) |
| Business impact | High |
| Risk | Critical (yields full root control) |
| CVE | CVE-2025-60787 |
| Affected asset | motionEye v0.43.1b4 (`127.0.0.1:8765`) |
| Authentication required | Admin |
| MITRE ATT&CK | T1190, T1068 (Exploitation for Privilege Escalation) |

Description: user-supplied configuration values are written to Motion config files and interpreted as shell-expandable strings when the Motion process restarts, permitting arbitrary command execution. The service runs as root, so successful exploitation yields root control.

Evidence: an authenticated request to the internal motionEye instance via SSH tunnel returned a root shell (`root@cctv:/etc/motioneye#`) (Figure 5).

Business impact: complete system compromise: full access to all data, credentials, camera feeds, and the ability to pivot into connected networks.

Remediation: upgrade motionEye to a patched release (0.43.1b5 or later); sanitise all user input before writing to config; run the service as a dedicated non-privileged account; restrict administrative access to trusted networks.

References: CVE-2025-60787 (NVD).

---

### F-04: Service and Database Credentials in Client-Side Source

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 |
| Likelihood | High |
| Business impact | Medium |
| Risk | High |
| CVE | n/a |
| Affected asset | ZoneMinder client-side JavaScript / API config |
| Authentication required | None |
| MITRE ATT&CK | T1552.001 (Credentials in Files) |

Description: telemetry and database credentials were embedded in plaintext within client-side code (a telemetry endpoint URL containing credentials, and the `ZM_DB_USER` / `ZM_DB_PASS` values), retrievable by anyone able to view the page source.

Evidence: telemetry endpoint and database credentials present in page source (all values redacted).

Business impact: exposed secrets enable lateral movement and direct database access.

Remediation: never embed credentials in client-side code; hold configuration server-side; use a secrets-management solution and rotate the exposed values.

References: OWASP A05:2021 (Security Misconfiguration).

---

### F-05: Weak, Crackable SSH Password

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 7.5 |
| Likelihood | Medium (requires hash recovery via F-02, then offline crack) |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | User account `mark` (SSH) |
| Authentication required | None (offline crack) |
| MITRE ATT&CK | T1110.002 (Password Cracking) |

Description: the bcrypt hash for `mark` was a common dictionary word, cracked within seconds against a standard wordlist (recovered within the first approximately 2,300 entries), granting SSH access and a foothold on the host.

Evidence: hash cracked in approximately 37 seconds; recovered password is a single dictionary word (value redacted, Figure 4).

Business impact: interactive shell access on the host, enabling enumeration and privilege escalation.

Remediation: enforce a strong password policy and account lockout; deploy a password manager; prefer SSH key-based authentication and disable password authentication where possible.

References: OWASP A07:2021.

---

### F-06: Admin Credential Readable in Configuration File

| Field | Detail |
|-------|--------|
| Severity | Medium (reconciled from the original High: CVSS 6.0 falls in the Medium band) |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.0 |
| Likelihood | High (file was readable by the foothold user) |
| Business impact | Medium |
| Risk | Medium |
| CVE | n/a |
| Affected asset | `/etc/motioneye/motion.conf` |
| Authentication required | User (`mark`) |
| MITRE ATT&CK | T1552.001 |

Description: the motionEye configuration file was readable by a low-privilege user and contained the admin username and credential in commented plaintext, directly enabling F-03.

Evidence: `motion.conf` exposed the `admin_username` and `admin_password` values (redacted).

Business impact: provided the credential needed to reach root via F-03.

Remediation: restrict configuration file permissions to the service account only; remove credential comments; use dedicated secrets management.

References: OWASP A05:2021.

---

### F-07: SHA1 Hash String Used Directly as a Password

| Field | Detail |
|-------|--------|
| Severity | Medium |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 5.4 |
| Likelihood | Medium |
| Business impact | Medium |
| Risk | Medium |
| CVE | n/a |
| Affected asset | motionEye admin account |
| Authentication required | None (value obtained via F-06) |
| MITRE ATT&CK | T1078 |

Description: the motionEye admin password was a SHA1 hash string used verbatim as a plaintext password. Once read from the config file, authentication was possible without any cracking: poor password hygiene that removed the final barrier to F-03.

Evidence: direct authentication to motionEye using the hash string as the password (value redacted).

Business impact: eliminated any cracking barrier between the config-file read (F-06) and root RCE (F-03).

Remediation: use strong, randomly generated passwords unrelated to hash values; deploy a password manager.

References: OWASP A07:2021.

---

## 7. Strategic Recommendations (Root-Cause Themes)

1. No credential-management standard. Default passwords, secrets in source, secrets in config files, and a hash-as-password all stem from the absence of a secrets-management discipline. Implement a vault-based secrets standard and mandatory credential rotation.
2. Unpatched, internet-reachable applications. Both exploited CVEs were patchable. Establish a vulnerability-management cycle with defined patch SLAs for internet-facing software.
3. Excessive service privilege. motionEye running as root turned an application bug into full host compromise. Apply a least-privilege baseline so no service runs as root without documented justification.

---

## 8. Remediation Roadmap

### Immediate (Critical priority)
1. Patch motionEye (CVE-2025-60787) and ZoneMinder (CVE-2024-51482).
2. Replace all default and weak passwords; rotate every exposed credential.

### Short-term (High priority)
3. Remove credentials from client-side code and configuration files; restrict config permissions.
4. Run motionEye and ZoneMinder as dedicated non-privileged accounts.

### Medium-term
5. Enforce a password policy with MFA; deploy secrets management.
6. Establish a patch-management cycle and restrict administrative interfaces to trusted networks; add runtime detection for anomalous process activity.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | SSH as `mark` after offline hash crack | `/home/mark/user.txt` -> [REDACTED] |
| Root | motionEye RCE (CVE-2025-60787) via SSH tunnel | `/root/root.txt` -> [REDACTED] |

---

## 10. Retest and Validation

Recommend retest within 30 days of remediation to confirm both CVEs are patched, default and weak credentials are eliminated, secrets are removed from source and config, and services no longer run as root.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | n/a | Port and service enumeration |
| ffuf | n/a | Directory enumeration |
| curl | n/a | API interaction and cookie handling |
| CVE-2024-51482 PoC / sqlmap | n/a | SQL injection exploitation |
| hashcat, john | n/a | Offline hash cracking |
| CVE-2025-60787 PoC | n/a | motionEye RCE |
| netcat (nc) | n/a | Reverse-shell listener |
| ss | n/a | Internal service discovery |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| CVE-2024-51482 | https://nvd.nist.gov/vuln/detail/CVE-2024-51482 |
| CVE-2025-60787 | https://nvd.nist.gov/vuln/detail/CVE-2025-60787 |
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |
| MITRE ATT&CK | https://attack.mitre.org/ |

---

*Produced for educational purposes within the Hack The Box authorised training environment. All testing was conducted legally on assigned infrastructure.*
