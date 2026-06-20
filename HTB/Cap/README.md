 Penetration Test Report: HTB Cap

## Document Control

| Field | Detail |
|-------|--------|
| Report title | Penetration Test Report: HTB Cap |
| Version | 1.1 |
| Author | David Lumsden |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-05-XX |
| Classification | Confidential / Training Documentation |
| Distribution | Portfolio (public) |
| Publication status | RETIRED, cleared for portfolio |
| Redaction policy | Flags withheld. Captured credentials redacted in body. |

### Version history

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-05-XX | David Lumsden | Initial v2 conversion |
| 1.1 | 2026-05-XX | David Lumsden | Re-stamped to v3 standard; em-dashes removed |

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

An attacker with no prior access could take complete control of the assessed server by chaining together several individually moderate weaknesses. A web dashboard allowed any visitor to view network-capture files belonging to other users; one such capture contained a valid set of login credentials in readable form. Because the same password had been reused for remote server access, the attacker could log in directly to the host. A final misconfiguration in a system component then allowed escalation to full administrative ("root") control.

No single weakness was catastrophic in isolation, but together they formed a reliable path from the public internet to total system compromise, requiring no specialist tooling. The overall exposure is therefore rated Critical, driven by the end-to-end attack chain rather than by any one finding.

Overall risk rating: CRITICAL (chained; see risk model)

### Findings at a glance (severities reconciled to CVSS bands in this revision)

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 3 |
| Medium | 1 |
| Informational | 0 |

Most urgent action: remove the misconfigured Linux capability from the Python binary, and enforce authorisation checks on the web dashboard.

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | 10.129.X.X (cap.htb) and all open services |
| Out of scope | HTB infrastructure, other platform users |
| Authorisation | Hack The Box; machine assigned to tester account |
| Testing type | Black-box (no prior credentials or source) |
| Testing window | Single session, May 2026 |
| Constraints | No denial-of-service testing |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to NIST SP 800-115 and the OWASP Web Security Testing Guide, across reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting.

Risk rating model: base severity uses CVSS v3.1 (vector per finding), labelled strictly by band (Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9). A contextual Risk rating is derived from Likelihood multiplied by Business Impact. Note F-03: its CVSS base is High, because the capability abuse requires local access (which caps the score), but its operational Risk is Critical, because it grants full root control. This is also why the overall engagement risk is Critical despite no individual finding scoring in the Critical band: the chain, not any single finding, achieves full compromise.

---

## 4. Attack Narrative

### Phase 1: Reconnaissance
An `nmap -sC -sV` scan identified three services: vsftpd 3.0.3 (21), OpenSSH 8.2p1 (22), and a gunicorn-hosted Python web application (80) (Figure 1).

![Figure 1: Nmap service Scan](./images/01-Nmap_Initial_Scan.png)
### Phase 2: Web Enumeration and IDOR
The web dashboard presented a "Security Snapshot" feature at `/data/{id}`, generating downloadable PCAP captures referenced by sequential integer IDs. Decrementing the identifier from the assigned value to `/data/0` returned a capture belonging to another session, with no authorisation check: an Insecure Direct Object Reference (Figure 2).

![Figure 2:](04-IDOR_Exploit.png)

### Phase 3: Credential Recovery via PCAP Analysis
The captured PCAP from `/data/0` contained a complete FTP session. Following the TCP stream in Wireshark revealed the `USER` and `PASS` exchange in cleartext, disclosing valid credentials for user `nathan` (password redacted) (Figure 3).

![Figure 3:](./images/06-PCAP_TCP_Stream(Redacted).jpg)

### Phase 4: Foothold (SSH)
The recovered FTP password had been reused for SSH. Authenticating to port 22 as `nathan` granted an interactive shell and captured user-level access.

### Phase 5: Privilege Escalation (Linux Capability Abuse)
Capability enumeration with `getcap -r /` showed `/usr/bin/python3.8` carrying `cap_setuid+eip`. This permits the binary to set its UID to 0 regardless of the calling user's privileges. Invoking `os.setuid(0)` followed by a shell yielded root and full system compromise (Figure 4).

![Figure 4:](./images/08-Get_Cap_Exploit.png)

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Insecure Direct Object Reference exposes PCAP captures | High | 7.5 | High | n/a |
| F-02 | FTP credentials transmitted in cleartext | Medium | 5.9 | High | n/a |
| F-03 | Misconfigured `cap_setuid` capability on Python (root) | High | 7.8 | Critical | n/a |
| F-04 | Password reuse across FTP and SSH | High | 7.3 | High | n/a |

---

## 6. Detailed Findings

### F-01: Insecure Direct Object Reference Exposes PCAP Captures

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | Web application, `/data/{id}` endpoint |
| Authentication required | None |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |

Description: the Security Snapshot feature references stored network captures by sequential integer ID with no server-side authorisation check, allowing any visitor to retrieve captures belonging to other users by manipulating the ID.

Evidence: requesting `/data/0` (Figure 2) returned a PCAP belonging to another session; the application performed no ownership validation.

Business impact: exposure of arbitrary users' network captures, which may contain credentials, session tokens, and confidential traffic, as demonstrated in this assessment where the capture yielded valid login credentials.

Remediation: enforce server-side authorisation verifying the requester owns the resource; use non-sequential, unpredictable identifiers (UUIDs); apply access-control lists mapping users to their own resources.

References: OWASP A01:2021 (Broken Access Control).

---

### F-02: FTP Credentials Transmitted in Cleartext

| Field | Detail |
|-------|--------|
| Severity | Medium (reconciled from the original High/7.2: exploitation in isolation requires a traffic-capture position, AC:H) |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9 |
| Likelihood | Medium |
| Business impact | High |
| Risk | High (a capture was already exposed via F-01) |
| CVE | n/a |
| Affected asset | vsftpd 3.0.3 (port 21) |
| Authentication required | None |
| MITRE ATT&CK | T1040 (Network Sniffing), T1552 (Unsecured Credentials) |

Description: FTP transmits authentication in cleartext. The capture obtained via F-01 contained a full FTP session exposing the username and password in readable form.

Evidence: Wireshark TCP-stream analysis revealed the `USER` and `PASS` exchange in plaintext for user `nathan` (password redacted, Figure 3).

Business impact: any party able to capture or access stored traffic can recover valid credentials, which here enabled host access via F-04.

Remediation: disable FTP and replace with SFTP or SCP; if legacy FTP is unavoidable, enforce FTPS (FTP over TLS); adopt an organisation-wide no-cleartext-protocols policy.

References: OWASP A02:2021 (Cryptographic Failures).

---

### F-03: Misconfigured `cap_setuid` Capability on Python (Root)

| Field | Detail |
|-------|--------|
| Severity | High (reconciled from the original Critical/8.8: local-access requirement caps the base score in the High band; see Risk) |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.8 |
| Likelihood | High (trivial once a shell is held) |
| Business impact | High |
| Risk | Critical (grants full root control) |
| CVE | n/a |
| Affected asset | `/usr/bin/python3.8` (`cap_setuid+eip`) |
| Authentication required | Local user (via F-04) |
| MITRE ATT&CK | T1548 (Abuse Elevation Control Mechanism) |

Description: the Python 3.8 binary carries the `cap_setuid` capability with effective, inheritable, and permitted flags. This lets any local user set the process UID to 0 and spawn a root shell, bypassing normal privilege boundaries.

Evidence: `getcap -r / 2>/dev/null` returned `/usr/bin/python3.8 = cap_setuid+eip` (Figure 4); `python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"` yielded `whoami` returning `root`.

Business impact: complete host compromise: full data access, persistence, malware installation, and onward pivoting.

Remediation: remove the capability (`sudo setcap -r /usr/bin/python3.8`); audit all binaries (`getcap -r /`); assign capabilities only where strictly required and review them as part of routine hardening.

References: GTFOBins (Python, Capabilities); Linux `capabilities(7)`; MITRE T1548.

---

### F-04: Password Reuse Across FTP and SSH

| Field | Detail |
|-------|--------|
| Severity | High (reconciled from the original Medium/6.5: the reused credential directly granted the host foothold) |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 7.3 |
| Likelihood | Medium |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | User `nathan` (FTP and SSH) |
| Authentication required | None (credential obtained via F-01/F-02) |
| MITRE ATT&CK | T1078 (Valid Accounts) |

Description: the FTP password recovered from the capture was reused verbatim for SSH, allowing a single exposed credential to grant interactive host access.

Evidence: authentication to SSH (port 22) as `nathan` succeeded using the FTP-derived password, returning a user shell.

Business impact: credential compromise on one service immediately extended to another, providing the foothold for privilege escalation.

Remediation: enforce unique credentials per service; deploy a password manager; prefer SSH key-based authentication and disable password authentication for SSH.

References: OWASP A07:2021 (Identification and Authentication Failures).

---

## 7. Strategic Recommendations (Root-Cause Themes)

1. No least-privilege baseline. The `cap_setuid` assignment on a general-purpose interpreter turned a local foothold into full root. Establish a hardening standard that assigns Linux capabilities only to binaries that require them, with periodic capability audits.
2. Credential hygiene absent. Cleartext transmission plus password reuse meant one exposed capture led directly to host access. Mandate encrypted protocols and unique per-service credentials, supported by a password manager and SSH keys.
3. Broken access control. The IDOR reflects missing server-side authorisation. Adopt access-control checks and unpredictable resource identifiers as a development standard, validated in code review.

---

## 8. Remediation Roadmap

### Immediate (Critical priority)
1. Remove `cap_setuid` from `/usr/bin/python3.8`; audit all binary capabilities.
2. Disable cleartext FTP; migrate to SFTP/SCP.

### Short-term (High priority)
3. Implement server-side authorisation and UUID identifiers on the web dashboard.
4. Eliminate password reuse; rotate the exposed credential.

### Medium-term
5. Enforce SSH key-only authentication; deploy a password manager; integrate capability and access-control checks into routine hardening and code review.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | SSH as `nathan` via reused credential | `/home/nathan/user.txt` -> [REDACTED] |
| Root | `cap_setuid` abuse on python3.8 | `/root/root.txt` -> [REDACTED] |

---

## 10. Retest and Validation

Recommend retest within 30 days of remediation to confirm the Python capability is removed, cleartext FTP is disabled, the web dashboard enforces authorisation, and the exposed credential has been rotated and is no longer reused.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | 7.98 | Port scanning and service enumeration |
| Web browser | n/a | Web application enumeration / IDOR |
| Wireshark | n/a | PCAP analysis and credential extraction |
| ssh | n/a | Remote host access |
| getcap | n/a | Linux capability enumeration |
| python3.8 | 3.8 | Privilege-escalation vehicle |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |
| GTFOBins (Python) | https://gtfobins.github.io/gtfobins/python/ |
| Linux capabilities(7) | https://man7.org/linux/man-pages/man7/capabilities.7.html |
| MITRE ATT&CK | https://attack.mitre.org/ |

---

*Produced for educational purposes within the Hack The Box authorised training environment. All testing was conducted legally on assigned infrastructure.*

*Report classification: Training / CTF Documentation.*
