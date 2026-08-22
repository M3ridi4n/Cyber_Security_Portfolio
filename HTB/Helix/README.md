# Penetration Test Report: Helix

## Document Control

| Field | Detail |
|-------|--------|
| Report title | Penetration Test Report: Helix |
| Template version | v4 |
| Report version | 1.0 |
| Author | David Lumsden (M3ridi4n) |
| Reviewer (QA) | Self-reviewed |
| Date | 2026-08-22 |
| Classification | Confidential / Training Documentation |
| Distribution | Author, portfolio reviewers with granted access |
| Publication status | PENDING RETIREMENT CONFIRMATION (workshop copy, remains in private repo until Helix retirement is verified; flip to RETIRED at that point) |
| Redaction policy | Flags withheld. HTB target IPs obfuscated as 10.129.XX.XX. Attacker VPN IP obfuscated as 10.10.XX.XX. Sensitive secrets redacted in body. |

### Version history

| Report version | Date | Author | Notes |
|----------------|------|--------|-------|
| 0.1 | 2026-08-22 | D. Lumsden | Initial draft from engagement notes |
| 1.0 | 2026-08-22 | D. Lumsden | Final, built to v4 template |

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

Helix is an internet-facing operational technology platform representing an industrial reactor control environment. Testing was conducted from outside the network with no credentials and no prior knowledge. Within a single engagement, the tester achieved full administrative control of the platform and, more significantly, was able to force the reactor's safety system into a state it should not have reached, by using documented operator tools in a sequence the designer did not anticipate.

Three distinct weaknesses were chained: a public web service running without any login requirement, an operational credential left inside a diagnostic file, and a design flaw in the reactor control system where a tool documented as a calibration adjustment actually drives real physical state and can be used to trick the safety controller into unlocking privileged access. The third weakness has no software patch: it is a design and process problem, and comparable issues have been implicated in real-world ICS incidents.

Overall risk rating: CRITICAL

### Findings at a glance

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 1 |
| Medium | 0 |
| Informational | 0 |

Most urgent action: enforce authentication on the public data-flow platform and remove all credential material from service-writable directories within 24 hours; convene an engineering review of the reactor control model to close the calibration-drives-state gap.

---

## 2. Scope and Rules of Engagement

| Item | Detail |
|------|--------|
| In scope | Single host: 10.129.XX.XX. Discovered vhosts: helix.htb, flow.helix.htb. Internal services reached via foothold: OPC UA endpoint 127.0.0.1:4840, HMI 127.0.0.1:8081. |
| Out of scope | Adjacent HTB infrastructure, other tenants, denial-of-service testing, brute-force against SSH. |
| Authorisation | Hack The Box authorised testing on assigned lab infrastructure. |
| Testing type | Black-box (no prior credentials, no prior knowledge). |
| Testing window | 2026-08-22 (single-session engagement). |
| Constraints | Single tester, single testing window; no destructive testing beyond that required to demonstrate exploitability of documented findings. |

---

## 3. Methodology and Risk Rating Model

Testing was aligned to PTES and structured across the following phases: reconnaissance, enumeration, vulnerability identification, exploitation, post-exploitation, and reporting. For the ICS component of the engagement, MITRE ATT&CK for ICS provided the tactical vocabulary; the enterprise matrix covered the initial-access and lateral-movement stages.

Risk rating model: each finding is assigned a base severity using CVSS v3.1 (vector string shown per finding). Severity labels follow CVSS bands strictly: Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9. A contextual Risk rating is then derived from Likelihood multiplied by Business Impact, reflecting how the finding would affect the assessed organisation rather than a generic environment. Where a finding is not tied to a published CVE (F-02, F-03), the CVSS score has been derived by the tester from the vector components and flagged as such.

---

## 4. Attack Narrative

### Phase 1: Reconnaissance

Nmap TCP scan of the target revealed only two externally exposed services: OpenSSH 8.9p1 on port 22 and nginx 1.18.0 on port 80. With no credentials available, SSH was not an initial-access candidate. Web became the sole attack surface.

### Phase 2: Enumeration

The web root redirected to `helix.htb`, a static corporate landing page with no interactive functionality. Given nginx as the fronting server, virtual host fuzzing was the correct next step. `ffuf` against the `Host` header (size-filtering out the default vhost) revealed `flow.helix.htb`, which served Apache NiFi 1.21.0. The NiFi canvas loaded without authentication.

### Phase 3: Initial Access

NiFi 1.21.0 unauthenticated exposure is exploitable in two overlapping ways: (a) its own processor primitives (`ExecuteStreamCommand`, `ExecuteProcess`) are RCE-as-a-feature, and (b) it is affected by CVE-2023-34468, an H2 JDBC driver arbitrary code execution reachable via the `DBCPConnectionPool` controller service. The tester attempted manual exploitation of the H2 vector first, to validate understanding of the mechanism, then pivoted to the Metasploit module `exploit/multi/http/apache_nifi_processor_rce` for reliable execution. A command shell was obtained as the `nifi` service account. The module's automatic pre-flight check returned 404 due to nginx path handling; `ForceExploit true` was used only after the version banner had independently confirmed vulnerability.

### Phase 4: Privilege Escalation / Lateral Movement

Enumeration of the NiFi installation directory found an OpenSSH ed25519 private key backup (`operator_id_ed25519.bak`) inside `/opt/nifi-1.21.0/support-bundles/`, readable by the service account. The key was exfiltrated and used to authenticate to SSH as the `operator` user. As `operator`, `sudo -l` disclosed a single `NOPASSWD` entry: `/usr/local/sbin/helix-maint-console`. Executing it returned `Maintenance window CLOSED`; the binary was gated on system state, not authentication.

Enumeration of local listeners identified an OPC UA server on 127.0.0.1:4840, the IANA-registered port for industrial control. A password-protected PDF (`Operator Control & Safety Guide.pdf`) in the operator's home directory documented the reactor control model. The PDF was unlocked via `pdf2john` and John the Ripper with `rockyou.txt` (password: `operator1`, username plus one digit).

### Phase 5: Full Compromise

The operator guide documented the reactor's trip thresholds and, critically in Section 8, described `CalibrationOffset` as a sensor calibration adjustment while also stating that increasing it "gradually" causes temperature and pressure to rise. OPC UA enumeration via `asyncua` confirmed which nodes accepted writes. The exploit sequence: set `Mode = "MAINTENANCE"`, `TestOverride = True`, then ramp `CalibrationOffset` upward one unit per second. At an offset value of approximately 16, reactor temperature entered the 295 C to 304.9 C "maintenance window" band without exceeding the 305 C trip threshold. The safety controller autonomously opened the maintenance window; in a parallel SSH session, `sudo /usr/local/sbin/helix-maint-console` executed successfully, returning `[+] Privileged maintenance access granted` and dropping a root shell. Full compromise achieved.

---

## 5. Findings Summary

| ID | Finding | Severity | CVSS | Risk | CVE |
|----|---------|----------|------|------|-----|
| F-01 | Unauthenticated Apache NiFi 1.21.0 permits remote code execution via CVE-2023-34468 | Critical | 9.8 (contextual, verify on NVD) | Critical | CVE-2023-34468 |
| F-02 | Sensitive SSH private key stored in NiFi diagnostic directory readable by service account | High | 7.5 (derived, verify on NVD n/a) | High | n/a |
| F-03 | OPC UA CalibrationOffset drives physical reactor state, enabling coerced maintenance-window unlock | Critical | 9.1 (derived, verify on NVD n/a) | Critical | n/a |

---

## 6. Detailed Findings

### F-01: Unauthenticated Apache NiFi 1.21.0 permits remote code execution via CVE-2023-34468

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (contextual; NVD baseline is 8.8 assuming PR:L, verify on NVD) |
| Likelihood | High |
| Business impact | High |
| Risk | Critical |
| CVE | CVE-2023-34468 |
| Affected asset | flow.helix.htb (Apache NiFi 1.21.0) |
| Authentication required | None (NiFi authentication is not enforced) |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter) |

Description: Apache NiFi 1.21.0 was deployed on the `flow.helix.htb` virtual host without authentication. The `DBCPConnectionPool` controller service accepts JDBC URLs using the H2 driver; H2 supports an `INIT` clause that runs arbitrary SQL at connection time, and `CREATE ALIAS ... AS $$ <Java> $$` compiles and loads inline Java into the JVM. Chaining the two allows arbitrary code execution inside NiFi's JVM when the controller service is enabled. Separately, NiFi's `ExecuteStreamCommand` and `ExecuteProcess` processors execute arbitrary commands as designed features; an unauthenticated NiFi is effectively RCE by any of several paths.

Evidence: initial access confirmed via the Metasploit module `exploit/multi/http/apache_nifi_processor_rce`, which creates an `ExecuteStreamCommand` processor via the REST API and returns a command shell. Post-exploitation `whoami` returned `nifi`. Reference Figures 4 and 5.

Business impact: full command execution as the NiFi service account on the ingress host. In a production environment, this places any data flowing through NiFi at risk (ingestion pipelines commonly carry sensitive telemetry), enables lateral movement (as demonstrated by F-02), and provides a foothold into any adjacent OT segment the NiFi host can reach.

Remediation:

- Upgrade Apache NiFi to 1.23.1 or later (fix for CVE-2023-34468).
- Enforce authentication on the NiFi endpoint (single-user, LDAP, or Kerberos as appropriate to the environment).
- Restrict processor creation to a dedicated engineering role via NiFi policies; general operators should not be able to create `ExecuteStreamCommand`, `ExecuteProcess`, `ExecuteScript`, or `DBCPConnectionPool` resources.
- Remove public-facing exposure. NiFi is a data-flow platform, not a public web service; place it behind a reverse proxy that terminates authenticated sessions or on an internal VLAN only.

Detection guidance (SOC lens):

- Alert on NiFi audit-log events for the creation or modification of `ExecuteStreamCommand`, `ExecuteProcess`, and `DBCPConnectionPool` resources, especially from identities outside the engineering group.
- Egress monitoring on the NiFi host: outbound TCP to non-corporate addresses from the NiFi service account is anomalous.
- Detect JDBC connection strings containing `INIT=`, `CREATE ALIAS`, or embedded Java class references in NiFi configuration diffs.

References: CVE-2023-34468 (NVD), Apache NiFi 1.23.0 release notes.

---

### F-02: Sensitive SSH private key stored in NiFi diagnostic directory readable by service account

| Field | Detail |
|-------|--------|
| Severity | High |
| CVSS v3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = 7.5 (derived by tester, no CVE; verify on NVD n/a) |
| Likelihood | High |
| Business impact | High |
| Risk | High |
| CVE | n/a |
| Affected asset | `/opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak` on the Helix host |
| Authentication required | User (NiFi service account access, obtained via F-01) |
| MITRE ATT&CK | T1552.004 (Unsecured Credentials: Private Keys), T1078 (Valid Accounts) |

Description: An OpenSSH ed25519 private key backup file, associated with the `operator` interactive user, was stored in the NiFi installation's diagnostic bundle directory (`support-bundles/`). The file was owned by, and readable by, the `nifi` service account (permissions `-rw-r-----` with `nifi:nifi` ownership). Any compromise of the NiFi process (F-01) therefore yielded direct access to the operator user with no further exploitation required. The key's comment field (`root@management`) further suggested the key was originally generated on an unrelated management host, indicating poor key hygiene beyond this instance.

Evidence: `ls -la /opt/nifi-1.21.0/support-bundles/` listed the file post-foothold; the key was retrieved and used successfully to authenticate as `operator` via SSH. Reference Figures 6 and 7.

Business impact: crosses a privilege boundary from an unprivileged service account to an interactive operator account with sudo rights to the reactor's maintenance console (see F-03). In real terms, a single web-service compromise becomes a foothold on the OT operator plane. The scope change is the driver of the CVSS score (S:C).

Remediation:

- Prohibit storage of credential material in any application, service, or diagnostic directory. Support bundles and log directories are recurring hiding places precisely because engineers underestimate what gets swept into them.
- Use dedicated secrets management (HashiCorp Vault, AWS Secrets Manager, or an equivalent enterprise solution) for all operational credentials; provision to hosts via short-lived tokens where possible.
- Rotate the exposed key immediately and audit for any additional copies (`grep -r 'BEGIN OPENSSH' /opt /var /etc /home` on all comparable hosts).
- Apply file integrity monitoring to service directories with rules that alert on the creation of `.key`, `.pem`, or `id_*` files.

Detection guidance:

- FIM rules alerting on new files matching SSH private-key patterns under `/opt`, `/var`, `/home`, or any application installation directory.
- Auditd rules on `open()` syscalls for private key files by non-standard users (service accounts should never read interactive user keys).
- SSH login monitoring: interactive login by a user account originating from a session that used credentials sourced from a service account's readable path (correlate SSH `Accepted` events with recent file reads).

References: MITRE ATT&CK T1552.004 (Unsecured Credentials: Private Keys), OWASP ASVS 2.10 (Service Authentication).

---

### F-03: OPC UA CalibrationOffset drives physical reactor state, enabling coerced maintenance-window unlock

| Field | Detail |
|-------|--------|
| Severity | Critical |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` = 7.6 base; adjusted to 9.1 contextual on the basis of ICS safety scope (derived by tester, no CVE; verify on NVD n/a) |
| Likelihood | Medium (requires operator-level access, OPC UA knowledge, and process documentation; all three obtainable in a compromise scenario) |
| Business impact | High (safety system integrity and privileged access) |
| Risk | Critical |
| CVE | n/a |
| Affected asset | OPC UA endpoint 127.0.0.1:4840 on the Helix host; `helix-maint-console` sudo binary; safety controller trust model |
| Authentication required | User (operator OPC UA write privileges) |
| MITRE ATT&CK | T0836 (Modify Parameter, ICS matrix), T0831 (Manipulation of Control, ICS matrix), T1548 (Abuse Elevation Control Mechanism, enterprise) |

Description: The `Plant.Reactor.CalibrationOffset` OPC UA variable is documented in the Operator Control and Safety Guide as a sensor calibration bias, described as having no direct control of physical reactor state. In practice, when `Control.Mode` is set to `MAINTENANCE` and `Control.TestOverride` is enabled, writes to `CalibrationOffset` drive the reactor's actual temperature and pressure readings. Section 8 of the same guide contradicts its introduction by confirming this behaviour ("when CalibrationOffset is increased gradually, Temperature rises predictably").

By ramping `CalibrationOffset` upward at approximately one unit per second, an authenticated operator can land the reactor's reported state in the 295 C to 304.9 C "maintenance window" band without crossing the 305 C trip threshold. The safety controller, trusting the reported physical state, autonomously opens a privileged maintenance window during which the `sudo helix-maint-console` binary executes and grants a root shell. No exploit code, no protocol violation, and no undocumented behaviour is used; every action is a supported operator function.

Evidence: OPC UA enumeration via `asyncua` confirmed writable and read-only nodes. A 51-step ramp script (`opcua_exploit.py`) walked `CalibrationOffset` from 0 to a target value while polling `Plant.Reactor.Temperature` and `Plant.Safety.TripActive`. At offset ~16, temperature crossed 295 C without tripping. In a parallel SSH session, `sudo /usr/local/sbin/helix-maint-console` executed and returned `[+] Privileged maintenance access granted`, dropping a root shell. Reference Figures 10 and 11.

Business impact: the design flaw allows any account with OPC UA write access and shell access on the PLC host to obtain root without any true hazardous condition existing. In a physical facility, the same class of manipulation would also cause the operator team and any downstream safety instrumented systems to react to a phantom hazard, with consequences ranging from unplanned shutdown to unsafe operator intervention. The root cause (a "diagnostic" tool with unintended physical consequences) has been implicated in real ICS incidents where debug or calibration functions were reachable from the production control plane.

Remediation:

- Enforce a hard separation between diagnostic sensor calibration and reactor process inputs at the controller firmware level. `CalibrationOffset` must affect only reported values, never physical state.
- Restrict writability of `Control.Mode`, `Control.TestOverride`, and `Plant.Reactor.CalibrationOffset` to a dedicated maintenance-engineer OPC UA role. General operators should not hold these privileges.
- Require independent physical confirmation before the safety controller grants the maintenance window: cross-reference primary sensor readings against redundant, physically separate instrumentation, and treat divergence between them as an alarm condition rather than a valid state.
- Segregate the OPC UA endpoint from the operator's interactive shell environment. No single account should hold both a shell on the PLC host and OPC UA write privileges to safety-relevant parameters.
- Review all other "operator adjustments" for hidden physical effects. Any adjustment with physical consequences is a control-plane action and must be authorised, logged, and rate-limited as such.

Detection guidance:

- Alert on OPC UA write events targeting `CalibrationOffset` with monotonically increasing patterns, and on writes to `Control.Mode = MAINTENANCE` combined with `TestOverride = True` from non-engineering sessions.
- Alert on any invocation of the maintenance console outside pre-approved and change-managed maintenance windows.
- Continuously correlate PLC-reported state against redundant physical instrumentation. Divergence exceeding a defined tolerance is a strong indicator of calibration abuse (or genuine sensor failure, which is also worth investigating).
- Correlate temporal proximity of OPC UA writes to `CalibrationOffset` with `sudo` events on the host. The two should rarely co-occur; when they do, escalate.

References: MITRE ATT&CK for ICS T0836 (Modify Parameter), T0831 (Manipulation of Control); MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism); NIST SP 800-82 Rev. 3 (Guide to Operational Technology Security), sections on access control and separation of engineering and operator roles.

---

## 7. Strategic Recommendations (Root-Cause Themes)

Three themes recur across the findings and each has a strategic response that goes beyond the finding-level remediation.

**Theme 1: Authentication is not enforced where it matters most.** The public-facing NiFi instance had no login requirement; the maintenance console relied on state rather than authenticated authorisation; the operator's SSH key was reusable with no MFA. Strategic recommendation: establish an authentication baseline that treats every service (internal or external) as requiring identity, applies MFA to any interactive account with access to OT systems, and audits for unauthenticated services quarterly.

**Theme 2: Sensitive material is stored in places it should never be.** The SSH key sat inside a NiFi diagnostic directory; the operator's password was `operator1`, a pattern that appears in public breach corpora. Strategic recommendation: adopt a centralised secrets management platform, prohibit credential storage in application or diagnostic directories via policy and file integrity monitoring, and enforce password complexity and reuse controls that would reject `operator1` outright.

**Theme 3: The control system trusts what it is told, not what is true.** The safety controller granted the maintenance window based on reported sensor values, and the sudo binary trusted that grant. There is no independent physical validation anywhere in the chain. Strategic recommendation: adopt a defence-in-depth model for safety-critical decisions that requires physical validation from redundant instrumentation, and separates the identities that can adjust sensor parameters from the identities that can act on the resulting states. This is the pattern behind a large share of real ICS incidents; it deserves an engineering review rather than a configuration change.

---

## 8. Remediation Roadmap

### Immediate (Critical priority, within 24 to 72 hours)

- Take the public-facing NiFi instance offline or place it behind an authenticated reverse proxy pending upgrade.
- Rotate the exposed SSH key and audit all hosts for comparable credential files in service directories.
- Disable OPC UA write access to `CalibrationOffset`, `Mode`, and `TestOverride` from operator accounts pending the engineering review in the medium term.

### Short-term (High priority, within 30 days)

- Upgrade Apache NiFi to 1.23.1 or later and enforce authentication.
- Deploy file integrity monitoring on service directories with alerts for credential-like file patterns.
- Deploy centralised secrets management for all operational credentials.
- Deploy audit logging and alerting for the OPC UA write patterns described in F-03.

### Medium-term (within 90 days)

- Complete the safety controller engineering review recommended under Theme 3: separate diagnostic calibration from physical inputs, add redundant instrumentation cross-checks, and require independent confirmation before the maintenance window opens.
- Introduce role separation between operators (interactive shell) and maintenance engineers (OPC UA write to safety-relevant parameters), with break-glass procedures for genuine emergencies.
- Re-baseline password policy and enforce it via a modern IAM system; reject weak patterns such as username plus digit.

---

## 9. Proof of Exploitation

| Flag | Method | Location |
|------|--------|----------|
| User | SSH authentication as `operator` using an ed25519 private key recovered from the NiFi service account's readable diagnostic directory | `/home/operator/user.txt` -> REDACTED |
| Root | `sudo /usr/local/sbin/helix-maint-console` executed while the reactor was held in the 295 C to 304.9 C maintenance-window band via OPC UA CalibrationOffset ramp | `/root/root.txt` -> REDACTED |

---

## 10. Retest and Validation

A retest is recommended no earlier than 30 days after the short-term remediation items complete, and again after the medium-term engineering review closes out. A retest would verify:

- NiFi is no longer accessible without authentication from outside the internal network, and its version is at or above 1.23.1.
- No SSH private keys or comparable credential material are present in service-writable directories on the Helix host or comparable hosts; FIM alerts fire when a test key is placed and immediately removed.
- Attempts to write to `CalibrationOffset`, `Mode`, or `TestOverride` from the operator account are refused at the OPC UA server; writes from the maintenance-engineer role succeed and are logged and alerted on.
- Ramping `CalibrationOffset` (from a maintenance-engineer session) no longer results in the `helix-maint-console` maintenance window opening, because the safety controller now requires redundant physical confirmation.

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | 7.94 | External TCP service and version scan |
| ffuf | 2.1.0 | Virtual host fuzzing with size-based filtering |
| Metasploit Framework | 6.x (module `apache_nifi_processor_rce`) | Reliable RCE against NiFi 1.21.0 |
| OpenSSH client | 8.9p1 | Lateral movement, transport, tunnelling |
| pdf2john, John the Ripper | JtR 1.9.0 | PDF password recovery |
| Python 3 | 3.11 | Scripting host for OPC UA client |
| `asyncua` | 1.0.x | OPC UA enumeration and manipulation |
| ss (iproute2) | native | Local listener enumeration |

## Appendix B: References

| Reference | URL |
|-----------|-----|
| CVE-2023-34468 (Apache NiFi H2 JDBC RCE) | https://nvd.nist.gov/vuln/detail/CVE-2023-34468 |
| Apache NiFi 1.23.0 release notes | https://nifi.apache.org/docs.html |
| OPC UA specification overview | https://opcfoundation.org/about/opc-technologies/opc-ua/ |
| MITRE ATT&CK for ICS: T0836 Modify Parameter | https://attack.mitre.org/techniques/T0836/ |
| MITRE ATT&CK for ICS: T0831 Manipulation of Control | https://attack.mitre.org/techniques/T0831/ |
| MITRE ATT&CK T1190 Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |
| MITRE ATT&CK T1552.004 Unsecured Credentials: Private Keys | https://attack.mitre.org/techniques/T1552/004/ |
| MITRE ATT&CK T1548 Abuse Elevation Control Mechanism | https://attack.mitre.org/techniques/T1548/ |
| NIST SP 800-82 Rev. 3 Guide to Operational Technology Security | https://csrc.nist.gov/pubs/sp/800/82/r3/final |

---

*Produced for educational purposes within an authorised Hack The Box training environment. All testing was conducted legally on assigned infrastructure. Flags withheld. HTB target IP obfuscated as 10.129.XX.XX; attacker VPN IP obfuscated as 10.10.XX.XX.*
