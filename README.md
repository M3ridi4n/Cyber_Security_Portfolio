# David Lumsden: Cyber Security Portfolio

Former British Army veteran (REME) building a career in cyber security, with a focus on SOC analyst and blue team roles. CompTIA Security+ certified, CREST CPSA in progress.

---
## About Me

I served in the Royal Electrical and Mechanical Engineers as a vehicle mechanic, where every fault followed the same process: observe the symptoms, form a hypothesis, test it, confirm the root cause, fix it, and document what you found. That diagnostic discipline is the foundation of everything in this portfolio.

I study offensive techniques and attacker tradecraft to defend more effectively. Every machine I break teaches me what a SOC needs to detect and how an attacker actually moves. The write-ups in this repository document that process: not just what I exploited, but how I would detect it and how I would fix it. Red team skills in service of a blue team career.

---
## Certifications

| Certification                              | Status                |
| ------------------------------------------ | --------------------- |
| CompTIA Security+                          | Achieved (March 2026) |
| CREST Practitioner Security Analyst (CPSA) | In progress           |

---
## Skills

| Focus                             | Detail                                                                                            |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| Web exploitation                  | SQL injection, IDOR, command injection, unauthenticated RCE, mass-assignment privilege escalation |
| Manual exploitation               | PoC adaptation and exploitation by hand; minimal reliance on automated frameworks                 |
| Privilege escalation and pivoting | Linux privilege escalation, container-to-host escape, sudo abuse, capability abuse                |
| Credential attacks                | Offline hash cracking (hashcat, John the Ripper), SSH key cracking                                |
| Custom tooling                    | Purpose-built Python scripts for exploit automation (see HTB-Facts)                               |
| Reporting                         | Client-style pentest reports with CVSS scoring, risk ratings, business impact, and remediation    |

---
## Completed Machines

### Hack The Box (retired machines only)

| Machine               | Difficulty | OS    | Key Techniques                                                     | Write-up               |
| --------------------- | ---------- | ----- | ------------------------------------------------------------------ | ---------------------- |
| [Cap](./HTB-Cap/)     | Easy       | Linux | IDOR, PCAP analysis, Linux capabilities                            | [Report](./HTB-Cap/)   |
| [Facts](./HTB-Facts/) | Easy       | Linux | Mass assignment, CVE-2024-46987, S3 enumeration, facter sudo abuse | [Report](./HTB-Facts/) |

Other Machines have been completed and are awaiting publishing however due to TryHackMe and Hack The Box rules and TOS rooms that are currently active or non-retired cannot be published.
<!--
  Add rows here as machines retire and their write-ups are transferred from the
  private repo. Do not list active or seasonal machines.
-->

---
## Repository Structure

Each machine folder where applicable contains:

- **README.md**: professional pen-test report (CVSS scoring, risk ratings, business impact, remediation).
- **images/**: annotated screenshots of key steps (flags and credentials redacted).
- **tools/**: custom scripts and wordlists where applicable (see HTB-Facts for an example).

All reports follow a consistent template (v3) aligned to PTES and the OWASP Web Security Testing Guide.

---
## Methodology

Every assessment follows a structured approach:

1. **Reconnaissance**: identify open ports, services, and versions.
2. **Enumeration**: enumerate services, directories, virtual hosts, and credentials.
3. **Exploitation**: exploit identified vulnerabilities, favouring manual techniques over automated tooling.
4. **Post-exploitation**: escalate privileges and pivot where in scope.
5. **Reporting**: document findings to a professional, client-facing standard with remediation and detection recommendations.

---

## Currently Working Towards

- CREST CPSA exam preparation.
- TryHackMe SOC Analyst / blue team pathway.
- Expanding into Medium-difficulty and Windows / Active Directory machines.
- Building SOC and detection-engineering skills (LetsDefend, Blue Team Labs Online).
- Anthropic AI Academy for AI fluency and greater efficiency with AI augmented workflows.

---
## Contact

- **LinkedIn:** [David Lumsden](https://www.linkedin.com/in/david-lumsden-25bb1228a/)
- **Hack The Box:** [M3ridi4n](https://profile.hackthebox.com/profile/019e0ce6-dd04-70dc-baf2-bbe5cb3d6a86)
- **TryHackMe:** [M3ridi4n](https://tryhackme.com/p/M3ridi4n)

---

*All penetration testing documented in this portfolio was conducted on authorised platforms in controlled lab environments. No unauthorised systems were accessed. Flags are never published. Write-ups for active or seasonal machines are withheld until retirement.*
