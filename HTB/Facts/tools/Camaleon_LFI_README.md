# Camaleon CMS Path Traversal Scanner

A Python wrapper around CVE-2024-46987, built to automate authenticated local file inclusion against Camaleon CMS v2.9.0 during an authorised Hack The Box engagement.

## Background

CVE-2024-46987 is an authenticated path traversal in Camaleon CMS (versions up to and including 2.9.0). The vulnerable endpoint `/admin/media/download_private_file` accepts a `file` parameter that is not properly sanitised, allowing directory traversal (`../../`) to read arbitrary files from the server.

The original public PoC (ExploitDB 52531) requires manual, interactive input for each file path, returning one result per execution. During the HTB Facts engagement, this proved operationally slow: a high proportion of guessed paths returned HTTP 500, and iterating manually was an inefficient use of time.

This script solves that by automating the process. It takes a wordlist of target paths, runs each against the traversal endpoint, and saves every successful read (HTTP 200) to a local `loot/` directory as a text file for later analysis.

## Usage

```bash
python3 Camaleon_lfi.py -u <TARGET_URL> -w <WORDLIST> -t <AUTH_TOKEN> [-o <OUTPUT_DIR>]
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target base URL | `http://facts.htb` |
| `-w`, `--wordlist` | Path to the wordlist of file paths to attempt | Required |
| `-t`, `--token` | `auth_token` cookie value (obtained from an authenticated CMS session) | Required |
| `-o`, `--output` | Directory to save retrieved files | `loot` |

### Example

```bash
python3 Camaleon_lfi.py \
  -u http://TARGET_URL \
  -w Lfi_Paths.md \
  -t YOUR_AUTH_TOKEN \
  -o loot
```

The script will iterate through every path in the wordlist, report the HTTP status for each, and save all HTTP 200 responses to the output directory with filenames derived from the path (slashes replaced with underscores).

## Output

```
[*] Target:    http://TARGET_URL
[*] Wordlist:  Lfi_Paths.md (52 paths)
[*] Output:    loot/
[*] Starting scan...

  [1/52] HIT    /etc/passwd (1847 bytes) -> saved to loot/etc_passwd
  [2/52] 500    /etc/shadow
  ...

============================================================
[*] Scan complete. 12/52 files retrieved.

[+] Successful reads:
    /etc/passwd
    /home/trivia/.ssh/authorized_keys
    ...
```

## Wordlist

The included `Lfi_Paths.md` is a targeted wordlist built for this engagement, structured by category:

- **System files:** `/etc/passwd`, `/etc/shadow`, `/etc/hostname`, `/etc/crontab`
- **SSH keys:** private and authorised keys for all identified user accounts and root
- **Proc filesystem:** runtime environment, command line, and process status
- **Rails application paths:** database configs, secrets, environment files, and Gemfiles across four common deployment directories (`/var/www`, `/opt`, `/srv`, home directories), covering both legacy (`secrets.yml`) and modern (`credentials.yml.enc` / `master.key`) Rails credential formats

The list is deliberately targeted rather than exhaustive. It was built after initial reconnaissance confirmed a Ruby on Rails backend and identified the user accounts `trivia` and `william` from `/etc/passwd`.

## Requirements

- Python 3
- `requests` library (`pip install requests`)

## Disclaimer

This tool was built and used exclusively within an authorised Hack The Box lab environment for educational purposes. It targets a specific, known CVE in a controlled setting. Do not use this tool against any system you do not own or do not have explicit written permission to test.
