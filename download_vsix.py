#!/usr/bin/env python3
"""Download .vsix for each extension row. Marketplace is gentle at ~1 req/s."""
import json
import os
import sys
import time
import urllib.request
import urllib.error

TEMPLATE = (
    "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/"
    "{publisher}/vsextensions/{name}/{version}/vspackage"
)

HEADERS = {
    "Accept": "application/octet-stream;api-version=3.0-preview.1",
    "User-Agent": "VSCode 1.95",
    "Accept-Encoding": "gzip",
}


def download(row, out_dir):
    url = TEMPLATE.format(**row)
    fname = f"{row['publisher']}.{row['name']}-{row['version']}.vsix"
    dest = os.path.join(out_dir, fname)
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return "skip", dest
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}", dest
    except Exception as e:
        return f"ERR {type(e).__name__}", dest
    # Marketplace returns gzip even when not asked. magic: 1f 8b
    if raw[:2] == b"\x1f\x8b":
        import gzip
        raw = gzip.decompress(raw)
    # a .vsix is a zip; magic: 50 4b
    if raw[:2] != b"PK":
        return f"NOT-ZIP {raw[:4].hex()}", dest
    with open(dest, "wb") as f:
        f.write(raw)
    return "ok", dest


def main():
    rows = json.load(open(sys.argv[1]))
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    rows = rows[:n]
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "vsix"
    os.makedirs(out_dir, exist_ok=True)
    for i, row in enumerate(rows, 1):
        status, dest = download(row, out_dir)
        print(f"{i:>3}/{n}  {status:<12}  {row['publisher']}.{row['name']}  ({os.path.getsize(dest) if status in ('ok','skip') else 0:,} B)", flush=True)
        time.sleep(1.0)


if __name__ == "__main__":
    main()
