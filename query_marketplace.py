#!/usr/bin/env python3
"""Query the VS Code Marketplace for top extensions by install count."""
import json
import sys
import urllib.request

URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"

def query(page_number: int, page_size: int = 100):
    body = {
        "filters": [
            {
                "criteria": [
                    {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                    {"filterType": 12, "value": "4096"},
                ],
                "pageNumber": page_number,
                "pageSize": page_size,
                "sortBy": 4,
                "sortOrder": 0,
            }
        ],
        "assetTypes": [],
        "flags": 914,
    }
    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        headers={
            "Accept": "application/json;api-version=3.0-preview.1",
            "Content-Type": "application/json",
            "User-Agent": "VSCode 1.95",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def extract(resp):
    rows = []
    results = resp.get("results", [])
    if not results:
        return rows
    for ext in results[0].get("extensions", []):
        installs = None
        for stat in ext.get("statistics", []):
            if stat.get("statisticName") == "install":
                installs = int(stat["value"])
        versions = ext.get("versions") or [{}]
        latest_version = versions[0].get("version")
        repo = None
        for prop in versions[0].get("properties", []):
            if prop.get("key") in (
                "Microsoft.VisualStudio.Services.Links.Source",
                "Microsoft.VisualStudio.Services.Links.GitHub",
            ):
                repo = prop.get("value")
                break
        rows.append(
            {
                "publisher": ext["publisher"]["publisherName"],
                "name": ext["extensionName"],
                "display": ext["displayName"],
                "installs": installs,
                "version": latest_version,
                "repo": repo,
            }
        )
    return rows


def main():
    all_rows = []
    for page in (1, 2):
        resp = query(page, 100)
        batch = extract(resp)
        all_rows.extend(batch)
        print(f"page {page}: {len(batch)} extensions", file=sys.stderr)
    out = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout"
    with (sys.stdout if out == "/dev/stdout" else open(out, "w")) as f:
        json.dump(all_rows, f, indent=2)
    print(f"wrote {len(all_rows)} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
