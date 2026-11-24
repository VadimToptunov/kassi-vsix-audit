#!/usr/bin/env python3
"""Watch the OSV npm feed against a pinned snapshot, without re-downloading anything.

A snapshot pins what each extension shipped (runs/<date>/inventory.json). An
advisory published after the snapshot can apply to a dependency that was clean
back then. The bundle didn't change; the advisory list did. This script finds
those cases from the feed:

  1. Read OSV's npm change feed (modified_id.csv, newest first) down to the
     checkpoint: the last time this script ran, or the snapshot date on the
     first run.
  2. Fetch each changed record and keep the ones that name a package the
     snapshot ships (any version).
  3. Ask OSV /v1/querybatch about exactly those (name, version) pairs, so OSV
     decides whether the pinned version is in range. No semver code here.
  4. Report matches that the snapshot's audit.json didn't have and that an
     earlier run of this script didn't report yet. Also report records that
     were withdrawn while the snapshot still lists them.

MAL-* records (malicious packages) come through the same feed and are reported
the same way.

The bundled-JS blind spot carries over: an extension that ships one bundled JS
file has no inventory, so nothing in the feed can match it.

Usage:
  python3 watch_feed.py runs/2026-11-08                 # report since last run
  python3 watch_feed.py runs/2026-11-08 --since 2026-11-08T00:00:00Z
  python3 watch_feed.py runs/2026-11-08 --dry-run       # don't move the checkpoint

State (checkpoint + rows already reported) is kept in <run>/feed_state.json.
Exit code: 0 nothing new, 1 something new, 2 error.
"""
import argparse
import concurrent.futures
import io
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

FEED = "https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv"
RECORD = "https://osv-vulnerabilities.storage.googleapis.com/npm/{id}.json"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"
UA = {"User-Agent": "kassi-vsix-audit"}


def http(url, data=None, timeout=60):
    headers = dict(UA)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout)


def changed_since(checkpoint):
    """(timestamp, id) pairs from the feed newer than checkpoint, newest first."""
    out = []
    with http(FEED, timeout=120) as r:
        for raw in io.TextIOWrapper(r, encoding="utf-8"):
            line = raw.strip()
            if not line:
                continue
            ts, _, osv_id = line.partition(",")
            if ts <= checkpoint:
                break  # the feed is sorted newest first
            out.append((ts, osv_id))
    return out


def fetch_record(osv_id):
    try:
        with http(RECORD.format(id=osv_id), timeout=30) as r:
            return osv_id, json.loads(r.read())
    except Exception as e:  # noqa: BLE001 - reported, not fatal
        return osv_id, {"error": str(e)}


def npm_packages(record):
    names = set()
    for a in record.get("affected", []):
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") == "npm" and pkg.get("name"):
            names.add(pkg["name"])
    return names


def querybatch(pairs):
    """{(name, version): set(ids)} for the given pairs, 500 per request."""
    out = {}
    for off in range(0, len(pairs), 500):
        batch = pairs[off:off + 500]
        body = json.dumps({"queries": [
            {"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in batch
        ]}).encode()
        with http(QUERYBATCH, data=body) as r:
            results = json.loads(r.read()).get("results", [])
        for pair, res in zip(batch, results):
            out[pair] = {v["id"] for v in res.get("vulns", [])}
            # querybatch pages long result lists; a dep with that many matches
            # is already flagged by the snapshot, so the first page is enough here.
    return out


def severity(record):
    s = (record.get("database_specific") or {}).get("severity")
    if s:
        return str(s).upper()
    return "MALICIOUS" if record.get("id", "").startswith("MAL-") else "UNKNOWN"


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("run_dir")
    ap.add_argument("--since", help="ISO timestamp; overrides the stored checkpoint")
    ap.add_argument("--dry-run", action="store_true", help="report, but don't update state")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    inv_path = os.path.join(args.run_dir, "inventory.json")
    if not os.path.exists(inv_path):
        print(f"{inv_path} is missing. Re-run audit_extensions.py for this snapshot; "
              "it writes inventory.json next to audit.json.", file=sys.stderr)
        return 2
    inventory = json.load(open(inv_path))
    baseline = set()
    for f in json.load(open(os.path.join(args.run_dir, "audit.json"))):
        for vid in f["vulns"]:
            baseline.add((f["ext"], f["dep"], f["version"], vid))

    state_path = os.path.join(args.run_dir, "feed_state.json")
    state = json.load(open(state_path)) if os.path.exists(state_path) else {}
    reported = {tuple(r) for r in state.get("reported", [])}
    checkpoint = args.since or state.get("checkpoint") or \
        os.path.basename(os.path.normpath(args.run_dir)) + "T00:00:00Z"

    # Which extensions ship which (name, version).
    shipped = {}  # name -> {version -> [ext, ...]}
    for e in inventory:
        for d in e["deps"]:
            shipped.setdefault(d["name"], {}).setdefault(d["version"], []).append(e["ext"])
    print(f"snapshot: {len(inventory)} extensions, {len(shipped)} distinct packages; "
          f"checkpoint {checkpoint}", file=sys.stderr)

    changes = changed_since(checkpoint)
    print(f"feed: {len(changes)} records changed since the checkpoint", file=sys.stderr)
    if not changes:
        print("No feed changes since the checkpoint.")
        return 0
    newest = changes[0][0]

    records, errors = {}, []
    with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
        for osv_id, rec in pool.map(fetch_record, [i for _, i in changes]):
            if "error" in rec:
                errors.append(f"{osv_id}: {rec['error']}")
            else:
                records[osv_id] = rec
    if errors:
        # Don't move the checkpoint past records we couldn't read.
        print(f"{len(errors)} records could not be fetched, e.g. {errors[0]}", file=sys.stderr)

    relevant = {i: r for i, r in records.items() if npm_packages(r) & shipped.keys()}
    print(f"records naming a shipped package: {len(relevant)}", file=sys.stderr)

    # Ask OSV about exactly the pinned versions of those packages.
    names = set().union(*(npm_packages(r) for r in relevant.values())) & shipped.keys() if relevant else set()
    pairs = sorted((n, v) for n in names for v in shipped[n])
    matches = querybatch(pairs) if pairs else {}

    new_rows, withdrawn = [], []
    for (name, version), ids in matches.items():
        for vid in ids & relevant.keys():
            rec = relevant[vid]
            for ext in shipped[name][version]:
                row = (ext, name, version, vid)
                if row in baseline or row in reported:
                    continue
                new_rows.append((row, rec))
    for vid, rec in relevant.items():
        if not rec.get("withdrawn"):
            continue
        for row in baseline:
            if row[3] == vid and (row + ("withdrawn",)) not in reported:
                withdrawn.append((row, rec))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"# OSV feed watch: {os.path.basename(os.path.normpath(args.run_dir))}\n")
    print(f"Checked {now}. Feed changes since {checkpoint}: {len(changes)}; "
          f"naming a shipped package: {len(relevant)}; pinned pairs re-queried: {len(pairs)}.\n")
    if new_rows:
        print("## New matches on pinned versions\n")
        print("| extension | dependency | version | advisory | severity | published | modified |")
        print("|---|---|---|---|---|---|---|")
        for (ext, name, version, vid), rec in sorted(new_rows, key=lambda x: x[0]):
            print(f"| `{ext}` | `{name}` | {version} | [{vid}](https://osv.dev/vulnerability/{vid}) "
                  f"| {severity(rec)} | {rec.get('published', '')[:10]} | {rec.get('modified', '')[:10]} |")
        print()
    if withdrawn:
        print("## Withdrawn since the snapshot\n")
        for (ext, name, version, vid), rec in sorted(withdrawn, key=lambda x: x[0]):
            print(f"- `{ext}`: `{name}@{version}` [{vid}](https://osv.dev/vulnerability/{vid}) "
                  f"withdrawn {rec['withdrawn'][:10]}")
        print()
    if not new_rows and not withdrawn:
        print("Nothing new for the pinned versions.\n")
    if errors:
        print(f"{len(errors)} feed records could not be fetched; the checkpoint was not moved.\n")

    if not args.dry_run:
        state["reported"] = sorted(reported | {r for r, _ in new_rows} |
                                   {r + ("withdrawn",) for r, _ in withdrawn})
        if not errors:
            state["checkpoint"] = newest
        json.dump(state, open(state_path, "w"), indent=1)

    if errors and not new_rows:
        return 2
    return 1 if (new_rows or withdrawn) else 0


if __name__ == "__main__":
    sys.exit(main())
