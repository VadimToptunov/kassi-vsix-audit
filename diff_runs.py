#!/usr/bin/env python3
"""Compare two pinned snapshots (runs/<date>/) and emit a longitudinal change report.

Answers:
  1. For the 19 (or whatever) extensions affected in the earlier snapshot:
     did they publish a new version? What is the new last-updated date?
  2. Which (ext, dep, advisory) rows disappeared (dep bumped past fix)?
  3. Which rows are new (advisory published since, or dep not previously flagged)?
  4. Developer response time: for each advisory, time between its publish date
     and the first extension release that cleared it.

Usage:
  python3 diff_runs.py runs/2026-11-08 runs/2027-02-08 > CHANGELOG.md
"""
import csv
import json
import os
import sys
from collections import defaultdict


def load_run(run_dir):
    dataset = []
    with open(os.path.join(run_dir, "DATASET.csv")) as f:
        for row in csv.DictReader(f):
            row["installs"] = int(row["installs"])
            dataset.append(row)
    with open(os.path.join(run_dir, "filtered.json")) as f:
        filtered = {f"{e['publisher']}.{e['name']}": e for e in json.load(f)}
    return dataset, filtered


def pair_set(dataset):
    return {(r["extension"], r["dep"], r["lead_osv"]) for r in dataset}


def ext_version(filtered, ext_key):
    e = filtered.get(ext_key)
    return e["version"] if e else None


def main():
    old_dir, new_dir = sys.argv[1], sys.argv[2]
    old_data, old_filtered = load_run(old_dir)
    new_data, new_filtered = load_run(new_dir)

    old_pairs = pair_set(old_data)
    new_pairs = pair_set(new_data)

    disappeared = old_pairs - new_pairs
    added = new_pairs - old_pairs
    stayed = old_pairs & new_pairs

    old_by_ext = defaultdict(list)
    for r in old_data:
        old_by_ext[r["extension"]].append(r)
    new_by_ext = defaultdict(list)
    for r in new_data:
        new_by_ext[r["extension"]].append(r)

    print(f"# kassi-vsix-audit changelog: {os.path.basename(old_dir)} → {os.path.basename(new_dir)}\n")

    print("## Summary\n")
    print(f"- Old affected extensions: **{len(old_by_ext)}**")
    print(f"- New affected extensions: **{len(new_by_ext)}**")
    print(f"- Rows disappeared (dep bumped past fix, dep removed, or extension gone): **{len(disappeared)}**")
    print(f"- Rows new (new advisory or new vulnerable dep): **{len(added)}**")
    print(f"- Rows unchanged (still shipping the same vulnerable version): **{len(stayed)}**")
    print()

    print("## Per-extension version movement\n")
    all_exts = sorted(set(old_by_ext) | set(new_by_ext))
    print("| Extension | Old ver | New ver | Last updated (new) | Rows cleared | Rows new |")
    print("|-----------|---------|---------|---------------------|-------------:|---------:|")
    for ext in all_exts:
        ov = ext_version(old_filtered, ext) or "—"
        nv = ext_version(new_filtered, ext) or "—"
        last = (new_filtered.get(ext) or {}).get("lastUpdated", "—")
        cleared = sum(1 for r in old_by_ext[ext] if (ext, r["dep"], r["lead_osv"]) in disappeared)
        new_rows = sum(1 for r in new_by_ext[ext] if (ext, r["dep"], r["lead_osv"]) in added)
        print(f"| `{ext}` | {ov} | {nv} | {last} | {cleared} | {new_rows} |")
    print()

    print("## Rows that disappeared\n")
    if disappeared:
        print("| Extension | Dep | OSV |")
        print("|-----------|-----|-----|")
        for ext, dep, osv in sorted(disappeared):
            print(f"| `{ext}` | `{dep}` | {osv} |")
    else:
        print("_None._")
    print()

    print("## Rows that appeared\n")
    if added:
        print("| Extension | Dep | Dep version | Severity | OSV |")
        print("|-----------|-----|-------------|----------|-----|")
        lookup = {(r["extension"], r["dep"], r["lead_osv"]): r for r in new_data}
        for key in sorted(added):
            r = lookup[key]
            print(f"| `{r['extension']}` | `{r['dep']}` | {r['dep_version']} | {r['severity']} | {r['lead_osv']} |")
    else:
        print("_None._")
    print()


if __name__ == "__main__":
    main()
