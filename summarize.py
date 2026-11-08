#!/usr/bin/env python3
"""Collapse ranked findings into one row per (ext, dep, lead_osv) and produce a markdown summary."""
import json
import sys
from collections import defaultdict

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}


def main():
    ranked = json.load(open(sys.argv[1]))
    # dedupe: same (ext, dep, lead_osv) counted once; keep worst severity
    seen = {}
    for r in ranked:
        key = (r["ext"], r["dep"], r["lead_osv"])
        prior = seen.get(key)
        if not prior or SEV_ORDER.get(r["severity"], 9) < SEV_ORDER.get(prior["severity"], 9):
            seen[key] = r
    rows = list(seen.values())

    # group by ext
    by_ext = defaultdict(list)
    for r in rows:
        by_ext[r["ext"]].append(r)
    for ext in by_ext:
        by_ext[ext].sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["dep"]))

    ranked_exts = sorted(
        by_ext.keys(),
        key=lambda e: (
            -by_ext[e][0]["installs"],
            SEV_ORDER.get(by_ext[e][0]["severity"], 9),
        ),
    )

    md = ["# VS Code top-100 supply-chain audit (2026-11-08)",
          "",
          "Static scan of top 100 non-first-party VS Code extensions (by install count) for shipped "
          "node_modules deps with known OSV advisories. Unpacked each `.vsix`, enumerated every "
          "`node_modules/<pkg>/package.json`, batch-queried api.osv.dev.",
          "",
          f"**Extensions affected:** {len(by_ext)} / 100",
          f"**Total unique (ext, dep, OSV) findings:** {len(rows)}",
          "",
          "## Ranked by (install count, worst severity)",
          "",
          "| # | Installs | Ext | Worst sev | Vulnerable deps |",
          "|---|---------:|-----|-----------|-----------------|"]
    for i, ext in enumerate(ranked_exts, 1):
        top = by_ext[ext][0]
        deps_line = ", ".join(
            f"`{r['dep']}` ({r['severity']})"
            for r in by_ext[ext][:6]
        )
        if len(by_ext[ext]) > 6:
            deps_line += f" +{len(by_ext[ext]) - 6} more"
        md.append(f"| {i} | {top['installs']:>12,} | `{ext}` | {top['severity']} | {deps_line} |")

    md += ["",
           "## Per-extension detail",
           ""]
    for ext in ranked_exts:
        installs = by_ext[ext][0]["installs"]
        md.append(f"### `{ext}` — {installs:,} installs")
        md.append("")
        md.append("| Sev | Dep | Version | OSV |")
        md.append("|-----|-----|---------|-----|")
        for r in by_ext[ext]:
            md.append(f"| {r['severity']} | `{r['dep']}` | {r['version']} | "
                      f"[{r['lead_osv']}](https://osv.dev/vulnerability/{r['lead_osv']}) |")
        md.append("")

    out = sys.argv[2] if len(sys.argv) > 2 else "SUMMARY.md"
    with open(out, "w") as f:
        f.write("\n".join(md))
    print(f"wrote {out}: {len(by_ext)} ext, {len(rows)} findings")


if __name__ == "__main__":
    main()
