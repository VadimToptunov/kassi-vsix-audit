# kassi-vsix-audit

Static supply-chain audit of VS Code Marketplace extensions.

Downloads `.vsix` bundles from the Marketplace, enumerates every `node_modules/<pkg>/package.json` inside each bundle, batch-queries [OSV.dev](https://osv.dev) for known advisories, and ranks findings by `installs × severity`.

No API keys, no scanner install, stdlib Python only.

## Last run

**2026-11-08, top 100 non-first-party, non-theme code extensions by install count:**

- **19 / 100** extensions ship at least one known-CVE dependency
- **1,357** nested dependency manifests enumerated across the 100 bundles (935 unique by `(name, version)`)
- **103** unique `(extension, dependency)` pairs with ≥1 matching advisory (a dep can match multiple advisories; one advisory can appear in many extensions, so this differs from the advisory-id count below)
- **149** unique OSV advisory IDs matched across those 103 pairs
- Severity breakdown of the 103 pairs, each counted once at its worst-severity advisory: **12 CRITICAL / 61 HIGH / 24 MODERATE / 6 LOW**
- Largest by install count: `ritwickdey.LiveServer` (84M) bundles `websocket-driver 0.7.4` (CRITICAL [GHSA-xv26-6w52-cph6](https://github.com/advisories/GHSA-xv26-6w52-cph6), published 2026-07-15)

Every finding above is at evidence level **Present** (the vulnerable `(name, version)` is inside the shipped bundle). Reachable / Exploitable are not claimed. See [`ARTICLE.md`](./ARTICLE.md) § "Levels of evidence" and § "Limitations" — in particular, 64 of the 100 sampled extensions had zero shipped `node_modules` entries (mostly bundled with esbuild/webpack/rollup), so 19 / 100 is a lower bound on detectable findings in this sample, not an ecosystem prevalence estimate.

Full per-extension breakdown: [`SUMMARY.md`](./SUMMARY.md). Flat row-per-row dataset: [`DATASET.csv`](./DATASET.csv). Writeup: [`ARTICLE.md`](./ARTICLE.md). Pinned snapshot inputs/outputs: [`runs/2026-11-08/`](./runs/2026-11-08/).

## Longitudinal plan

The intent is to re-run this quarterly (next: **2027-02-08**) and compare snapshots to measure:

- how many of the affected extensions published a new release in the window;
- how many old `(ext, dep, advisory)` rows disappeared (dep bumped past fix, dep removed, extension unpublished);
- how many new rows appeared (new advisory on an already-shipped dep, or a newly-shipped vulnerable dep);
- for each advisory, time between its publish date and the first extension release that cleared it (ecosystem response time).

Each run pins its inputs and outputs under `runs/<YYYY-MM-DD>/`. `diff_runs.py` takes two run directories and emits a markdown changelog:

```bash
python3 diff_runs.py runs/2026-11-08 runs/2027-02-08 > CHANGELOG.md
```

Keep the pinned `top200.json` (raw Marketplace response), `filtered.json` (sampled extensions with `lastUpdated` timestamps), `audit.json` (raw OSV matches), `ranked.json` (enriched), and `DATASET.csv` (flat) for each run so historical diffs remain reproducible.

## Pipeline

Six short scripts, each solving one step. Run in order:

```bash
# 1. Pull top N extensions from Marketplace extensionquery API
python3 query_marketplace.py top200.json

# 2. Drop first-party (ms-*, vscjava, GitHub, …) and themes
python3 filter_publishers.py top200.json filtered.json

# 3. Download .vsix for top 100 non-first-party — 1 req/sec, ~1.6 GB
python3 download_vsix.py filtered.json 100 vsix/

# 4. Unpack each .vsix and OSV-query every shipped node_modules dep
python3 audit_extensions.py 'vsix/*.vsix' unpacked/ audit.json

# 5. Enrich with GHSA severity + install count; produce ranked.json
python3 rank_findings.py audit.json filtered.json ranked.json

# 6. Collapse into a markdown summary
python3 summarize.py ranked.json SUMMARY.md
```

End-to-end takes about 15 minutes on a decent connection: ~3 minutes downloading, ~5 minutes auditing, the rest trivial. The `osv_cache.json` file produced by `rank_findings.py` is a local cache of OSV `/v1/vulns/<id>` responses; delete it to force a fresh fetch.

## What this is and is not

- It **is** a repeatable inventory of the frozen supply chain inside published extensions.
- It **is not** a vulnerability discovery tool — every finding is a published advisory from OSV. Discovery credit belongs to the original CVE reporters.
- A shipped vulnerable dep is not automatically exploitable. Reachability (does the extension's runtime actually hit the vulnerable code path?) has to be checked per finding; this tool does not do that.

## Dependencies

Python 3.9+, stdlib only. Nothing to install.

## License

MIT — see [`LICENSE`](./LICENSE).
