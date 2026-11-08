# kassi-vsix-audit

Static supply-chain audit of VS Code Marketplace extensions.

Downloads `.vsix` bundles from the Marketplace, enumerates every `node_modules/<pkg>/package.json` inside each bundle, batch-queries [OSV.dev](https://osv.dev) for known advisories, and ranks findings by `installs × severity`.

No API keys, no scanner install, stdlib Python only.

## Last run

**2026-11-08, top 100 non-first-party extensions by install count:**

- **19 / 100** extensions ship at least one known-CVE dependency
- **100** unique `(extension, dep, OSV)` findings
- Worst: `ritwickdey.LiveServer` (84M installs) — ships `websocket-driver 0.7.4` (CRITICAL [GHSA-xv26-6w52-cph6](https://github.com/advisories/GHSA-xv26-6w52-cph6)) on its live-reload code path

See [`SUMMARY.md`](./SUMMARY.md) for the full per-extension breakdown. The companion write-up with method, observations, and interpretation is [`ARTICLE.md`](./ARTICLE.md).

## Pipeline

Six short scripts, each solving one step. Run in order:

```bash
# 1. Pull top N extensions from Marketplace extensionquery API
python3 query_marketplace.py top200.json

# 2. Drop first-party (ms-*, vscjava, GitHub, …) and themes
python3 filter_publishers.py top200.json filtered.json

# 3. Download .vsix for top 100 non-first-party — 1 req/sec, ~1.5 GB
python3 download_vsix.py filtered.json 100 vsix/

# 4. Unpack each .vsix and OSV-query every shipped node_modules dep
python3 audit_extensions.py 'vsix/*.vsix' unpacked/ audit.json

# 5. Enrich with GHSA severity + install count; produce ranked.json
python3 rank_findings.py audit.json filtered.json ranked.json

# 6. Collapse into a markdown summary
python3 summarize.py ranked.json SUMMARY.md
```

End-to-end takes about 15 minutes on a decent connection: ~3 minutes downloading, ~5 minutes auditing, the rest trivial.

## What this is and is not

- It **is** a repeatable inventory of the frozen supply chain inside published extensions.
- It **is not** a vulnerability discovery tool — every finding is a published advisory from OSV. Discovery credit belongs to the original CVE reporters.
- A shipped vulnerable dep is not automatically exploitable. Reachability (does the extension's runtime actually hit the vulnerable code path?) has to be checked per finding; this tool does not do that.

## Dependencies

Python 3.9+, stdlib only. Nothing to install.

## License

MIT — see [`LICENSE`](./LICENSE).
