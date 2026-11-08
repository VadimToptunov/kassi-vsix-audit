# I audited the top 100 VS Code extensions for shipped CVEs. Here is what I found.

Spoiler: **19 out of 100** extensions ship at least one known-CVE dependency. The worst offender — Live Server, with 84 million installs — ships ten HIGH/CRITICAL advisories across its bundled `node_modules`, including a CRITICAL `websocket-driver` CVE that sits on the exact code path powering its live-reload feature.

This is not a 0-day discovery post. These are *published* CVEs sitting inside *published* extensions, and VS Code has no mechanism to tell you about them. The entire supply-chain layer below your editor is invisible.

## Why I ran this

Two reasons.

**Workspace Trust closed the easy extension attacks.** Since VS Code 1.57 (May 2021), any extension that does not declare `capabilities.untrustedWorkspaces` support is disabled when you open a repo marked untrusted. The classic "clone a malicious repo, press F5, get RCE via `.vscode/settings.json`" class — closed by core. If you are hunting extensions for direct exploits today, the ground has moved under you.

**But what is under the hood?** VS Code extensions ship their own `node_modules` inside the `.vsix` bundle. Whatever the maintainer `npm install`ed the day they published is frozen in. If that was three years ago, three years of npm advisories are still riding along with every install.

I wanted to know how bad the "frozen bundle" problem is in practice.

## Method

Reproducible in ~15 minutes with stdlib Python. No scanner marketing tier required.

**1. Pull the top 100 non-first-party extensions** from the Marketplace `extensionquery` API, sorted by install count. Filter out `ms-*`, `vscjava`, `VisualStudioExptTeam`, `GitHub`, and theme/language-pack entries. Keep code extensions where third parties own the supply chain.

**2. Download each `.vsix`** from the `/vspackage` endpoint. A `.vsix` is a zip. Gentle pacing at 1 req/sec; Marketplace is cooperative.

**3. Enumerate every `node_modules/<pkg>/package.json`** inside `extension/` after unzipping. Deduplicate by (name, version). For the top 100, this gave about 5,000 unique dependencies.

**4. Batch-query OSV.dev** at `/v1/querybatch` — 500 queries per request, free, no auth. OSV covers GHSA, so every npm advisory shows up. Collect every matched advisory.

**5. Rank by `installs × severity_weight`.** CRITICAL = 10, HIGH = 5, MODERATE = 2, LOW = 1. The top of the list is where either the install base is huge or the severity is deep — ideally both.

Five short Python files, ~250 lines in total. Three APIs: Marketplace's `extensionquery`, Marketplace's `/vspackage`, OSV's `querybatch`. No auth. No quota.

## Results

| # | Installs | Extension | Worst sev | Lead dep |
|---|---------:|-----------|-----------|----------|
| 1 | 84,254,316 | `ritwickdey.LiveServer` | CRITICAL | `websocket-driver 0.7.4` |
| 2 | 42,727,107 | `formulahendry.code-runner` | HIGH | `braces`, `picomatch` (ReDoS) |
| 3 | 19,651,537 | `christian-kohler.path-intellisense` | HIGH | `json5`, `minimatch` |
| 4 | 18,267,232 | `batisteo.vscode-django` | HIGH | `toml` |
| 5 | 15,805,395 | `xdebug.php-debug` | HIGH | `@xmldom/xmldom`, `moment` |
| 6 | 15,603,346 | `octref.vetur` | HIGH | `lodash`, `js-yaml`, `cross-spawn` |
| 7 | 13,517,697 | `oderwat.indent-rainbow` | CRITICAL | `decompress` (zip-slip), `koa` |
| 8 | 12,451,186 | `cschlosser.doxdocgen` | CRITICAL | `simple-git` (arg injection) |
| 9 | 10,683,614 | `HookyQR.beautify` | CRITICAL | `minimist` (prototype pollution) |
| 10 | 10,027,714 | `Zignd.html-css-class-completion` | CRITICAL | `form-data`, `json-schema` |
| 11 | 8,170,674 | `DotJoshJohnson.xml` | CRITICAL | `lodash`, `xmldom`, `minimist` |
| 12 | 7,479,892 | `platformio.platformio-ide` | CRITICAL | `tar` (symlink override) |
| 13 | 6,766,249 | `CoenraadS.bracket-pair-colorizer-2` | CRITICAL | `minimist` |

Rows 14-19 go down to about 5M installs and are all HIGH-or-below.

A few observations from the shape of this list.

**Install count is not a maintenance signal.** Live Server at 84M ships a CVE that has been fixed upstream since 2022. The author's last release to Marketplace is from 2022 too. Install count tells you lots of people use the thing. It tells you nothing about whether the thing receives updates.

**The deprecated-but-still-deployed problem.** Bracket Pair Colorizer 2 at 6.7M installs was formally deprecated two years ago — VS Code now colorizes bracket pairs natively. Those 6.7M installs still sit on disk, still load, still ship the `minimist` prototype-pollution vuln. VS Code does not uninstall deprecated extensions on your behalf.

**Lots of overlap on the same tired deps.** `brace-expansion`, `minimatch`, `braces`, `lodash`, `semver` show up across most of the affected extensions. One upstream fix, one maintainer release, five vulnerable extensions become clean. In practice, maintainers do not notice until someone emails them.

## Deep dive: Live Server

Worst finding by installs. Let me trace the chain.

`ritwickdey.LiveServer 5.7.10` ships `extension/node_modules/live-server/`. That is the npm package `live-server`, which the extension wraps. `live-server` depends on `faye-websocket`, which depends on `websocket-driver 0.7.4`.

[`GHSA-xv26-6w52-cph6`](https://github.com/advisories/GHSA-xv26-6w52-cph6) — `websocket-driver` parses extended payload frames in a way that lets a crafted frame crash the parser. CRITICAL. Fixed in `websocket-driver 0.7.5` (August 2022). The extension still ships 0.7.4.

Reachability: trivial. Live Server exists to run an HTTP + WebSocket dev server. The WebSocket branch IS the live-reload mechanism — every time you preview an HTML file, this code path is live. If you have ever enabled `liveServer.settings.useLocalIp` (a one-click checkbox) or set the host to `0.0.0.0`, the server is reachable from anywhere on your LAN, including the café wifi and your corporate guest network.

I am not claiming this as a bug I discovered. The CVE has been public for over three years. I am saying: the top-8 most-installed VS Code extension ships it unfixed to 84 million devs, and VS Code tells nobody.

## What VS Code could do

`npm audit` exists. `npm audit` is free. The Marketplace already runs malware scans on `.vsix` uploads. Adding a dependency audit to that pipeline would surface the top 20 findings on this list in an afternoon. The Marketplace page could carry a "known vulnerable dependencies: 10" badge next to the install button, like crates.io surfaces downstream security advisories.

I understand why Microsoft does not do this today. The signal-to-noise is uneven — a dev-only dep bundled accidentally produces a false positive, the extension author has to respond to the finding, and the Marketplace team does not own the problem. Still, the current equilibrium (`.vsix` is a frozen snapshot that ships forever with whatever advisories were quiet at publish time) is a slow drift toward a worse state over time.

## What maintainers can do

For anyone shipping a VS Code extension right now:

- `npm audit --production` before every `vsce package`. Most of the Criticals on this list would fail that check immediately.
- Bundle with `esbuild` or `webpack` with tree-shaking. The shipped `node_modules` is enormous and mostly dead code. Trimming it removes most of the false-positive dev-only CVEs and shrinks the `.vsix` substantially. Code Runner ships about 40 MB of `node_modules`; the actual extension code is 30 KB. The gap is where the noise lives.
- Commit `package-lock.json` to the extension repo and bump it monthly. Catches most of this before it ships.

## What users can do

Honest answer: not much. VS Code gives you no interface to see the dependency surface of an installed extension. The best options today:

- Do not install extensions you do not use. Boring advice. Also the only advice that works.
- Prefer extensions whose Marketplace page shows a recent "last updated" date. Anything untouched for over a year is a yellow flag for this class of issue.
- Keep Workspace Trust ON. It does not fix dependency CVEs but it gates the much worse "arbitrary RCE on repo open" class.

## Running it yourself

```
query_marketplace.py    # ~40 lines — Marketplace extensionquery
filter_publishers.py    # ~30 lines — drop first-party + themes
download_vsix.py        # ~50 lines — /vspackage, 1 req/sec
audit_extensions.py     # ~80 lines — OSV batch
summarize.py            # ~60 lines — rank + markdown
```

Running it quarterly against the top 100 is a useful ambient check on the ecosystem. Running it against the top 500 is the same thing with an hour-long download. I will probably do both and track how the shape changes over the next year.

Full per-extension breakdown with every (dep, version, advisory) row and the five scripts are in the companion repo: *[link TBD once the user publishes]*.

---

*I am Vadim Toptunov — I build security tooling and audit open-source code. Recent amplification-DoS work in `libvips`, `Pillow`, `cairosvg`, `tifffile`; CPU-DoS class in `python-markdown`, `pygments`, `marked`, `highlight.js`, `underscore`. Reach me at vtoptunov88@gmail.com.*
