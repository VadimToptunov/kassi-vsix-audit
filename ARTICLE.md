# I audited the top 100 third-party VS Code extensions for shipped CVEs. Here is what I found.

Spoiler: **19 out of 100** sampled extensions ship at least one known-CVE dependency inside their `.vsix` bundle. The one with the largest install base — Live Server, 84 million installs — bundles `websocket-driver 0.7.4` (CRITICAL [GHSA-xv26-6w52-cph6](https://github.com/advisories/GHSA-xv26-6w52-cph6) / CVE-2026-54466).

I want to be precise about what that sentence does and does not claim. This is a static inventory of what is shipped. It is not a dynamic exploitation study. The strongest evidence level for any finding below is **"the vulnerable version is present inside the extension bundle"** — see "Levels of evidence" further down. VS Code gives users no interface for seeing the bundled dependency surface of what they install; that invisibility is the actual topic of the post.

## Why I ran this

Two reasons.

**Workspace Trust mitigated the easiest extension attacks.** Since VS Code 1.57 (May 2021), any extension that does not declare `capabilities.untrustedWorkspaces` support is disabled when you open a repo marked untrusted. The classic "clone a malicious repo, press F5, get RCE via `.vscode/settings.json`" class is now gated behind the user's trust decision. The gate is not absolute — a user who clicks "Trust" through habit re-opens the surface, extensions that declare support run anyway, and the check does not reach dependency CVEs — but it meaningfully reduced the easy path.

**But what is under the hood?** VS Code extensions ship their own `node_modules` inside the `.vsix` bundle. Whatever the maintainer `npm install`ed the day they published is frozen in. Advisories published after that release never propagate backwards; there is no mechanism in the Marketplace or in VS Code itself that tells either the maintainer or the user "an advisory now applies to something you shipped three months ago." That's the frozen-bundle problem.

I wanted to measure it.

## Method

Reproducible in ~15 minutes with stdlib Python. No scanner install required.

**Snapshot:** Marketplace and OSV queried on **2026-11-08**. Install counts and advisory data are from that date; both change over time.

**1. Pull the top 200 extensions** from the Marketplace `extensionquery` API, sorted by install count.

**2. Filter the sample.** Drop first-party publishers (`ms-*`, `vscjava`, `VisualStudioExptTeam`, `MicrosoftDocs`, `redhat`, `Microsoft`, `MS-CEINTL`), `GitHub`, and anything whose name or display title contains `language-pack`, `icon-theme`, `material-theme`, `vscode-icons`, `theme`, `keybindings`, or `cheatsheet`. From 200 raw entries this kept 116; I took the top 100 by install count. The precise phrase is **"top 100 non-first-party, non-theme code extensions by install count on 2026-11-08"**, not "top 100 extensions on the Marketplace".

**3. Download each `.vsix`** from the `/vspackage` endpoint. A `.vsix` is a zip. Gentle pacing at 1 req/sec. All 100 downloads succeeded (~1.6 GB total).

**4. Enumerate every `node_modules/<pkg>/package.json`** inside `extension/` after unzipping. For the top 100 this gave **1,357 nested dependency manifests** — of which **935 were unique by `(name, version)`** (712 unique package names, many shipped in two or more extensions at the same version).

**5. Batch-query OSV.dev** at `/v1/querybatch` — 500 queries per request, free, no auth. OSV covers GHSA, so every npm advisory shows up. Collect every matched advisory.

**6. Score and rank.** For each `(extension, dependency, advisory)` row I keep the worst severity and compute `score = installs × severity_weight` with `CRITICAL=10, HIGH=5, MODERATE=2, LOW=1`. The results table below is sorted by install count — most-shipped at the top. The `score` column is in the companion CSV for anyone who wants to re-rank.

**Affected** means: at least one `(dependency, version)` pair inside the extension bundle has a matching OSV advisory of any severity. It does not imply the code path is loaded at runtime, that user input can reach it, or that any impact is realised.

Six Python files, 527 lines total, stdlib only. Three APIs: Marketplace's `extensionquery`, Marketplace's `/vspackage`, OSV's `querybatch`. No auth. No quota.

## Results

Three different counts, because the numbers answer three different questions:

- **19 / 100** sampled extensions had at least one `(dependency, version)` inside their bundle matching an OSV advisory.
- **103** unique `(extension, dependency)` pairs with ≥1 matching advisory. A single `(extension, dependency)` pair can match multiple advisories — a dep may have several open advisories or be below more than one fix threshold — so this is less than the total advisory matches.
- **149** unique OSV advisory IDs across those 103 pairs. One advisory often shows up in many extensions (`lodash`, `minimatch`, `braces`, `brace-expansion`, `semver` are the serial offenders), so advisory-id-count and pair-count diverge.
- Severity breakdown of the 103 pairs, each counted once at its worst-severity advisory: **12 CRITICAL**, **61 HIGH**, **24 MODERATE**, **6 LOW**.

Sorted by install count on the snapshot date. "Worst sev" is the maximum severity across all matched advisories inside that extension's bundle.

| # | Installs | Extension | Worst sev | Lead deps (abridged) |
|---|---------:|-----------|-----------|----------------------|
| 1 | 84,254,316 | `ritwickdey.LiveServer` | CRITICAL | `websocket-driver 0.7.4`, `braces`, `lodash`, `js-yaml`, +14 more |
| 2 | 42,727,107 | `formulahendry.code-runner` | HIGH | `braces`, `picomatch` (ReDoS class) |
| 3 | 19,651,537 | `christian-kohler.path-intellisense` | HIGH | `json5`, `minimatch`, `brace-expansion` |
| 4 | 18,267,232 | `batisteo.vscode-django` | HIGH | `toml` |
| 5 | 15,805,395 | `xdebug.php-debug` | HIGH | `@xmldom/xmldom`, `moment`, `brace-expansion` |
| 6 | 15,603,346 | `octref.vetur` | HIGH | `lodash`, `js-yaml`, `cross-spawn`, +3 more |
| 7 | 15,369,970 | `EditorConfig.EditorConfig` | HIGH | `brace-expansion`, `minimatch` |
| 8 | 13,517,697 | `oderwat.indent-rainbow` | CRITICAL | `decompress` (zip-slip), `koa`, +4 more |
| 9 | 12,451,186 | `cschlosser.doxdocgen` | CRITICAL | `simple-git`, `moment` |
| 10 | 10,683,614 | `HookyQR.beautify` | CRITICAL | `minimist` (proto pollution), +4 more |
| 11 | 10,027,714 | `Zignd.html-css-class-completion` | CRITICAL | `form-data`, `json-schema`, `lodash`, +3 more |
| 12 | 9,742,813 | `naumovs.color-highlight` | HIGH | `brace-expansion`, `minimatch` |
| 13 | 8,170,674 | `DotJoshJohnson.xml` | CRITICAL | `lodash`, `minimist`, `xmldom`, +3 more |
| 14 | 7,479,892 | `platformio.platformio-ide` | CRITICAL | `tar` (symlink override), +5 more |
| 15 | 6,766,249 | `CoenraadS.bracket-pair-colorizer-2` | CRITICAL | `minimist`, `json5` |
| 16 | 6,696,727 | `Oracle.oracle-java` | HIGH | `brace-expansion`, `fast-uri` |
| 17 | 6,140,258 | `zobo.php-intellisense` | HIGH | `brace-expansion`, `cross-spawn`, `minimatch` |
| 18 | 5,887,595 | `James-Yu.latex-workshop` | MODERATE | `glob`, `minimatch` |
| 19 | 5,517,213 | `steoates.autoimport` | HIGH | `lodash` |

Full per-extension, per-advisory breakdown with versions and OSV IDs is in `SUMMARY.md` and `DATASET.csv` in the companion repo.

## Levels of evidence

The headline number is **Present**, not **Exploitable**. The distinction matters, and most writeups in this space blur it.

| Level | What has been established |
|---|---|
| **Present** | A vulnerable `(name, version)` pair is in the shipped bundle |
| **Loaded** | The extension's runtime actually loads this copy of the module |
| **Reachable** | A code path that reaches the vulnerable code is exercised during normal use |
| **Exploitable** | An adversary-controlled input reaches the vulnerable code in a reproduced PoC |

Every number in the Results table is **Present**. For a few deps I believe **Loaded** is very likely from static reading, but I did not instrument the extensions to prove it. **Reachable** and **Exploitable** are not claimed for any row.

Publishing at Present is still worth it: the frozen-bundle pattern is a measurable property of the ecosystem, and 19 / 100 is a baseline you can compare future runs against. Upgrading individual rows to higher evidence levels is per-extension work, not a batch job.

## A closer look at Live Server

The highest-install row in the table. Tracing it as far as the static scan allows.

`ritwickdey.LiveServer 5.7.10` ships `extension/node_modules/live-server/`. That is the `live-server` npm package, which the extension wraps as its HTTP + live-reload server. `live-server` depends on `faye-websocket`, which depends on `websocket-driver 0.7.4` — present under `extension/node_modules/websocket-driver/`.

[`GHSA-xv26-6w52-cph6`](https://github.com/advisories/GHSA-xv26-6w52-cph6) / **CVE-2026-54466** — *"websocket-driver: Message corruption via abuse of protocol length headers"*. Severity **critical** per the GitHub Advisory API. Vulnerable range: `< 0.7.5`; first patched version: `0.7.5`. Advisory **published on 2026-07-15** (cross-checked against the GitHub Advisory API on 2026-11-08).

Here's the interesting part of the chronology. Live Server v5.7.10 was last updated on the Marketplace on **2026-02-27** — about five months *before* the GHSA on `websocket-driver` was published. The maintainer wasn't ignoring a known advisory at the time they shipped. The advisory simply did not exist yet.

This is the frozen-bundle problem in one case study. A reasonable `npm install` on 2026-02-27 picks up `websocket-driver 0.7.4`, which was not under any OSV advisory at the time. Five months later an advisory is filed against that version. The bundle on disk does not change. I could not find a publicly documented, user-visible Marketplace mechanism that re-scans already-published `.vsix` artefacts against new OSV rows or notifies the publisher when a matching advisory appears; corrections welcome if one exists.

How far I can go on reachability without a PoC: `faye-websocket` is `live-server`'s WebSocket layer, and the live-reload channel is the extension's headline feature, so it is likely that this copy of `websocket-driver` is loaded when Live Server is running. I did not instrument Live Server to confirm module load; I did not attempt a crafted-frame reproduction. **Potentially reachable, verified present, unverified reachable or exploitable.** If someone wants to do the dynamic work and confirm or refute the Reachable / Exploitable claim, the repo has everything needed to reproduce the inventory and I would be glad to link verified follow-ups.

Static takeaway: an extension ranked 8th by installs on the unfiltered Marketplace on 2026-11-08 (and 1st in this filtered third-party sample) ships a CRITICAL advisory on a module that sits under its headline feature, four months after the advisory was filed, and nothing in the install flow tells the user.

## Three observations from the shape of this list

**Install count is not a maintenance signal.** 84M installs doesn't mean anyone upstream is watching the advisory feed on your behalf. It means a lot of people downloaded the thing once. The maintainer may or may not be active — in Live Server's case they shipped a release about eight months before this snapshot, and the vulnerable dep is still there because the advisory postdates that release.

**The still-on-disk-after-dormancy problem.** Bracket Pair Colorizer 2 was last updated on the Marketplace in March 2022. VS Code has shipped native bracket pair colorization in the core editor since 2021 (`editor.bracketPairColorization.enabled`). The extension's 6.7M installs still sit on users' machines, still load on VS Code startup if enabled, still ship `minimist` with a CRITICAL prototype-pollution advisory. VS Code does not uninstall dormant extensions on your behalf.

**Lots of overlap on the same tired deps.** `brace-expansion`, `minimatch`, `braces`, `lodash`, `semver` show up across most of the affected extensions. One upstream fix, one maintainer release, several vulnerable extensions become clean. In practice, maintainers don't notice until someone emails them.

## The size side of the problem

Not every extension ships a big bundle, but the ones that do carry a lot of dead surface along for the ride. Live Server's unpacked `extension/` directory is **30 MB**, and almost all of that is `extension/node_modules/`. The actual Live Server glue code — the TypeScript that bridges `live-server` into the VS Code extension API — is tiny; the bulk is transitive dependencies dragged in by the npm resolver.

This is where bundling with `esbuild` or `webpack` with tree-shaking helps: the shipped artifact only contains code reachable from the entry points. It is not a silver bullet — a transitive dep that *is* called stays in the bundle, and the vulnerable code path inside it still ships — but it typically shrinks both the bundle and the matched-advisory count.

For comparison: Code Runner's whole unpacked tree is 1.8 MB (1.2 MB of `node_modules`). Still shipping two HIGH advisories, but far less dead surface by volume.

## What VS Code could do

OSV's `/v1/querybatch` is free. The Marketplace already runs malware scans on `.vsix` uploads. Running OSV against the shipped `node_modules` of a `.vsix` on upload — exactly what the scripts in the repo do — would surface the top-20 findings on this list in an afternoon.

More importantly, the same scan could run periodically against already-published `.vsix` artefacts and notify the publisher when a new advisory applies, which addresses the frozen-bundle chronology directly. A count surfaced on the public install page would let users factor it into their choice. That is the kind of backfill mechanism I could not find in the public Marketplace feature set at the snapshot date.

I am not inside Microsoft's processes, and there may be reasons this is harder than it looks from the outside: signal-to-noise is uneven, the extension author has to respond, and reachability is a per-extension question. The point stands at the ecosystem level: the `.vsix` is a frozen snapshot that ships forever with whatever advisories were quiet at publish time, and silently acquires new ones as time passes.

## What maintainers can do

For anyone shipping a VS Code extension right now:

- **Audit the final `.vsix`, not just the source tree.** `npm audit` against your working copy reports what's in your lockfile — that is a source-tree check and is not the same as an inventory of what shipped. The reliable artifact-level audit is: package with `vsce package`, unzip the result, enumerate every `(name, version)` pair under `extension/node_modules/*/package.json` (and the `@scope/name` variant), and query OSV. That is exactly what `audit_extensions.py` in the repo does, and the ~110 lines around that pipeline are the useful piece to copy into your own release workflow.
- **Bundle with `esbuild` or `webpack`.** Shipped `node_modules` directories are often large and contain code the extension never calls. Bundling and tree-shaking typically reduces both size and the number of surfaced advisories. It is not a guarantee: a transitive dep the extension *does* call is still bundled, and the vulnerable code path inside that call chain is still shipped. Measure the audit output before and after; do not assume the number went to zero.
- **Re-audit already-published releases on a schedule.** The chronology in the Live Server case study — advisory published five months after the release — is not unusual. A quarterly re-check of your already-published `.vsix` against OSV catches advisories that appear after you ship. Treat it as the backfill the Marketplace does not provide.

## What users can do

Honest answer: not much, today.

- Do not install extensions you do not use. Boring advice. It's also the only advice that works.
- Prefer extensions whose Marketplace page shows a recent "last updated" date. A long-stale date is a yellow flag for dependency staleness. Recent activity isn't a clean bill of health — Live Server was updated about eight months before this snapshot and still ships a CRITICAL — but a long gap is clearly worse.
- Keep Workspace Trust ON. It does not address dependency CVEs, but it gates the much worse "arbitrary RCE on repo open" class behind an explicit prompt.

## Running it yourself

```
query_marketplace.py     87 lines — Marketplace extensionquery
filter_publishers.py     49 lines — drop first-party + themes
download_vsix.py         61 lines — /vspackage, 1 req/sec
audit_extensions.py     137 lines — unpack + OSV batch
rank_findings.py        113 lines — enrich with GHSA severity
summarize.py             80 lines — collapse + markdown
                        ---
                        527 lines — stdlib only
```

Running it quarterly against the top 100 is a useful ambient check. Running against the top 500 is the same with an hour-long download. I'll probably do both and track the shape over the next year.

Full per-extension breakdown with every `(dep, version, advisory)` row, the CSV dataset, and the six scripts are in the companion repo:

**https://github.com/vadimtoptunov/kassi-vsix-audit**

---

*Vadim Toptunov — security tooling and open-source audit. Contact: vtoptunov88@gmail.com.*
