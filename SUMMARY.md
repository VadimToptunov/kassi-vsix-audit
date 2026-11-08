# VS Code top-100 supply-chain audit (2026-11-08)

Static scan of top 100 non-first-party VS Code extensions (by install count) for shipped node_modules deps with known OSV advisories. Unpacked each `.vsix`, enumerated every `node_modules/<pkg>/package.json`, batch-queried api.osv.dev.

**Extensions affected:** 19 / 100
**Total unique (ext, dep, OSV) findings:** 100

## Ranked by (install count, worst severity)

| # | Installs | Ext | Worst sev | Vulnerable deps |
|---|---------:|-----|-----------|-----------------|
| 1 |   84,254,316 | `ritwickdey.LiveServer` | CRITICAL | `websocket-driver` (CRITICAL), `brace-expansion` (HIGH), `braces` (HIGH), `js-yaml` (HIGH), `lodash` (HIGH), `minimatch` (HIGH) +13 more |
| 2 |   42,727,107 | `formulahendry.code-runner` | HIGH | `braces` (HIGH), `picomatch` (HIGH), `micromatch` (MODERATE) |
| 3 |   19,651,537 | `christian-kohler.path-intellisense` | HIGH | `brace-expansion` (HIGH), `json5` (HIGH), `minimatch` (HIGH) |
| 4 |   18,267,232 | `batisteo.vscode-django` | HIGH | `toml` (HIGH) |
| 5 |   15,805,395 | `xdebug.php-debug` | HIGH | `@xmldom/xmldom` (HIGH), `brace-expansion` (HIGH), `minimatch` (MODERATE), `moment` (MODERATE) |
| 6 |   15,603,346 | `octref.vetur` | HIGH | `brace-expansion` (HIGH), `cross-spawn` (HIGH), `flatted` (HIGH), `js-yaml` (HIGH), `lodash` (HIGH), `minimatch` (HIGH) +5 more |
| 7 |   15,369,970 | `EditorConfig.EditorConfig` | HIGH | `brace-expansion` (HIGH), `minimatch` (MODERATE) |
| 8 |   13,517,697 | `oderwat.indent-rainbow` | CRITICAL | `decompress` (CRITICAL), `koa` (CRITICAL), `brace-expansion` (HIGH), `extract-zip` (HIGH), `jpeg-js` (HIGH), `minimatch` (HIGH) +6 more |
| 9 |   12,451,186 | `cschlosser.doxdocgen` | CRITICAL | `simple-git` (CRITICAL), `moment` (HIGH) |
| 10 |   10,683,614 | `HookyQR.beautify` | CRITICAL | `minimist` (CRITICAL), `brace-expansion` (HIGH), `ini` (HIGH), `minimatch` (HIGH), `semver` (HIGH) |
| 11 |   10,027,714 | `Zignd.html-css-class-completion` | CRITICAL | `form-data` (CRITICAL), `json-schema` (CRITICAL), `decode-uri-component` (HIGH), `lodash` (HIGH), `qs` (HIGH), `ajv` (MODERATE) +3 more |
| 12 |    9,742,813 | `naumovs.color-highlight` | HIGH | `brace-expansion` (HIGH), `minimatch` (HIGH), `@babel/runtime` (MODERATE) |
| 13 |    8,170,674 | `DotJoshJohnson.xml` | CRITICAL | `lodash` (CRITICAL), `minimist` (CRITICAL), `xmldom` (CRITICAL), `ansi-regex` (HIGH), `cross-spawn` (HIGH), `dot-prop` (HIGH) +3 more |
| 14 |    7,479,892 | `platformio.platformio-ide` | CRITICAL | `tar` (CRITICAL), `brace-expansion` (HIGH), `glob` (HIGH), `minimatch` (HIGH), `underscore` (HIGH), `ws` (HIGH) +1 more |
| 15 |    6,766,249 | `CoenraadS.bracket-pair-colorizer-2` | CRITICAL | `minimist` (CRITICAL), `json5` (HIGH) |
| 16 |    6,696,727 | `Oracle.oracle-java` | HIGH | `brace-expansion` (HIGH), `fast-uri` (MODERATE) |
| 17 |    6,140,258 | `zobo.php-intellisense` | HIGH | `brace-expansion` (HIGH), `cross-spawn` (HIGH), `minimatch` (HIGH) |
| 18 |    5,887,595 | `James-Yu.latex-workshop` | MODERATE | `glob` (MODERATE), `minimatch` (MODERATE) |
| 19 |    5,517,213 | `steoates.autoimport` | HIGH | `lodash` (HIGH) |

## Per-extension detail

### `ritwickdey.LiveServer` — 84,254,316 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `websocket-driver` | 0.7.4 | [GHSA-xv26-6w52-cph6](https://osv.dev/vulnerability/GHSA-xv26-6w52-cph6) |
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `braces` | 3.0.2 | [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) |
| HIGH | `js-yaml` | 3.14.1 | [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) |
| HIGH | `lodash` | 4.17.21 | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) |
| HIGH | `minimatch` | 3.1.2 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| HIGH | `picomatch` | 2.3.1 | [GHSA-c2c7-rcm5-vvqj](https://osv.dev/vulnerability/GHSA-c2c7-rcm5-vvqj) |
| HIGH | `semver` | 5.7.1 | [GHSA-c2qf-rxjj-qqgw](https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw) |
| HIGH | `shelljs` | 0.7.8 | [GHSA-4rq4-32rv-6wp6](https://osv.dev/vulnerability/GHSA-4rq4-32rv-6wp6) |
| HIGH | `trim-newlines` | 1.0.0 | [GHSA-7p7h-4mm5-852v](https://osv.dev/vulnerability/GHSA-7p7h-4mm5-852v) |
| MODERATE | `ajv` | 4.11.8 | [GHSA-2g4f-4pwh-qvx6](https://osv.dev/vulnerability/GHSA-2g4f-4pwh-qvx6) |
| MODERATE | `follow-redirects` | 1.14.9 | [GHSA-cxjh-pqwp-8mfp](https://osv.dev/vulnerability/GHSA-cxjh-pqwp-8mfp) |
| MODERATE | `got` | 5.6.0 | [GHSA-pfrx-2q88-qq97](https://osv.dev/vulnerability/GHSA-pfrx-2q88-qq97) |
| MODERATE | `morgan` | 1.10.0 | [GHSA-4vj7-5mj6-jm8m](https://osv.dev/vulnerability/GHSA-4vj7-5mj6-jm8m) |
| MODERATE | `uuid` | 3.4.0 | [GHSA-w5hq-g745-h8pq](https://osv.dev/vulnerability/GHSA-w5hq-g745-h8pq) |
| MODERATE | `word-wrap` | 1.2.3 | [GHSA-j8xg-fqg3-53r7](https://osv.dev/vulnerability/GHSA-j8xg-fqg3-53r7) |
| LOW | `es5-ext` | 0.10.53 | [GHSA-4gmj-3p3h-gm8h](https://osv.dev/vulnerability/GHSA-4gmj-3p3h-gm8h) |
| LOW | `on-headers` | 1.0.2 | [GHSA-76c9-3jph-rj3q](https://osv.dev/vulnerability/GHSA-76c9-3jph-rj3q) |
| LOW | `send` | 0.17.2 | [GHSA-m6fv-jmcg-4jfg](https://osv.dev/vulnerability/GHSA-m6fv-jmcg-4jfg) |

### `formulahendry.code-runner` — 42,727,107 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `braces` | 3.0.2 | [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) |
| HIGH | `picomatch` | 2.0.7 | [GHSA-c2c7-rcm5-vvqj](https://osv.dev/vulnerability/GHSA-c2c7-rcm5-vvqj) |
| MODERATE | `micromatch` | 4.0.2 | [GHSA-952p-6rrq-rcjv](https://osv.dev/vulnerability/GHSA-952p-6rrq-rcjv) |

### `christian-kohler.path-intellisense` — 19,651,537 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `json5` | 2.2.0 | [GHSA-9c47-m6qq-7p4h](https://osv.dev/vulnerability/GHSA-9c47-m6qq-7p4h) |
| HIGH | `minimatch` | 3.0.4 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |

### `batisteo.vscode-django` — 18,267,232 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `toml` | 3.0.0 | [GHSA-4qx8-w7c3-pj3p](https://osv.dev/vulnerability/GHSA-4qx8-w7c3-pj3p) |

### `xdebug.php-debug` — 15,805,395 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `@xmldom/xmldom` | 0.9.10 | [GHSA-27p8-2357-5qqv](https://osv.dev/vulnerability/GHSA-27p8-2357-5qqv) |
| HIGH | `brace-expansion` | 5.0.5 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| MODERATE | `minimatch` | 10.2.3 | [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) |
| MODERATE | `moment` | 2.30.1 | [GHSA-4p3w-j4w9-5jqw](https://osv.dev/vulnerability/GHSA-4p3w-j4w9-5jqw) |

### `octref.vetur` — 15,603,346 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `cross-spawn` | 7.0.3 | [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) |
| HIGH | `flatted` | 3.1.0 | [GHSA-25h7-pfq9-p65f](https://osv.dev/vulnerability/GHSA-25h7-pfq9-p65f) |
| HIGH | `js-yaml` | 4.1.0 | [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) |
| HIGH | `lodash` | 4.17.21 | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) |
| HIGH | `minimatch` | 3.1.2 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| HIGH | `semver` | 7.3.8 | [GHSA-c2qf-rxjj-qqgw](https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw) |
| MODERATE | `ajv` | 6.12.4 | [GHSA-2g4f-4pwh-qvx6](https://osv.dev/vulnerability/GHSA-2g4f-4pwh-qvx6) |
| MODERATE | `postcss-selector-parser` | 6.0.11 | [GHSA-rj75-hqrm-r3gf](https://osv.dev/vulnerability/GHSA-rj75-hqrm-r3gf) |
| MODERATE | `word-wrap` | 1.2.3 | [GHSA-j8xg-fqg3-53r7](https://osv.dev/vulnerability/GHSA-j8xg-fqg3-53r7) |
| LOW | `diff` | 4.0.2 | [GHSA-73rr-hh4g-fpgx](https://osv.dev/vulnerability/GHSA-73rr-hh4g-fpgx) |

### `EditorConfig.EditorConfig` — 15,369,970 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 5.0.5 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| MODERATE | `minimatch` | 10.2.5 | [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) |

### `oderwat.indent-rainbow` — 13,517,697 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `decompress` | 4.2.1 | [GHSA-hrh2-vp3x-79xf](https://osv.dev/vulnerability/GHSA-hrh2-vp3x-79xf) |
| CRITICAL | `koa` | 2.13.1 | [GHSA-593f-38f6-jp5m](https://osv.dev/vulnerability/GHSA-593f-38f6-jp5m) |
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `extract-zip` | 2.0.1 | [GHSA-7pqw-9j4j-h8q3](https://osv.dev/vulnerability/GHSA-7pqw-9j4j-h8q3) |
| HIGH | `jpeg-js` | 0.4.3 | [GHSA-xvf7-4v9q-58w6](https://osv.dev/vulnerability/GHSA-xvf7-4v9q-58w6) |
| HIGH | `minimatch` | 3.0.4 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| HIGH | `path-to-regexp` | 6.2.0 | [GHSA-9wv6-86v2-598j](https://osv.dev/vulnerability/GHSA-9wv6-86v2-598j) |
| HIGH | `playwright` | 1.15.0 | [GHSA-7mvr-c777-76hp](https://osv.dev/vulnerability/GHSA-7mvr-c777-76hp) |
| HIGH | `ws` | 7.5.5 | [GHSA-3h5v-q93c-6h6q](https://osv.dev/vulnerability/GHSA-3h5v-q93c-6h6q) |
| MODERATE | `morgan` | 1.10.0 | [GHSA-4vj7-5mj6-jm8m](https://osv.dev/vulnerability/GHSA-4vj7-5mj6-jm8m) |
| LOW | `@tootallnate/once` | 1.1.2 | [GHSA-vpq2-c234-7xj6](https://osv.dev/vulnerability/GHSA-vpq2-c234-7xj6) |
| LOW | `on-headers` | 1.0.2 | [GHSA-76c9-3jph-rj3q](https://osv.dev/vulnerability/GHSA-76c9-3jph-rj3q) |

### `cschlosser.doxdocgen` — 12,451,186 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `simple-git` | 2.38.0 | [GHSA-9w5j-4mwv-2wj8](https://osv.dev/vulnerability/GHSA-9w5j-4mwv-2wj8) |
| HIGH | `moment` | 2.29.1 | [GHSA-8hfj-j24r-96c4](https://osv.dev/vulnerability/GHSA-8hfj-j24r-96c4) |

### `HookyQR.beautify` — 10,683,614 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `minimist` | 0.0.8 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) |
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `ini` | 1.3.5 | [GHSA-qqgx-2p2h-9c37](https://osv.dev/vulnerability/GHSA-qqgx-2p2h-9c37) |
| HIGH | `minimatch` | 3.0.4 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| HIGH | `semver` | 5.6.0 | [GHSA-c2qf-rxjj-qqgw](https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw) |

### `Zignd.html-css-class-completion` — 10,027,714 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `form-data` | 2.3.3 | [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) |
| CRITICAL | `json-schema` | 0.2.3 | [GHSA-896r-f27r-55mw](https://osv.dev/vulnerability/GHSA-896r-f27r-55mw) |
| HIGH | `decode-uri-component` | 0.2.0 | [GHSA-qr28-fpjm-wq7f](https://osv.dev/vulnerability/GHSA-qr28-fpjm-wq7f) |
| HIGH | `lodash` | 4.17.20 | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) |
| HIGH | `qs` | 6.5.2 | [GHSA-hrpp-h998-j3pp](https://osv.dev/vulnerability/GHSA-hrpp-h998-j3pp) |
| MODERATE | `ajv` | 6.12.6 | [GHSA-2g4f-4pwh-qvx6](https://osv.dev/vulnerability/GHSA-2g4f-4pwh-qvx6) |
| MODERATE | `request` | 2.88.2 | [GHSA-p8p7-x288-28g6](https://osv.dev/vulnerability/GHSA-p8p7-x288-28g6) |
| MODERATE | `tough-cookie` | 2.5.0 | [GHSA-72xf-g2v4-qvf3](https://osv.dev/vulnerability/GHSA-72xf-g2v4-qvf3) |
| MODERATE | `uuid` | 3.4.0 | [GHSA-w5hq-g745-h8pq](https://osv.dev/vulnerability/GHSA-w5hq-g745-h8pq) |

### `naumovs.color-highlight` — 9,742,813 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 1.1.11 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `minimatch` | 3.1.2 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| MODERATE | `@babel/runtime` | 7.24.0 | [GHSA-968p-4wvh-cqc8](https://osv.dev/vulnerability/GHSA-968p-4wvh-cqc8) |

### `DotJoshJohnson.xml` — 8,170,674 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `lodash` | 3.10.1 | [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) |
| CRITICAL | `minimist` | 1.2.0 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) |
| CRITICAL | `xmldom` | 0.1.27 | [GHSA-crh6-fp67-6883](https://osv.dev/vulnerability/GHSA-crh6-fp67-6883) |
| HIGH | `ansi-regex` | 3.0.0 | [GHSA-93q8-gq69-wqmw](https://osv.dev/vulnerability/GHSA-93q8-gq69-wqmw) |
| HIGH | `cross-spawn` | 5.1.0 | [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) |
| HIGH | `dot-prop` | 4.2.0 | [GHSA-ff7x-qrg7-qggm](https://osv.dev/vulnerability/GHSA-ff7x-qrg7-qggm) |
| HIGH | `ini` | 1.3.5 | [GHSA-qqgx-2p2h-9c37](https://osv.dev/vulnerability/GHSA-qqgx-2p2h-9c37) |
| HIGH | `semver` | 5.5.0 | [GHSA-c2qf-rxjj-qqgw](https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw) |
| MODERATE | `got` | 6.7.1 | [GHSA-pfrx-2q88-qq97](https://osv.dev/vulnerability/GHSA-pfrx-2q88-qq97) |

### `platformio.platformio-ide` — 7,479,892 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `tar` | 7.4.3 | [GHSA-23hp-3jrh-7fpw](https://osv.dev/vulnerability/GHSA-23hp-3jrh-7fpw) |
| HIGH | `brace-expansion` | 2.0.1 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `glob` | 10.4.5 | [GHSA-5j98-mcp5-4vw2](https://osv.dev/vulnerability/GHSA-5j98-mcp5-4vw2) |
| HIGH | `minimatch` | 9.0.5 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |
| HIGH | `underscore` | 1.13.7 | [GHSA-qpx9-hpmf-5gmw](https://osv.dev/vulnerability/GHSA-qpx9-hpmf-5gmw) |
| HIGH | `ws` | 8.18.0 | [GHSA-96hv-2xvq-fx4p](https://osv.dev/vulnerability/GHSA-96hv-2xvq-fx4p) |
| MODERATE | `xml2js` | 0.4.23 | [GHSA-776f-qx25-q3cc](https://osv.dev/vulnerability/GHSA-776f-qx25-q3cc) |

### `CoenraadS.bracket-pair-colorizer-2` — 6,766,249 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| CRITICAL | `minimist` | 1.2.5 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) |
| HIGH | `json5` | 2.2.0 | [GHSA-9c47-m6qq-7p4h](https://osv.dev/vulnerability/GHSA-9c47-m6qq-7p4h) |

### `Oracle.oracle-java` — 6,696,727 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 2.1.4 | [GHSA-6j4f-fj2g-mc7p](https://osv.dev/vulnerability/GHSA-6j4f-fj2g-mc7p) |
| MODERATE | `fast-uri` | 3.1.8 | [GHSA-w74x-v6f9-j3xg](https://osv.dev/vulnerability/GHSA-w74x-v6f9-j3xg) |

### `zobo.php-intellisense` — 6,140,258 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `brace-expansion` | 2.0.1 | [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) |
| HIGH | `cross-spawn` | 7.0.3 | [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) |
| HIGH | `minimatch` | 5.1.6 | [GHSA-23c5-xmqv-rm74](https://osv.dev/vulnerability/GHSA-23c5-xmqv-rm74) |

### `James-Yu.latex-workshop` — 5,887,595 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| MODERATE | `glob` | 13.0.6 | [GHSA-3g3m-2fjr-6pw4](https://osv.dev/vulnerability/GHSA-3g3m-2fjr-6pw4) |
| MODERATE | `minimatch` | 10.2.5 | [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) |

### `steoates.autoimport` — 5,517,213 installs

| Sev | Dep | Version | OSV |
|-----|-----|---------|-----|
| HIGH | `lodash` | 4.17.21 | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) |
