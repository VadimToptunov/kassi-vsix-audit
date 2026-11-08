#!/usr/bin/env python3
"""Enrich audit findings with GHSA severity + install count, rank juiciest.

Juice = installs × severity_weight × runtime_reachability_hint.
"""
import json
import sys
import urllib.request

SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MODERATE": 2, "LOW": 1, "UNKNOWN": 1}


def fetch_osv(osv_id, cache):
    if osv_id in cache:
        return cache[osv_id]
    try:
        req = urllib.request.Request(
            f"https://api.osv.dev/v1/vulns/{osv_id}",
            headers={"User-Agent": "kassi-vsc-audit"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            cache[osv_id] = data
            return data
    except Exception as e:
        cache[osv_id] = {"error": str(e)}
        return cache[osv_id]


def severity_of(v):
    if not isinstance(v, dict):
        return "UNKNOWN"
    # try database_specific.severity
    ds = v.get("database_specific") or {}
    if "severity" in ds:
        s = str(ds["severity"]).upper()
        return s if s in SEV_WEIGHT else "UNKNOWN"
    sev = v.get("severity") or []
    # pick first CVSS score and derive band
    for s in sev:
        if s.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = s.get("score", "")
            # score is a vector string; look for AV:N etc but we just want the band from database_specific
            pass
    return "UNKNOWN"


def main():
    audit = json.load(open(sys.argv[1]))
    installs_json = sys.argv[2]
    installs = {}
    for row in json.load(open(installs_json)):
        installs[f"{row['publisher']}.{row['name']}"] = row["installs"]

    cache_path = "osv_cache.json"
    try:
        cache = json.load(open(cache_path))
    except Exception:
        cache = {}

    enriched = []
    all_osv_ids = set()
    for f in audit:
        for osv_id in f["vulns"]:
            all_osv_ids.add(osv_id)
    print(f"resolving {len(all_osv_ids)} unique OSV ids...", file=sys.stderr)
    for i, osv_id in enumerate(sorted(all_osv_ids), 1):
        fetch_osv(osv_id, cache)
        if i % 50 == 0:
            with open(cache_path, "w") as c:
                json.dump(cache, c)
    with open(cache_path, "w") as c:
        json.dump(cache, c)

    for finding in audit:
        ext_key = finding["ext"].rsplit("-", 1)[0]  # strip version
        inst = installs.get(ext_key, 0)
        max_sev = "UNKNOWN"
        max_w = 0
        best_osv = None
        for osv_id in finding["vulns"]:
            v = cache.get(osv_id, {})
            sev = severity_of(v)
            w = SEV_WEIGHT.get(sev, 1)
            if w > max_w:
                max_w = w
                max_sev = sev
                best_osv = osv_id
        enriched.append({
            "ext": ext_key,
            "installs": inst,
            "dep": finding["dep"],
            "version": finding["version"],
            "severity": max_sev,
            "lead_osv": best_osv,
            "all_osv": finding["vulns"],
            "score": inst * max_w,
        })

    enriched.sort(key=lambda r: -r["score"])
    out_path = sys.argv[3] if len(sys.argv) > 3 else "ranked.json"
    with open(out_path, "w") as f:
        json.dump(enriched, f, indent=2)

    # text report
    print(f"\n{'rank':>4}  {'installs':>12}  {'sev':>8}  {'ext':<45}  {'dep':<25}  osv")
    print("-" * 150)
    for i, r in enumerate(enriched[:60], 1):
        print(f"{i:>4}  {r['installs']:>12,}  {r['severity']:>8}  {r['ext']:<45}  {r['dep']:<25}  {r['lead_osv']}")


if __name__ == "__main__":
    main()
