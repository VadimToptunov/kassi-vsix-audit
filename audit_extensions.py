#!/usr/bin/env python3
"""Unpack .vsix, enumerate node_modules, query OSV for vulnerabilities."""
import glob
import json
import os
import sys
import urllib.request
import zipfile

OSV_URL = "https://api.osv.dev/v1/querybatch"


def unpack(vsix_path, out_root):
    name = os.path.basename(vsix_path).replace(".vsix", "")
    dest = os.path.join(out_root, name)
    if os.path.exists(dest):
        return dest
    os.makedirs(dest, exist_ok=True)
    try:
        with zipfile.ZipFile(vsix_path) as z:
            # safe extract: skip absolute paths and .. traversal
            for info in z.infolist():
                if info.filename.startswith("/") or ".." in info.filename.split("/"):
                    continue
                if info.filename.startswith("extension/"):
                    z.extract(info, dest)
    except Exception as e:
        print(f"ERR unpack {name}: {e}", file=sys.stderr)
    return dest


def enumerate_deps(ext_dir):
    deps = []
    root = os.path.join(ext_dir, "extension")
    if not os.path.isdir(root):
        return deps
    for pj in glob.glob(f"{root}/**/node_modules/**/package.json", recursive=True):
        # only package.json of installed packages, not nested test fixtures
        parts = pj.split("/")
        if "node_modules" not in parts:
            continue
        # skip if this package.json isn't the pkg root (must be immediately under node_modules/<pkg>/)
        try:
            with open(pj) as f:
                pkg = json.load(f)
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            # confirm that pj path is .../node_modules/<name>/package.json or .../node_modules/@scope/<name>/package.json
            idx = parts.index("node_modules") if "node_modules" in parts else -1
            # find the LAST node_modules
            for i in range(len(parts) - 1, -1, -1):
                if parts[i] == "node_modules":
                    idx = i
                    break
            tail = parts[idx+1:-1]
            if not tail:
                continue
            if tail[0].startswith("@"):
                if len(tail) != 2 or tail[0] + "/" + tail[1] != name:
                    continue
            else:
                if len(tail) != 1 or tail[0] != name:
                    continue
            deps.append({"name": name, "version": version, "path": pj})
        except Exception:
            continue
    return deps


def osv_query(deps_batch):
    queries = []
    for d in deps_batch:
        queries.append({
            "package": {"name": d["name"], "ecosystem": "npm"},
            "version": d["version"],
        })
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def main():
    vsix_glob = sys.argv[1] if len(sys.argv) > 1 else "vsix/*.vsix"
    unpack_root = sys.argv[2] if len(sys.argv) > 2 else "unpacked"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "audit.json"

    os.makedirs(unpack_root, exist_ok=True)
    vsix_files = sorted(glob.glob(vsix_glob))
    print(f"found {len(vsix_files)} vsix", file=sys.stderr)

    all_findings = []
    for i, vsix in enumerate(vsix_files, 1):
        ext_id = os.path.basename(vsix).replace(".vsix", "")
        ext_dir = unpack(vsix, unpack_root)
        deps = enumerate_deps(ext_dir)
        print(f"{i:>3}/{len(vsix_files)}  {ext_id}: {len(deps)} deps", file=sys.stderr)
        if not deps:
            continue
        # dedup: query unique (name, version) pairs
        seen = {}
        for d in deps:
            key = (d["name"], d["version"])
            seen.setdefault(key, d)
        unique = list(seen.values())
        # query in batches of 500
        for off in range(0, len(unique), 500):
            batch = unique[off:off+500]
            try:
                resp = osv_query(batch)
            except Exception as e:
                print(f"  osv err: {e}", file=sys.stderr)
                continue
            for dep, result in zip(batch, resp.get("results", [])):
                vulns = result.get("vulns", [])
                if vulns:
                    all_findings.append({
                        "ext": ext_id,
                        "dep": dep["name"],
                        "version": dep["version"],
                        "vulns": [v.get("id") for v in vulns],
                    })

    with open(out_path, "w") as f:
        json.dump(all_findings, f, indent=2)
    print(f"wrote {len(all_findings)} findings to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
