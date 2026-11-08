#!/usr/bin/env python3
"""Drop first-party / platform-owned / non-code / language-pack publishers."""
import json
import sys

SKIP_PUBLISHERS = {
    "ms-python", "ms-toolsai", "ms-vscode", "ms-vscode-remote", "ms-azuretools",
    "ms-dotnettools", "ms-vsliveshare", "ms-edgedevtools", "ms-vscode-devkit",
    "ms-playwright", "ms-vscode-ipynb", "ms-ossdata", "ms-kubernetes-tools",
    "ms-vscode-remote-insiders", "ms-ceintl", "ms-sarifvscode",
    "Microsoft", "MS-CEINTL", "msjsdiag",
    "vscjava",
    "GitHub", "github",
    "VisualStudioExptTeam", "MicrosoftDocs",
    "redhat",
    "GitLab.gitlab-workflow".split(".")[0],
}

SKIP_SUBSTRING = (
    "language-pack", "icon-theme", "material-theme", "vscode-icons",
    "theme", "keybindings", "cheatsheet",
)


def is_firstparty(row):
    pub = row["publisher"].lower()
    for p in SKIP_PUBLISHERS:
        if p.lower() == pub:
            return True
    return False


def is_theme_or_nonextension(row):
    name = f"{row['name']} {row.get('display', '')}".lower()
    return any(s in name for s in SKIP_SUBSTRING)


def main():
    with open(sys.argv[1]) as f:
        rows = json.load(f)
    kept = [r for r in rows if not is_firstparty(r) and not is_theme_or_nonextension(r)]
    out = sys.argv[2] if len(sys.argv) > 2 else "/dev/stdout"
    with (sys.stdout if out == "/dev/stdout" else open(out, "w")) as f:
        json.dump(kept, f, indent=2)
    print(f"kept {len(kept)} / {len(rows)}", file=sys.stderr)


if __name__ == "__main__":
    main()
