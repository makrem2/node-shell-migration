#!/usr/bin/env python3
"""Install node-shell-migration for AI coding agents that support Agent Skills.

  python scripts/install.py                         # personal install for all supported agents
  python scripts/install.py --scope project --project /path/to/repo
  python scripts/install.py --tool claude-code --tool codex
  python scripts/install.py --mode symlink           # live-edit while developing
  python scripts/install.py --zip dist/node-shell-migration.zip   # for claude.ai / Claude API
  python scripts/install.py --uninstall | --list
"""
import argparse
import os
import shutil
import sys
import zipfile

NAME = "node-shell-migration"
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORE = shutil.ignore_patterns(".git", "dist", "__pycache__", "*.pyc", ".DS_Store")

# tool -> (personal dir, project dir). Folder conventions per vendor docs as of 2026-10; verify if a tool ignores the skill.
TOOLS = {
    "claude-code": ("~/.claude/skills", ".claude/skills"),
    "codex": ("~/.agents/skills", ".agents/skills"),
    "copilot": ("~/.agents/skills", ".agents/skills"),
    "cursor": ("~/.agents/skills", ".agents/skills"),
    "gemini": ("~/.agents/skills", ".agents/skills"),
    "opencode": ("~/.agents/skills", ".agents/skills"),
}


def targets(a):
    chosen = a.tool or list(TOOLS)
    out = []
    for t in chosen:
        if t not in TOOLS:
            sys.exit("unknown tool %r; use --list" % t)
        base = TOOLS[t][0] if a.scope == "personal" else os.path.join(os.path.abspath(a.project), TOOLS[t][1])
        p = os.path.join(os.path.expanduser(base), NAME)
        if p not in out:
            out.append(p)
    if a.dir:
        out.append(os.path.join(os.path.expanduser(a.dir), NAME))
    return out


def remove(p):
    if os.path.islink(p) or os.path.isfile(p):
        os.remove(p)
    elif os.path.isdir(p):
        shutil.rmtree(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", choices=["personal", "project"], default="personal")
    ap.add_argument("--project", default=".")
    ap.add_argument("--tool", action="append")
    ap.add_argument("--dir", help="install into this folder instead (for tools without native skills)")
    ap.add_argument("--mode", choices=["copy", "symlink"], default="copy")
    ap.add_argument("--zip")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    if a.list:
        for t, (pers, proj) in TOOLS.items():
            print("%-12s personal: %-22s project: %s" % (t, pers, proj))
        return 0
    if a.zip:
        os.makedirs(os.path.dirname(os.path.abspath(a.zip)), exist_ok=True)
        with zipfile.ZipFile(a.zip, "w", zipfile.ZIP_DEFLATED) as z:
            for dp, dn, fn in os.walk(SRC):
                dn[:] = [d for d in dn if d not in (".git", "dist", "__pycache__")]
                for f in fn:
                    if f.endswith(".pyc"):
                        continue
                    full = os.path.join(dp, f)
                    z.write(full, os.path.join(NAME, os.path.relpath(full, SRC)))
        print("wrote %s (upload in claude.ai: Customize > Skills)" % a.zip)
        return 0

    for p in targets(a):
        if a.uninstall:
            remove(p)
            print("removed  " + p)
            continue
        os.makedirs(os.path.dirname(p), exist_ok=True)
        remove(p)
        if a.mode == "symlink":
            os.symlink(SRC, p, target_is_directory=True)
        else:
            shutil.copytree(SRC, p, ignore=IGNORE)
        print("%s  %s" % ("linked  " if a.mode == "symlink" else "installed", p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
