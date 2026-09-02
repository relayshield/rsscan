#!/usr/bin/env python3
"""FD-1: make every rsscan version reference match pyproject.toml.

Run this INSIDE a clone of the authoritative repo, github.com/RelayShield/rsscan.
It reads the one true version from pyproject.toml and rewrites every place that
restates it, so no version number is ever typed by hand again.

WHY THIS EXISTS RATHER THAN A LIST OF EDITS
-------------------------------------------
The pin has drifted twice. RELEASE_0.1.3.md records the first: action.yml and the
CircleCI orb pinned rsscan==0.1.0 while PyPI was at 0.1.3. It then recurred --
both pinned 0.1.3 while PyPI published 0.2.1. Both times the fix was "remember to
update the other files", and both times nobody did.

A version stated in four files is a version that will disagree in four files.
This makes pyproject.toml the single source and derives the rest, and
tests/test_version_pin.py fails the build when they diverge, so a third
recurrence is a red test rather than a silent shipment of stale code.

WHAT IT REWRITES
  action.yml        pip install rsscan==<version>
  orb/rsscan.yml    the same pin
  README.md         rev: v<version>   and   uses: RelayShield/rsscan@v<version>

USAGE
    git clone https://github.com/RelayShield/rsscan
    cd rsscan
    python3 tools/rsscan_sync_version.py --check     # report only, exit 1 if stale
    python3 tools/rsscan_sync_version.py             # rewrite in place

Then commit, tag v<version>, and publish the release.
"""

import argparse
import re
import sys
from pathlib import Path

PIN = re.compile(r"(rsscan==)(\d+\.\d+\.\d+)")
REV = re.compile(r"(^\s*rev:\s*v)(\d+\.\d+\.\d+)", re.M)
USES = re.compile(r"(RelayShield/rsscan@v)(\d+\.\d+\.\d+)")

TARGETS = [
    ("action.yml", [PIN]),
    ("orb/rsscan.yml", [PIN]),
    ("README.md", [PIN, REV, USES]),
]


def declared_version(root: Path) -> str:
    text = (root / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        sys.exit("no version = \"...\" in pyproject.toml — is this the rsscan repo?")
    return m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="report differences and exit 1, changing nothing")
    ap.add_argument("--root", default=".", help="repo root (default: cwd)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "pyproject.toml").exists():
        sys.exit(f"{root} has no pyproject.toml. Run this inside a clone of "
                 "github.com/RelayShield/rsscan, not the relayshield monorepo — "
                 "that copy is a stale snapshot and fixing it changes nothing "
                 "anyone can install.")

    version = declared_version(root)
    print(f"pyproject.toml version: {version}\n")

    stale, changed = [], []
    for rel, patterns in TARGETS:
        path = root / rel
        if not path.exists():
            print(f"  skip     {rel} (not present)")
            continue
        text = original = path.read_text()
        found = 0
        for pat in patterns:
            for m in pat.finditer(text):
                found += 1
                if m.group(2) != version:
                    stale.append(f"{rel}: {m.group(0)} should be {version}")
            text = pat.sub(lambda m: m.group(1) + version, text)
        if text != original:
            changed.append(rel)
            if not args.check:
                path.write_text(text)
            print(f"  {'STALE ' if args.check else 'FIXED '}  {rel} ({found} reference(s))")
        else:
            print(f"  ok       {rel} ({found} reference(s))")

    if args.check:
        if stale:
            print("\nSTALE REFERENCES:")
            for s in stale:
                print(f"  {s}")
            print("\nRun without --check to fix, then commit and tag "
                  f"v{version}.")
            return 1
        print("\nEvery version reference matches pyproject.toml.")
        return 0

    if changed:
        print(f"\nRewrote {len(changed)} file(s). Now:")
        print("  python -m unittest tests.test_version_pin")
        print(f"  git commit -am 'chore: sync version references to {version}'")
        print(f"  git tag -a v{version} -m 'rsscan {version}' && git push --tags")
        print("\nThe tag matters: README's pre-commit `rev:` points at it, so a "
              "missing tag makes the documented install fail.")
    else:
        print("\nNothing to change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
