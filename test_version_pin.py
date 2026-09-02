"""FD-1: assert the CI clients install the version this package actually is.

Put this in the AUTHORITATIVE rsscan repo (github.com/RelayShield/rsscan), as
tests/test_version_pin.py. It does not belong in the relayshield monorepo copy:
that copy is a stale snapshot and a test passing there proves nothing about what
users install.

This defect has now happened TWICE -- action.yml and orb pinned 0.1.0 while PyPI
was 0.1.3 (recorded in RELEASE_0.1.3.md), then pinned 0.1.3 while PyPI was 0.2.1.
Both times a human was expected to remember. This makes forgetting a red build.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"rsscan==([0-9]+\.[0-9]+\.[0-9]+)")


def declared_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "no version in pyproject.toml"
    return m.group(1)


class TestVersionPins(unittest.TestCase):
    def test_every_pin_matches_pyproject(self):
        version = declared_version()
        checked = 0
        for rel in ("action.yml", "orb/rsscan.yml", "README.md"):
            path = ROOT / rel
            if not path.exists():
                continue
            for pinned in PIN.findall(path.read_text()):
                checked += 1
                self.assertEqual(
                    pinned, version,
                    f"{rel} installs rsscan=={pinned} but this package is "
                    f"{version}. Bump the pin, or CI users get stale code.")
        self.assertGreater(checked, 0, "found no rsscan== pin to check at all - "
                                       "did a file move?")

    def test_readme_rev_tag_matches(self):
        """The pre-commit `rev:` must match too, or FD-2's listing points at a
        tag that installs a different version than the docs claim."""
        readme = (ROOT / "README.md")
        if not readme.exists():
            self.skipTest("no README")
        version = declared_version()
        revs = re.findall(r"^\s*rev:\s*v?([0-9]+\.[0-9]+\.[0-9]+)", readme.read_text(), re.M)
        for rev in revs:
            self.assertEqual(rev, version,
                             f"README pre-commit rev v{rev} != package {version}")


if __name__ == "__main__":
    unittest.main()
