"""rsscan — block commits and builds that introduce secrets.

Two modes, one code path:

  (no arguments)       `git diff --cached -U0`, the staged changes. The
                       pre-commit hook, and the default. Runs before the commit
                       enters git history, which is the whole point: once a
                       secret is committed and pushed it must be rotated even if
                       the commit is later deleted. There is no `--staged` flag;
                       staged is simply what you get without `--rev-range`.
  --rev-range A..B     `git diff A..B -U0`. The CI mode used by the GitHub
                       Action, the GitLab CI component and the CircleCI orb.
                       Strictly a backstop — by the time CI runs, the secret is
                       already in history.

Either way only ADDED lines are scanned, so a repo with pre-existing findings
does not get an unbypassable gate.

**Everything matches locally.** All 31 credential patterns run on this machine.
No source code, no diff and no matched value is ever transmitted. There is no
API key, no account and no network call on the scanning path — which is what
makes the free tier genuinely free (zero server cost per commit) and removes the
"why does our pre-commit hook POST source code to a third party" objection that
kills adoption for a security tool. Matched values are never printed either;
findings carry a file, a line and a truncated fingerprint.

Two optional, explicitly opt-in network features exist, both off by default:

  --report PATH   Writes an escalation report the developer can forward. Local
                  file write only, still no network.
  --org DOMAIN    Sends ONLY {org domain, tool version, anonymous install id,
                  per-severity counts} so RelayShield can see that N engineers
                  at one company are using it. Never file paths, never
                  fingerprints, never code, never the secrets themselves.

Exit codes:
    0  no blocking findings (or non-blocking severities only)
    1  blocking findings
    0  any config failure, unless --strict is set (see _fail_open)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import __version__ as _VERSION
from .patterns import _COMPILED, PATTERN_COUNT, fingerprint

# Org-signal endpoint. Only ever receives aggregate counts — see --org above.
DEFAULT_ORG_ENDPOINT = "https://api.relayshield.net/v1/telemetry/rsscan-install"
DEFAULT_TIMEOUT = 10
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Where a developer is sent to check what is ALREADY public. The local hook can
# only prevent the next leak; it cannot see what has already been scraped.
EXPOSURE_URL = "https://api.relayshield.net/developers?source=rsscan"
# --deps gets its own key. Both are registered, but they land on different
# banners on purpose: someone whose commit was just blocked is asking whether
# their org's credentials are already public, and someone who just counted 275
# publisher accounts in their dependency tree is asking a different question.
DEPS_EXPOSURE_URL = "https://api.relayshield.net/developers?source=rsscan-deps"

_RED = "\033[31m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _colour(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stderr.isatty():
        return text
    return f"{code}{text}{_RESET}"


def _git_diff(rev_range: str = "") -> str:
    """The diff to scan, zero context lines.

    -U0 matters: with context the server would still only scan `+` lines, but
    the payload would be several times larger for no benefit.
    """
    args = ["git", "diff", "-U0", "--no-color"]
    args += [rev_range] if rev_range else ["--cached"]
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def _load_allowlist(path: str) -> set[str]:
    """Fingerprints to ignore, one per line, `#` comments allowed.

    Fingerprints rather than raw values on purpose — an allowlist file that
    contains the actual secrets would be the same mistake this hook exists to
    prevent.
    """
    if not path or not os.path.exists(path):
        return set()
    out = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line)
    return out


def _fail_open(message: str, strict: bool) -> int:
    """Network down, no key, endpoint 500 — do not wedge the user's commit.

    A secret scanner that blocks every commit when the network is flaky gets
    uninstalled, and then it catches nothing at all. Default is to warn loudly
    and allow; --strict flips it for CI or a regulated repo.
    """
    if strict:
        print(_colour(f"rsscan: {message} (--strict, failing)", _RED), file=sys.stderr)
        return 1
    print(_colour(f"rsscan: {message} — skipping scan, continuing.", _YELLOW), file=sys.stderr)
    return 0


def _scan_text(text: str, filename: str = "") -> list[dict]:
    """Run every credential pattern over `text`. Mirrors the server's scanner.

    Deliberately never returns the matched value — only a fingerprint. A local
    tool printing secrets to a terminal (and therefore into CI logs and shell
    history) would recreate the exposure it exists to prevent.
    """
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    attributed: set[str] = set()

    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid
        return lo

    for name, pattern, severity, description, llm_provider in _COMPILED:
        for match in pattern.finditer(text):
            # Context-anchored patterns keep the secret in group 1, so the vendor
            # name that anchored the match is not fingerprinted with it.
            val = match.group(1) if pattern.groups else match.group(0)
            start = match.start(1) if pattern.groups else match.start(0)

            # A provider-attributed key must not also be reported by the
            # unattributed sk- catch-all. Same rule as the server.
            if llm_provider == "unknown_openai_compatible":
                if val in attributed:
                    continue
            elif llm_provider:
                attributed.add(val)

            key = (val, start)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type":        name,
                "description": description,
                "severity":    severity,
                "line":        line_of(start),
                "fingerprint": fingerprint(val),
                "file":        filename,
            })
    return findings


def _scan_unified_diff(diff: str) -> list[dict]:
    """Scan only the ADDED lines of a unified diff.

    Secrets already in a file are already in history; blocking on them would
    make the hook unbypassable on any repo with legacy findings. Added lines are
    reassembled per file so a pattern is not missed at a line boundary, with a
    side table mapping back to real line numbers.
    """
    findings: list[dict] = []
    current_file = ""
    new_lineno = 0
    buf: list[str] = []
    line_map: list[int] = []

    def flush() -> None:
        nonlocal buf, line_map
        if buf:
            block = "\n".join(buf)
            for f in _scan_text(block, current_file):
                idx = f["line"] - 1
                f["line"] = line_map[idx] if 0 <= idx < len(line_map) else 0
                findings.append(f)
        buf, line_map = [], []

    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            flush()
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current_file = "" if path == "/dev/null" else path
        elif raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw)
            new_lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            buf.append(raw[1:])
            line_map.append(new_lineno)
            new_lineno += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            pass                      # removed line: not in the new file
        elif raw.startswith("\\"):
            pass                      # "\ No newline at end of file"
        else:
            new_lineno += 1           # context line

    flush()
    return findings


def _install_id() -> str:
    """Stable per-machine id that identifies no person.

    Hostname + user, hashed and truncated. Enough to tell six developers at one
    company apart from one developer running it six times; useless for
    identifying anybody, and never reversible.
    """
    raw = f"{platform.node()}|{os.environ.get('USER') or os.environ.get('USERNAME') or ''}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


# Free/consumer mail domains, used by --deps to count how many publisher
# accounts sit on personal webmail rather than on an organisation's domain.
#
# That count is the point of the whole subcommand: a personal Gmail account with
# npm publish rights has no SSO, no central revocation and no IT department, so
# it is the account a stealer log actually monetises. This is a signal about the
# dependency, not a judgement about the person.
_PERSONAL_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "pm.me", "aol.com", "gmx.com", "gmx.de", "yandex.ru", "mail.com",
    "zoho.com", "fastmail.com", "hey.com", "duck.com", "users.noreply.github.com",
})


def _send_org_signal(org: str, counts: dict, endpoint: str, timeout: int) -> None:
    """Report that this org uses rsscan. Aggregate counts only, opt-in only.

    This is the bridge from an individual developer to the security lead who
    holds budget: N distinct install ids at one org domain is a qualified
    account, which PyPI download totals can never show. Deliberately carries no
    file paths, no fingerprints, no repo names, no code and no secrets — if it
    ever needs to, the answer is no.

    Failures are swallowed. Telemetry must never break somebody's commit.
    """
    payload = json.dumps({
        "org":         org,
        "install_id":  _install_id(),
        "version":     _VERSION,
        "counts":      counts,
        "reported_at": datetime.now(timezone.utc).isoformat(),
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": f"rsscan/{_VERSION}"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=timeout).read()
    except Exception:
        pass


def _write_report(path: str, findings: list[dict], where: str, org: str | None) -> bool:
    """Write the escalation artifact a developer forwards to their security lead.

    This is the actual conversion mechanic. A developer is not the buyer; the
    person they forward this to is. So the report answers the question the local
    scan cannot: this hook stopped the NEXT leak, but what is already public?
    """
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items())) or "none"

    lines = [
        "# Credential exposure report",
        "",
        f"Generated by rsscan {_VERSION} on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Scope: {where}",
        f"Findings: {summary}",
        "",
        "## What was found",
        "",
        "| Severity | Credential type | File | Line | Fingerprint |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {f.get('severity','?')} | {f.get('description', f.get('type','?'))} "
            f"| `{f.get('file') or '(unknown)'}` | {f.get('line','?')} "
            f"| `{f.get('fingerprint','')}` |"
        )
    lines += [
        "",
        "No secret values appear in this report — only non-reversible fingerprints,",
        "so it is safe to forward, paste into a ticket, or attach to an email.",
        "",
        "## Why this matters beyond this commit",
        "",
        "rsscan runs locally and blocks credentials *before* they enter git history.",
        "It cannot see credentials that already left — a key committed last year, or",
        "leaked through a dependency, a published package or a container image, may",
        "already be indexed and scraped. Rotating what is listed above does not answer",
        "that question.",
        "",
        "## Recommended next step for whoever owns security here",
        "",
        "Check what is already public for this organisation — leaked credentials in",
        "public repos, packages and images, plus the identity-layer exposure that",
        "secret scanners do not cover at all: workforce credentials appearing in",
        "infostealer logs and breach dumps, SIM-swap risk on staff accounts, and",
        "session/token exposure.",
        "",
        f"  {EXPOSURE_URL}",
        "",
    ]
    if org:
        lines += [f"Organisation: {org}", ""]

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return True
    except OSError as exc:
        print(_colour(f"rsscan: could not write report to {path} ({exc})", _YELLOW), file=sys.stderr)
        return False


def _report(findings: list[dict], blocking: list[dict], where: str, staged: bool) -> None:
    print(file=sys.stderr)
    print(_colour(f"  rsscan: secrets detected in {where}", _BOLD + _RED), file=sys.stderr)
    print(file=sys.stderr)
    for f in findings:
        sev = f.get("severity", "?")
        colour = _RED if sev in ("CRITICAL", "HIGH") else _YELLOW
        loc = f.get("file") or "(unknown file)"
        line = f.get("line") or "?"
        print(
            f"  {_colour(sev.ljust(8), colour)} {f.get('description', f.get('type', '?'))}",
            file=sys.stderr,
        )
        print(f"           {loc}:{line}", file=sys.stderr)
        print(_colour(f"           fingerprint {f.get('fingerprint', '')}", _DIM), file=sys.stderr)
    print(file=sys.stderr)
    if blocking:
        print(_colour("  Commit refused." if staged else "  Build failed.", _BOLD), file=sys.stderr)
        print(file=sys.stderr)
        if staged:
            print("  Remove the value and load it from a secrets manager or environment", file=sys.stderr)
            print("  variable instead. If it has already left this machine, rotate it.", file=sys.stderr)
        else:
            # CI is a backstop, not prevention. Saying "remove it" here would be
            # misleading advice: the secret is already in pushed history.
            print("  These secrets are already in git history. Deleting the commit is not", file=sys.stderr)
            print("  enough — rotate every credential listed above, then purge from history.", file=sys.stderr)
        print(file=sys.stderr)
        print("  False positive? Add the fingerprint to .relayshield-allowlist:", file=sys.stderr)
        for f in blocking:
            print(f"      echo '{f.get('fingerprint', '')}' >> .relayshield-allowlist", file=sys.stderr)
        if staged:
            print(file=sys.stderr)
            print(_colour("  To bypass entirely: git commit --no-verify", _DIM), file=sys.stderr)
        print(file=sys.stderr)

    # The limit of what a local scanner can honestly claim. Everything above is
    # a leak that has been PREVENTED. rsscan reads a diff, so it is structurally
    # incapable of seeing a credential that already left: committed last year,
    # published in a package, baked into an image. That question needs a search
    # of public artifacts, which is a different job and a paid one.
    #
    # Printed only when something was found, which is the one moment the reader
    # is already thinking about leaked credentials. Printing it on every clean
    # run would train people to skip the block, the same reasoning the delivery
    # channels use for staying quiet on clean builds.
    if findings:
        print(_colour("  What this scan could NOT see", _BOLD), file=sys.stderr)
        print("  rsscan reads your diff, so it catches what is about to leak. It cannot see", file=sys.stderr)
        print("  a credential that already left: committed months ago, shipped in a package,", file=sys.stderr)
        print("  or baked into an image, and possibly indexed and scraped since.", file=sys.stderr)
        print(f"  Check what is already public: {EXPOSURE_URL}", file=sys.stderr)
        print(file=sys.stderr)


# ---------------------------------------------------------------------------
# Delivery channels (BB-8): Slack and generic webhook
#
# Both are opt-in and point at an endpoint the user owns — their Slack, their
# receiver. rsscan stays a local scanner: nothing is sent anywhere unless a URL
# is supplied, and even then the payload carries no secret values, only the
# credential type, severity, location and fingerprint. Same rule as --report
# and --org: the tool must never be the thing that leaks the secret.
#
# Delivery failure never fails the build. A gate exists to block secrets, not
# to block on a flaky Slack endpoint; the scan's own exit code is unaffected
# and the problem is reported on stderr so it is not silent either.
# ---------------------------------------------------------------------------

def _ci_context() -> dict:
    """Best-effort repo/build identity from whichever CI is running.

    Read from env rather than git so it stays correct on detached-HEAD checkouts,
    which is how most CI systems check code out.
    """
    env = os.environ
    repo = (env.get("GITHUB_REPOSITORY") or env.get("CI_PROJECT_PATH")
            or env.get("BITBUCKET_REPO_FULL_NAME") or env.get("CIRCLE_PROJECT_REPONAME") or "")
    ref = (env.get("GITHUB_REF_NAME") or env.get("CI_COMMIT_REF_NAME")
           or env.get("BITBUCKET_BRANCH") or env.get("CIRCLE_BRANCH") or "")
    url = ""
    if env.get("GITHUB_SERVER_URL") and repo and env.get("GITHUB_RUN_ID"):
        url = f"{env['GITHUB_SERVER_URL']}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}"
    elif env.get("CI_PIPELINE_URL"):
        url = env["CI_PIPELINE_URL"]
    elif env.get("CIRCLE_BUILD_URL"):
        url = env["CIRCLE_BUILD_URL"]
    return {"repo": repo, "ref": ref, "build_url": url}


def _finding_payload(f: dict) -> dict:
    """The only shape a finding is ever transmitted in. No value, ever."""
    return {
        "type":        f.get("type", ""),
        "severity":    f.get("severity", ""),
        "description": f.get("description", ""),
        "file":        f.get("file", ""),
        "line":        f.get("line", 0),
        "fingerprint": f.get("fingerprint", ""),
    }


def _post_json(url: str, payload: dict, timeout: int, label: str) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": f"rsscan/{_VERSION}"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as exc:
        # Reported, not swallowed: a delivery channel that fails silently is a
        # channel the owner believes is working. Still does not change exit code.
        print(_colour(f"rsscan: {label} delivery failed ({exc})", _YELLOW), file=sys.stderr)


def _send_webhook(url: str, findings: list[dict], blocking: list[dict],
                  counts: dict, where: str, timeout: int) -> None:
    ctx = _ci_context()
    _post_json(url, {
        "tool":             "rsscan",
        "version":          _VERSION,
        "scanned":          where,
        "repo":             ctx["repo"],
        "ref":              ctx["ref"],
        "build_url":        ctx["build_url"],
        "findings_count":   len(findings),
        "blocking_count":   len(blocking),
        "highest_severity": findings[0].get("severity", "") if findings else None,
        "severity_counts":  counts,
        "findings":         [_finding_payload(f) for f in findings],
        "detected_at":      datetime.now(timezone.utc).isoformat(),
    }, timeout, "webhook")


# Slack renders at most a handful of lines usefully before the message becomes
# a wall. Link out to the build for the rest rather than pasting 200 findings.
_SLACK_DETAIL_LIMIT = 10


def _send_slack(url: str, findings: list[dict], blocking: list[dict],
                counts: dict, where: str, timeout: int) -> None:
    ctx = _ci_context()
    highest = findings[0].get("severity", "") if findings else ""
    icon = ":rotating_light:" if blocking else ":warning:"
    headline = (
        f"{icon} rsscan: {len(findings)} secret finding(s)"
        f"{f' — {len(blocking)} blocking' if blocking else ' — none blocking'}"
    )
    where_line = " · ".join(x for x in [ctx["repo"] or None, ctx["ref"] or None, where] if x)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"

    lines = []
    for f in findings[:_SLACK_DETAIL_LIMIT]:
        loc = f.get("file") or "(unknown file)"
        if f.get("line"):
            loc = f"{loc}:{f['line']}"
        lines.append(f"• *{f.get('severity','')}* `{f.get('type','')}` — {loc}")
    if len(findings) > _SLACK_DETAIL_LIMIT:
        lines.append(f"_…and {len(findings) - _SLACK_DETAIL_LIMIT} more._")

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": headline[:150], "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Where*\n{where_line or 'local'}"},
            {"type": "mrkdwn", "text": f"*Highest*\n{highest or 'n/a'}"},
            {"type": "mrkdwn", "text": f"*Severities*\n{summary}"},
            {"type": "mrkdwn", "text": f"*Blocking*\n{len(blocking)}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines) or "_no detail_"}},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": "No secret values are included — only type, location and fingerprint."}]},
    ]
    if ctx["build_url"]:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open build"},
             "url": ctx["build_url"]}]})

    _post_json(url, {"text": headline, "blocks": blocks}, timeout, "Slack")


# ---------------------------------------------------------------------------
# GitHub Actions annotations (BB-8)
#
# Puts each finding inline on the changed line in the PR's Files tab, where the
# developer already is, instead of buried in collapsed build log output.
#
# Deliberately implemented with workflow commands on stdout rather than the
# Checks API. The Checks API needs a GitHub App, an installation, a private key
# and a token exchange -- an account and a setup flow, which is precisely what
# the free tier promises you do not need. Workflow commands need nothing: no
# token, no permissions block, no network call. Same inline result.
# ---------------------------------------------------------------------------

# GitHub's own escaping rules. Message data and property values differ: a bare
# ":" or "," inside a property value would end the property list and silently
# mangle the annotation.
def _gh_escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_escape_prop(text: str) -> str:
    return _gh_escape_data(text).replace(":", "%3A").replace(",", "%2C")


# GitHub renders at most 10 annotations per step in the PR UI and rejects very
# large batches. Emitting hundreds would bury the important ones and slow the
# step, so cap and say so rather than truncating silently.
_ANNOTATION_LIMIT = 50


def _emit_github_annotations(findings: list[dict], blocking: list[dict]) -> None:
    """Write ::error / ::warning workflow commands to stdout.

    Never emits a secret value -- only the credential type, severity and
    fingerprint, matching the report's guarantee. The fingerprint is included
    because it is what the developer needs to allowlist a false positive, and
    it is non-reversible.
    """
    blocking_ids = {id(f) for f in blocking}
    for i, f in enumerate(findings):
        if i >= _ANNOTATION_LIMIT:
            print(
                f"::notice::rsscan: {len(findings) - _ANNOTATION_LIMIT} further finding(s) "
                f"not annotated (limit {_ANNOTATION_LIMIT}). See the step log for the full list."
            )
            break
        level = "error" if id(f) in blocking_ids else "warning"
        props = [f"title={_gh_escape_prop('rsscan: ' + str(f.get('severity', '')) + ' secret detected')}"]
        # Only claim a location when there is a real one. line=0 would anchor
        # the annotation to the wrong place, which is worse than a file-level
        # annotation with no line at all.
        path = f.get("file") or ""
        line = f.get("line") or 0
        if path:
            props.append(f"file={_gh_escape_prop(path)}")
            if line > 0:
                props.append(f"line={line}")
        # Pattern descriptions are written as noun phrases ("AWS IAM Access
        # Key") and do not carry terminal punctuation, so add it rather than
        # running two sentences together in the annotation bubble.
        desc = str(f.get("description", "")).strip().rstrip(".")
        message = (
            f"{f.get('type', 'secret')} ({f.get('severity', '')})."
            + (f" {desc}." if desc else "")
            + " Remove the value and load it from a secrets manager or environment variable;"
            " if it has already been pushed, rotate it."
            f" False positive? echo '{f.get('fingerprint', '')}' >> .relayshield-allowlist"
        )
        print(f"::{level} {','.join(props)}::{_gh_escape_data(message)}")


def _annotations_enabled(mode: str) -> bool:
    if mode == "off":
        return False
    if mode == "github":
        return True
    # auto: only inside GitHub Actions, where these lines are meaningful.
    # Anywhere else they are noise printed at a developer.
    return os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true"


# ---------------------------------------------------------------------------
# --deps: who can publish your dependencies
#
# Every package security tool analyses the artefact. None of them can tell you
# anything about the humans who hold publish rights on it, which is where the
# self-replicating npm worms actually enter: not through malicious code in a
# release, but through a maintainer account that someone else is now using.
#
# This subcommand counts those accounts and stops there. It does NOT screen them
# against anything, it names nobody, and it sends nothing to RelayShield. The
# only network calls are to registry.npmjs.org, and the only output is
# arithmetic over public registry metadata.
#
# It closes on what it cannot see -- whether any of those accounts are actually
# compromised right now -- which is the same construction --report uses.
# ---------------------------------------------------------------------------

# The version document, not the full package document. Three URLs are possible
# here and two of them are wrong:
#
#   /<pkg>          the full document: every version ever published. 11 MB for
#                   @types/node. Resolving 400 packages this way moves gigabytes.
#   /<pkg>/latest   3.7 KB, and carries both `maintainers` and `_npmUser`.
#   the abbreviated `application/vnd.npm.install-v1+json` document omits
#                   `maintainers` ENTIRELY, so it returns zero publishers for
#                   every package while looking like it worked. Never use it.
NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}/latest"

# Mirrors the server-side rule in relayshield_api.py so a package name that
# resolves here resolves there. Registry names are lowercase, optionally scoped.
_NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")

# Shared and automated addresses. `security@`, `oss-bot@`, `release-ci@`. These
# are counted separately rather than dropped: a role address is a real publish
# path, but it is a mailing list or a CI robot, so "is this person's laptop
# infected" is not a question that can be asked about it.
_ROLE_ADDRESS_LOCALPARTS = frozenset({
    "admin", "abuse", "bot", "ci", "contact", "dev", "devs", "developer",
    "developers", "help", "hello", "hi", "info", "it", "mail", "maintainer",
    "maintainers", "noreply", "no-reply", "npm", "ops", "oss", "oss-bot",
    "packages", "postmaster", "release", "releases", "root", "security",
    "support", "sysadmin", "team", "webmaster",
})

_MANIFEST_CANDIDATES = ("package-lock.json", "package.json")

# Polite concurrency against a public registry that owes us nothing. Eight
# workers resolves a 400-package manifest in well under a minute; more than that
# risks looking like abuse for no real gain.
_DEPS_WORKERS = 8


def _is_role_address(email: str) -> bool:
    local = email.split("@", 1)[0].lower()
    if local in _ROLE_ADDRESS_LOCALPARTS:
        return True
    # `oss-bot`, `npm-publish`, `release-ci` and friends.
    return any(local.startswith(p + "-") or local.endswith("-" + p)
               for p in ("bot", "ci", "oss", "npm", "release", "noreply"))


def _is_personal_email(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].strip().lower()
    return domain in _PERSONAL_EMAIL_DOMAINS


def _packages_from_manifest(manifest) -> list[str]:
    """Accept package.json or package-lock.json, as an object or a JSON string.

    A lockfile gives the full transitive tree, which is the number that matters:
    the worm does not care whether you declared the dependency yourself.
    """
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception:
            return []
    if not isinstance(manifest, dict):
        return []

    names: set[str] = set()
    # package.json
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = manifest.get(section)
        if isinstance(block, dict):
            names.update(k for k in block if isinstance(k, str))
    # package-lock.json v2/v3: keys look like "node_modules/left-pad"
    packages = manifest.get("packages")
    if isinstance(packages, dict):
        for key in packages:
            if isinstance(key, str) and "node_modules/" in key:
                names.add(key.rsplit("node_modules/", 1)[1])
    # package-lock.json v1
    deps = manifest.get("dependencies")
    if isinstance(deps, dict) and any(isinstance(v, dict) and "version" in v for v in deps.values()):
        names.update(k for k in deps if isinstance(k, str))

    return sorted(n for n in names if n and not n.startswith("."))


def _npm_maintainer_emails(package: str, timeout: int = 10) -> tuple[list[str], str | None]:
    """Resolve a package to its publisher emails. Returns (emails, error).

    An error is returned rather than an empty list, because "we could not ask"
    and "nobody can publish this" must never collapse into the same answer. The
    caller counts unresolved packages and prints that count, which is the
    difference between a report and a false clean.
    """
    if not _NPM_PACKAGE_RE.match(package):
        return [], "invalid_package_name"
    url = NPM_REGISTRY_URL.format(package=urllib.parse.quote(package, safe="@/"))
    req = urllib.request.Request(url, headers={
        "User-Agent": f"rsscan/{_VERSION} (+https://github.com/RelayShield/rsscan)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return [], ("not_found" if exc.code == 404 else f"registry_http_{exc.code}")
    except Exception:
        return [], "registry_unreachable"

    emails: list[str] = []
    for m in (doc.get("maintainers") or []):
        if isinstance(m, dict):
            e = (m.get("email") or "").strip().lower()
            if e and "@" in e:
                emails.append(e)
    # `_npmUser` is the account that actually published the version you have
    # installed, whereas `maintainers` lists everyone who merely could have.
    # Counted, never distinguished in the output.
    npm_user = ((doc.get("_npmUser") or {}).get("email") or "").strip().lower()
    if npm_user and "@" in npm_user:
        emails.append(npm_user)
    return sorted(set(emails)), (None if emails else "no_maintainer_email")


def _find_manifest(path: str) -> tuple[str, str]:
    """Resolve the manifest to (path, raw_text). Raises OSError if unreadable."""
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return path, fh.read()
    for candidate in _MANIFEST_CANDIDATES:
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                return candidate, fh.read()
    raise FileNotFoundError(
        f"no manifest found. Looked for {' then '.join(_MANIFEST_CANDIDATES)} "
        f"in {os.getcwd()}. Pass a path: rsscan --deps path/to/package-lock.json"
    )


def _run_deps(path: str, timeout: int) -> int:
    """Count the publisher accounts behind a dependency manifest."""
    try:
        manifest_path, raw = _find_manifest(path)
    except OSError as exc:
        print(_colour(f"rsscan --deps: {exc}", _RED), file=sys.stderr)
        return 1

    packages = _packages_from_manifest(raw)
    if not packages:
        print(
            _colour(
                f"rsscan --deps: no dependencies found in {manifest_path}. "
                f"If this is a package.json with no dependency sections, that is "
                f"the correct answer.",
                _DIM,
            ),
            file=sys.stderr,
        )
        return 0

    print(
        _colour(f"  Resolving publishers for {len(packages):,} packages "
                f"from {manifest_path}...", _DIM),
        file=sys.stderr,
    )

    emails: set[str] = set()
    unresolved: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=_DEPS_WORKERS) as pool:
        futures = {
            pool.submit(_npm_maintainer_emails, pkg, timeout): pkg
            for pkg in packages
        }
        for future in concurrent.futures.as_completed(futures):
            pkg = futures[future]
            try:
                found, err = future.result()
            except Exception:
                found, err = [], "lookup_failed"
            if err and not found:
                unresolved[pkg] = err
            emails.update(found)

    personal = {e for e in emails if _is_personal_email(e)}
    role = {e for e in emails if _is_role_address(e)}
    # A role address on a corporate domain is both, and the personal count is
    # the one that would be misleading, so role wins the overlap.
    personal -= role

    print(file=sys.stderr)
    print(_colour("  Who can publish your dependencies", _BOLD), file=sys.stderr)
    print(f"  {len(packages):>6,}  dependencies in {manifest_path}", file=sys.stderr)
    print(f"  {len(emails):>6,}  distinct publisher accounts can push code into them", file=sys.stderr)
    print(f"  {len(personal):>6,}  on personal webmail (no SSO, no central revocation)", file=sys.stderr)
    print(f"  {len(role):>6,}  role or automation addresses", file=sys.stderr)

    # Never a silent zero. An unresolved package is a package whose publishers
    # we do not know, which is not the same as a package with no publishers.
    if unresolved:
        print(
            _colour(f"  {len(unresolved):>6,}  packages could NOT be resolved "
                    f"(counted in neither line above)", _RED),
            file=sys.stderr,
        )
        reasons: dict[str, int] = {}
        for reason in unresolved.values():
            reasons[reason] = reasons.get(reason, 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(_colour(f"           {count:,} {reason}", _DIM), file=sys.stderr)

    print(file=sys.stderr)
    print(_colour("  What this count could NOT see", _BOLD), file=sys.stderr)
    print("  This is arithmetic over public registry metadata. It reads entirely locally", file=sys.stderr)
    print("  and sends nothing anywhere. What it cannot tell you is the part that decides", file=sys.stderr)
    print("  whether any of it matters: whether any of those accounts is compromised right", file=sys.stderr)
    print("  now, sitting in an infostealer log with a valid npm session alongside it.", file=sys.stderr)
    print(f"  {DEPS_EXPOSURE_URL}", file=sys.stderr)
    print(file=sys.stderr)

    # Always 0. This is a report, not a gate: there is no threshold at which a
    # dependency count is a build failure, and exiting non-zero would wire it
    # into pipelines as one.
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rsscan",
        description="Block commits and builds that introduce secrets.",
    )
    parser.add_argument(
        "--fail-on",
        default=os.environ.get("RSSCAN_FAIL_ON") or "HIGH",
        choices=SEVERITY_ORDER,
        help="Lowest severity that blocks (default: HIGH).",
    )
    parser.add_argument(
        "--rev-range",
        default=os.environ.get("RSSCAN_REV_RANGE", ""),
        help="Scan a commit range (e.g. origin/main...HEAD) instead of staged changes. CI mode.",
    )
    parser.add_argument("--allowlist", default=os.environ.get("RSSCAN_ALLOWLIST", ".relayshield-allowlist"))
    parser.add_argument(
        "--report",
        default=os.environ.get("RSSCAN_REPORT", ""),
        metavar="PATH",
        help="Write a forwardable exposure report (Markdown). Local file only, no network.",
    )
    parser.add_argument(
        "--org",
        default=os.environ.get("RSSCAN_ORG", ""),
        metavar="DOMAIN",
        help=(
            "Opt-in. Report your org domain with per-severity counts only "
            "(no code, no file paths, no fingerprints, no secrets)."
        ),
    )
    parser.add_argument("--org-endpoint", default=os.environ.get("RSSCAN_ORG_ENDPOINT", DEFAULT_ORG_ENDPOINT))
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("RSSCAN_TIMEOUT") or DEFAULT_TIMEOUT))
    # Tri-state on purpose: None means "not specified", which lets the default
    # differ between the pre-commit path and CI (see below).
    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_const",
        const=True,
        default=None,
        help="Fail if the scan cannot run, instead of allowing it through. Default in CI mode.",
    )
    parser.add_argument(
        "--no-strict",
        dest="strict",
        action="store_const",
        const=False,
        help="Allow the run to continue when the scan cannot run. Default in pre-commit mode.",
    )
    parser.add_argument(
        "--slack-webhook",
        default=os.environ.get("RSSCAN_SLACK_WEBHOOK", ""),
        metavar="URL",
        help=(
            "Opt-in. POST a findings summary to your own Slack incoming webhook. "
            "Sends no secret values — only type, severity, location and fingerprint."
        ),
    )
    parser.add_argument(
        "--webhook",
        default=os.environ.get("RSSCAN_WEBHOOK", ""),
        metavar="URL",
        help=(
            "Opt-in. POST findings as JSON to an endpoint you control. "
            "Sends no secret values — only type, severity, location and fingerprint."
        ),
    )
    parser.add_argument(
        "--annotate",
        default=os.environ.get("RSSCAN_ANNOTATE", "auto"),
        choices=("auto", "github", "off"),
        help=(
            "Emit inline CI annotations. 'auto' (default) turns them on only inside "
            "GitHub Actions; 'github' forces them; 'off' disables them."
        ),
    )
    # nargs="?" with const="": `--deps` alone auto-detects the manifest in the
    # current directory, `--deps path/to/package-lock.json` takes an explicit
    # one. The default is None so "flag absent" stays distinguishable from
    # "flag given with no path".
    parser.add_argument(
        "--deps",
        nargs="?",
        const="",
        default=None,
        metavar="MANIFEST",
        help=(
            "Count the publisher accounts that can push code into your npm "
            "dependencies. Reads package-lock.json or package.json locally, "
            "queries only registry.npmjs.org, screens nothing, names nobody, "
            "and sends nothing to RelayShield."
        ),
    )
    parser.add_argument("--version", action="version", version=f"rsscan {_VERSION}")
    args = parser.parse_args(argv)

    # --deps is its own mode. It reads a manifest, not a diff, so none of the
    # secret-scanning path below applies to it and it never blocks a commit.
    if args.deps is not None:
        return _run_deps(args.deps, args.timeout)

    staged = not args.rev_range

    if args.strict is None:
        env = os.environ.get("RSSCAN_STRICT", "").strip().lower()
        if env in ("1", "true", "yes"):
            args.strict = True
        elif env in ("0", "false", "no"):
            args.strict = False
        else:
            # Default differs by mode, and the asymmetry is deliberate.
            #
            # Pre-commit runs on a developer's machine many times a day. A hook
            # that wedges every commit on a flaky network gets uninstalled, and
            # then it catches nothing at all -- so fail open there.
            #
            # CI runs once, unattended, and its whole job is to be a gate. A
            # gate that silently reports success when it could not actually run
            # is worse than no gate: it manufactures false assurance. Verified
            # the hard way 2026-07-31 -- a container with an unmounted repo
            # printed a warning and exited 0, which would have passed every
            # build in a misconfigured pipeline.
            args.strict = not staged

    # No API key check. Scanning is entirely local and always free -- requiring a
    # key here was the single biggest install-friction item and bought nothing.
    where = "staged changes" if staged else args.rev_range
    try:
        diff = _git_diff(args.rev_range)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return _fail_open(f"could not read diff for {where} ({exc})", args.strict)

    # Nothing added means nothing to scan, and no billed call.
    if not diff.strip():
        return 0

    # No size cap. The old 1 MiB limit existed to protect an HTTP payload; a
    # local regex pass over a large diff is cheap, and refusing to scan a big
    # commit is exactly when a scanner is most needed.
    try:
        findings = _scan_unified_diff(diff)
    except re.error as exc:
        return _fail_open(f"pattern engine error ({exc})", args.strict)

    allowed = _load_allowlist(args.allowlist)
    findings = [f for f in findings if f.get("fingerprint") not in allowed]

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    # Opt-in org signal. Fires on clean runs too -- adoption is the signal we
    # want, and only reporting on failures would bias it toward messy repos.
    #
    # Deliberately still opt-in as of 0.2.0. An inferred-by-default version was
    # written and held back: a secret scanner is asking for more trust than any
    # other tool in the toolchain, and defaulting telemetry on is the one change
    # that would spend that trust for a metric we can live without.
    #
    # It announces itself on stderr when it does fire, rather than sending
    # quietly.
    org = (args.org or "").strip().lower()
    if org:
        _send_org_signal(org, severity_counts, args.org_endpoint, args.timeout)
        print(
            _colour(
                f"  rsscan: reported org '{org}' with severity counts only "
                f"(no code, no paths, no secrets).",
                _DIM,
            ),
            file=sys.stderr,
        )

    if not findings:
        return 0

    findings.sort(
        key=lambda f: (
            -SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in SEVERITY_ORDER else 0,
            f.get("line", 0),
        )
    )

    threshold = SEVERITY_ORDER.index(args.fail_on)
    blocking = [
        f for f in findings
        if f.get("severity") in SEVERITY_ORDER and SEVERITY_ORDER.index(f["severity"]) >= threshold
    ]

    _report(findings, blocking, where, staged)

    # Inline PR annotations. After _report so the human-readable block is still
    # first in the log, and guarded so these never print on a developer's
    # terminal during a pre-commit run.
    if _annotations_enabled(args.annotate):
        _emit_github_annotations(findings, blocking)

    # Delivery channels. Only fire when there is something to report — a
    # notification on every clean build trains people to ignore the channel,
    # which is how a real finding gets missed.
    if args.slack_webhook:
        _send_slack(args.slack_webhook, findings, blocking, severity_counts, where, args.timeout)
    if args.webhook:
        _send_webhook(args.webhook, findings, blocking, severity_counts, where, args.timeout)

    if args.report and _write_report(args.report, findings, where, args.org or None):
        print(_colour(f"  Report written to {args.report}", _BOLD), file=sys.stderr)
        print("  It contains no secret values — safe to forward to whoever owns security.", file=sys.stderr)
        print(file=sys.stderr)

    # GitHub Actions step output, ignored everywhere else.
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        try:
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(f"findings={len(findings)}\n")
                fh.write(f"blocking={len(blocking)}\n")
                fh.write(f"highest={findings[0].get('severity', '')}\n")
        except OSError:
            pass

    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
