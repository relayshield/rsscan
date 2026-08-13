# rsscan

Block commits and builds that introduce API keys, tokens and other machine credentials.

Detects 31 credential patterns: AWS IAM keys, GitHub PATs, Stripe secrets, Slack tokens, private keys, and LLM provider keys (OpenAI, Anthropic, Google, Groq, xAI, Replicate).

**Free, and it runs entirely on your machine.** No account, no API key, no network call. Your source code never leaves the host. Matching happens locally against patterns shipped inside the package.

**The pre-commit hook is the point.** It runs *before* the commit enters git history. A CI check only sees the secret after a push, and by then it is in history and has to be rotated even if you delete the commit. The CI integrations below are a backstop, not a substitute.

**New in 0.2.0:** `rsscan --deps` counts the accounts that can publish into your npm dependencies. See [Counting who can publish your dependencies](#counting-who-can-publish-your-dependencies).

## Install

### pre-commit hook (recommended)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/RelayShield/rsscan
    rev: v0.2.0
    hooks:
      - id: rsscan
```

```bash
pre-commit install
```

That is the whole setup. Nothing to configure, nothing to sign up for.

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0        # required: the range needs history
- uses: RelayShield/rsscan@v0.2.0
  with:
    fail-on: HIGH
```

Findings are annotated **inline on the changed lines in the pull request's Files tab**, so a
developer sees them where the code is rather than in collapsed build output. Blocking findings
(at or above `fail-on`) appear as errors; everything else appears as warnings.

This needs no token, no `permissions:` block and no GitHub App. Annotations are emitted as
workflow commands, not through the Checks API. Turn them off with `annotate: off` if you only
want the log.

Annotations never contain the secret value. Each one carries the credential type, its severity,
and the fingerprint you would add to `.relayshield-allowlist` to suppress a false positive.

### GitLab CI/CD

```yaml
rsscan:
  image: relayshield/rsscan:0.2.0
  variables:
    GIT_DEPTH: 0        # required: GitLab shallow-clones, and a shallow clone
                        # yields an empty diff, so the job would pass having
                        # scanned nothing
    RSSCAN_REV_RANGE: "origin/$CI_DEFAULT_BRANCH...HEAD"
    RSSCAN_FAIL_ON: HIGH
  script: ["rsscan"]
```

### CircleCI

```yaml
orbs:
  rsscan: relayshield/rsscan@0.1.0
workflows:
  main:
    jobs:
      - rsscan/scan
```

### Docker: Bitbucket Pipelines, Tekton, Drone, Woodpecker, Harness, anything else

```bash
docker run --rm -v "$PWD:/workspace" \
  -e RSSCAN_REV_RANGE=origin/main...HEAD \
  relayshield/rsscan:0.2.0
```

Bitbucket Pipelines:

```yaml
- step:
    script:
      - pipe: docker://relayshield/rsscan:0.2.0
        variables:
          RSSCAN_REV_RANGE: "origin/main...HEAD"
```

### Jenkins, Azure DevOps, or any shell

```bash
pip install rsscan
RSSCAN_REV_RANGE="origin/main...HEAD" rsscan
```

## How it works

Scans the diff locally and fails on a finding at or above `--fail-on` (default `HIGH`).

**Only added lines are scanned.** Secrets already in your files are not re-flagged, so the tool does not become unbypassable noise on a repo with legacy findings.

**Nothing is transmitted and nothing is printed.** There is no scan endpoint to send code to. Matched values never appear in output either: findings carry a file, a line and a non-reversible fingerprint, so a scan is safe to run in CI without leaking the secret into build logs.

```
  rsscan: secrets detected in staged changes

  CRITICAL AWS IAM Access Key
           src/config.py:14
           fingerprint sha256:1a5d44a2dca19669

  Commit refused.

  Remove the value and load it from a secrets manager or environment
  variable instead. If it has already left this machine, rotate it.

  False positive? Add the fingerprint to .relayshield-allowlist:
      echo 'sha256:1a5d44a2dca19669' >> .relayshield-allowlist

  To bypass entirely: git commit --no-verify
```

## Configuration

Every flag has an environment variable equivalent, which is how the CI clients drive it.

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--fail-on` | `RSSCAN_FAIL_ON` | `HIGH` | Lowest severity that fails. `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`. |
| `--rev-range` | `RSSCAN_REV_RANGE` | *(staged)* | Scan a commit range instead of staged changes. |
| `--allowlist` | `RSSCAN_ALLOWLIST` | `.relayshield-allowlist` | Fingerprints to ignore. |
| `--report` | `RSSCAN_REPORT` | *(off)* | Write a shareable exposure report to this path. |
| `--org` | `RSSCAN_ORG` | *(off)* | Opt in to reporting adoption for your org domain. |
| `--strict` / `--no-strict` | `RSSCAN_STRICT` | *see below* | Fail when the scan cannot run. |
| `--annotate` | `RSSCAN_ANNOTATE` | `auto` | Inline PR annotations. `auto` enables them inside GitHub Actions only; `github` forces; `off` disables. |
| `--slack-webhook` | `RSSCAN_SLACK_WEBHOOK` | *(off)* | POST a findings summary to your own Slack incoming webhook. |
| `--webhook` | `RSSCAN_WEBHOOK` | *(off)* | POST findings as JSON to an endpoint you control. |

### Failure behaviour differs by mode, on purpose

**Pre-commit fails open.** If the scan genuinely cannot run (an unreadable diff, a broken git invocation), it warns on stderr and lets the commit through. A hook that wedges every commit gets uninstalled, and then it catches nothing.

**CI fails closed.** A gate that silently reports success when it could not actually run is worse than no gate. It manufactures false assurance. Override either way with `--strict` / `--no-strict` or `RSSCAN_STRICT`.

### Allowlisting

The allowlist holds **fingerprints, not secrets**: a file containing the actual values would be the same mistake this tool exists to prevent.

```
# .relayshield-allowlist
sha256:1a5d44a2dca19669   # documented example key in docs/quickstart.md
```

## Sending findings somewhere

Two push channels, both opt-in, both pointing at somewhere you own. (The third delivery
channel, inline PR annotations, is automatic in GitHub Actions; see above.) Without one of
these flags rsscan makes no network call at all.

```bash
# Slack
rsscan --slack-webhook https://hooks.slack.com/services/T000/B000/xxxx

# Any JSON receiver you control
rsscan --webhook https://hooks.example.com/rsscan
```

**None of them ever carries a secret value.** Each finding is transmitted as its credential type,
severity, file, line and fingerprint. That is the same guarantee as `--report`. The Slack message says so
in its own footer, so whoever reads the channel knows it is safe to leave there.

They fire only when there are findings. A notification on every clean build trains people to
ignore the channel, which is how a real finding gets missed.

**Delivery failure never changes the exit code.** If Slack is unreachable, rsscan warns on stderr
and the build result stands on the scan alone: a gate should block on secrets, not on a flaky
notification endpoint.

The generic webhook posts:

```json
{
  "tool": "rsscan", "version": "0.2.0", "scanned": "origin/main...HEAD",
  "repo": "acme/api", "ref": "feature/pay", "build_url": "https://github.com/...",
  "findings_count": 2, "blocking_count": 2, "highest_severity": "CRITICAL",
  "severity_counts": {"CRITICAL": 2},
  "findings": [
    {"type": "aws_access_key", "severity": "CRITICAL", "description": "AWS IAM Access Key",
     "file": "src/config.py", "line": 3, "fingerprint": "sha256:1a5d44a2dca19669"}
  ],
  "detected_at": "2026-08-04T15:00:00+00:00"
}
```

## Counting who can publish your dependencies

```bash
rsscan --deps                              # auto-detects package-lock.json, then package.json
rsscan --deps path/to/package-lock.json    # or point it at one
```

A self-replicating npm worm does not start with malicious code. It starts with a maintainer account: an infostealer takes the publish token out of somebody's `.npmrc`, and a patch version nobody reads gets published four steps before there is any artifact for a scanner to analyse.

`--deps` tells you how large that surface is for your own tree:

```text
  Who can publish your dependencies
     433  dependencies in package-lock.json
     275  distinct publisher accounts can push code into them
     126  on personal webmail (no SSO, no central revocation)
      28  role or automation addresses
```

Each package is resolved to its `maintainers` list plus the `_npmUser` who actually published the version you would install. Counts are of distinct email addresses, which is a proxy for accounts and imperfect in both directions: one person with two addresses counts twice, two people sharing one count once.

**It reads locally and queries only `registry.npmjs.org`.** No account, no API key, no network call to RelayShield, and no telemetry. It prints integers and names nobody.

**It always exits 0.** There is no dependency count that constitutes a build failure, so this is a report and deliberately not a gate.

If a package cannot be resolved, that count is printed separately and is *not* folded into the totals. A package whose publishers we could not look up is not a package with no publishers, and collapsing those two into one number is how a tool ends up quietly reassuring you.

## Sharing a finding with your security team

```bash
rsscan --report exposure.md
```

Writes a Markdown report you can attach to a ticket or forward by email. It contains **no secret values**, only fingerprints, so it is safe to share.

## Optional: telling us your org uses rsscan

```bash
rsscan --org yourcompany.com
```

**Off by default and entirely optional.** When enabled it sends only your org domain, an anonymous per-machine id, the tool version, and how many findings there were by severity.

It never sends file paths, fingerprints, repository names, source code, or the secrets themselves. There is no mechanism in the tool to do so.

## What this tool cannot tell you

rsscan stops credentials *before* they enter git history. It cannot see credentials that have already left: a key committed last year, or one leaked through a dependency, a published package or a container image, may already be indexed and scraped.

Answering that needs a view of what is public, plus the identity layer secret scanners do not cover at all: workforce credentials surfacing in infostealer logs and breach dumps, SIM-swap risk on staff accounts, and session/token exposure. That is what [RelayShield](https://api.relayshield.net/developers?source=rsscan) does.

## Pricing

rsscan is free. There is no paid tier of this tool, no scan quota, and no account.

## Licence

MIT
