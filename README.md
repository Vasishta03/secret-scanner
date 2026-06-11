# leakscan

A fast, lightweight CLI tool that finds leaked API keys and secrets in your code, git history, and public GitHub profiles. Pure Python, zero config, installs in seconds.

[![PyPI version](https://img.shields.io/pypi/v/leakscan.svg)](https://pypi.org/project/leakscan/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/leakscan?period=total&units=ABBREVIATION&left_color=GREY&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/leakscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

![demo](https://raw.githubusercontent.com/Vasishta03/secret-scanner/main/demo.svg)

## Why leakscan?

Most secret scanners are either bloated (Docker required, YAML hell) or miss the things that matter (git history, staged changes, live verification). leakscan is different:

- **One command install:** `pip install leakscan`. No Docker, no config files, no setup.
- **107 secret patterns** covering every major provider (AWS, GCP, GitHub, Stripe, OpenAI, Supabase, Vercel, Datadog, MongoDB, PostgreSQL, Kubernetes, and 90+ more).
- **Git history scanning:** Finds secrets that were committed and then deleted. Most scanners miss this entirely.
- **Staged scanning:** The `--staged` flag scans only what you're about to commit. Pre-commit hooks run in milliseconds, not minutes.
- **Live verification:** Makes safe, read-only API calls to check whether a leaked key is still active, across 30+ services.
- **Know your blast radius:** Every finding explains what an attacker could do with it, how serious that is, and exactly where to rotate it.
- **Git blame and secret age:** See who committed a secret, when, on which branch, and how likely it is to have already been scraped by bots.
- **Fast on big repos:** Multi-threaded scanning with a live progress bar, chunked file reading that keeps memory flat, and a benchmark summary at the end.
- **.leakscanignore:** A gitignore-style ignore file with negation support, plus `leakscan ignore` and `leakscan init` helper commands.
- **History cleanup helper:** `leakscan purge` generates the `git filter-repo` / BFG Repo-Cleaner commands to scrub a secret from history, for you to review and run.
- **Slack / Discord alerts:** `--notify slack`, `--notify discord`, or `--notify both` posts a scan summary straight to your team's channel.
- **Custom rules:** Drop a `.leakscan.yaml` in your repo and define your own patterns.

## Quick comparison

| Feature | leakscan | gitleaks | trufflehog |
|---------|----------|----------|------------|
| Install | pip / brew / uvx / curl | Binary download | Binary / Docker |
| Config required | No | Yes (TOML) | No |
| Git history | Yes | Yes | Yes |
| Staged-only scan | Yes | No | No |
| Live verification | Yes (30+ services) | No | Limited |
| Custom patterns (YAML) | Yes | Yes | No |
| GitHub profile scan | Yes | No | Yes |
| Gist scanning | Yes | No | No |
| SARIF output | Yes | Yes | Yes |
| Pure Python | Yes | Go | Go |
| Pre-commit hook | Built-in | Manual | Manual |
| Multi-threaded scanning | Yes | Yes | Yes |
| Blast-radius remediation guidance | Yes | No | No |
| Git blame / secret age | Yes | No | No |
| History cleanup command generator | Yes (`purge`) | No | No |
| Slack / Discord alerts | Yes | No | No |

## Installation

**Homebrew** (macOS / Linux)
```bash
brew tap Vasishta03/leakscan
brew install leakscan
```

**pipx** (isolated, recommended for CLI tools)
```bash
pipx install leakscan
```

**uvx / uv**
```bash
uvx leakscan --help          # run without installing
uv tool install leakscan     # permanent install
```

**pip**
```bash
pip install leakscan
```

**curl one-liner**
```bash
curl -fsSL https://raw.githubusercontent.com/Vasishta03/secret-scanner/main/install.sh | sh
```

**From source**
```bash
git clone https://github.com/Vasishta03/secret-scanner
cd secret-scanner
pip install -e .
```

## Usage

### Scan a local project

```bash
leakscan scan ./myproject
leakscan scan . --severity HIGH
```

### Understanding a finding

By default, every finding is printed as a full block: what was found, what an
attacker could do with it, how serious that is, where to rotate it, and (inside
a git repo) who committed it and how long it has been exposed.

```
[CRITICAL] AWS Access Key ID
  File: config.py:3
  Match: AKIAIOSFODNN7EXAMPLE
  If leaked: Combined with its secret key, an attacker can call any AWS API the
  underlying IAM identity is permitted to use, including launching compute,
  reading S3 buckets, and modifying IAM policies.
  Blast radius: Full cloud account compromise
  Rotate at: https://console.aws.amazon.com/iam/home#/security_credentials
  Git blame: dev@example.com - commit a1b2c3d4e5f6 (45d ago, branch main)
    "add aws credentials"
  Secret age: 45d - scraping risk: CRITICAL
  This secret has been in git history for over 30 days. HIGH probability it has
  already been scraped by automated bots that continuously crawl public
  repositories for credentials.
```

Use `--brief` for the old compact one-line-per-finding table, and `--no-blame`
to skip the git blame and secret-age lookups (faster on large repos):

```bash
leakscan scan . --brief
leakscan scan . --no-blame
```

### Scan only staged changes (pre-commit)

```bash
leakscan scan . --staged
```

This is what the built-in pre-commit hook uses. It only checks the diff you're about to commit, so it finishes instantly even on large repos.

### Scan git history

Deleted a secret and pushed? It's still in your history. Find it:

```bash
leakscan scan . --history
leakscan scan . --history --depth 500 --since 2024-01-01
leakscan scan . --history --branch main
```

### Verify leaked secrets are still live

```bash
leakscan scan . --verify
```

Makes safe read-only API calls to check if detected tokens are active. Supports 30+ services, including GitHub, GitLab, Stripe, OpenAI, Anthropic, HuggingFace, SendGrid, Slack, npm, Replicate, Telegram, Google API, Sentry, Vercel, Cloudflare, Supabase, Notion, Linear, Mailgun, Postmark, Railway, Cohere, Groq, Pinecone, Datadog, Twilio, and Azure AD.

### Scan a GitHub repo by URL

```bash
leakscan scan https://github.com/owner/repo
leakscan scan https://github.com/owner/repo --history --verify
```

### Scan a GitHub user's entire profile

```bash
leakscan scan --github username
leakscan scan --github username --include-gists
leakscan scan --github username --history --token $GITHUB_TOKEN
```

### Output formats

```bash
leakscan scan . --format json --output results.json
leakscan scan . --format csv --output findings.csv
leakscan scan . --format sarif --output results.sarif
leakscan scan --github user --format disclosure --output report.md
```

### Redact secrets in output

```bash
leakscan scan . --redact
leakscan scan . --format json --redact --output safe-results.json
```

### Baseline mode (CI-friendly)

Save current findings as known, then only alert on new ones:

```bash
leakscan scan . --save-baseline .secrets.baseline
leakscan scan . --baseline .secrets.baseline
```

### Performance on large repos

Scanning is multi-threaded and streams files in fixed-size chunks, so memory
usage stays flat even on repos with very large files:

```bash
leakscan scan . --threads 16
leakscan scan . --chunk-size 2000000
leakscan scan . --max-file-size 100
```

A live progress bar tracks files as they're scanned, and a benchmark summary
is printed at the end:

```
Scanned 4213 file(s) in 1.84s (2289.7 files/sec)
```

`--threads` defaults to your CPU count, `--chunk-size` defaults to 1,000,000
bytes, and `--max-file-size` defaults to 50 MB (larger files are skipped with
a warning instead of being read into memory). Binary files are detected and
skipped automatically. Use `--no-progress` to disable the progress bar, for
example in CI logs.

## Custom configuration

Create `.leakscan.yaml` in your project root:

```yaml
custom_patterns:
  - name: "Internal Service Token"
    regex: "intk_[a-zA-Z0-9]{32}"
    severity: HIGH
    description: "Internal microservice auth token"

  - name: "Company OAuth Secret"
    regex: "myco_secret_[a-zA-Z0-9]{40}"
    severity: CRITICAL
    description: "OAuth client secret for internal apps"

exclude_paths:
  - "vendor/**"
  - "*.min.js"
  - "testdata/**"

entropy_threshold: 4.0
severity: HIGH
```

Or use `[tool.leakscan]` in your existing `pyproject.toml`:

```toml
[tool.leakscan]
severity = "HIGH"
entropy_threshold = 4.0
exclude_paths = ["vendor/**", "docs/**"]
```

## Pre-commit hook

```bash
leakscan install-hook
```

Installs a git pre-commit hook that runs `leakscan scan . --staged --severity HIGH --brief --no-blame`. Blocks commits containing secrets. Uses your `.secrets.baseline` automatically if present.

To suppress a specific line, add any of these comments:
- `# nosec`
- `# gitleaks:allow`
- `# secretscanner:allow`

## .leakscanignore

Create `.leakscanignore` in your project root to skip paths, using
gitignore-style syntax. The legacy `.secretignore` filename is still read for
backward compatibility.

```
tests/fixtures/**
vendor/**
*.example
docs/
node_modules/**

# Negation: re-include a path an earlier pattern ignored
!important.env
```

Supports full `**` glob syntax, trailing-slash directory patterns (`docs/`
matches `docs/` at any depth), and `!pattern` negation.

```bash
leakscan init                   # create .leakscanignore with sensible defaults
leakscan ignore "*.test.js"     # append a pattern to .leakscanignore
leakscan scan . --show-ignored  # list files skipped because of .leakscanignore
```

## Cleaning up git history

If a scan finds a secret that was committed in the past, `leakscan purge`
generates (but does not run) the commands to remove it with `git filter-repo`
or BFG Repo-Cleaner:

```bash
leakscan purge --file config/secrets.yaml
leakscan purge --commit a1b2c3d4
leakscan purge --all --method filter-repo
```

`--file` removes a file from every commit, `--commit` shows what a commit
changed so you can target it, and `--all` walks you through redacting every
leaked value found by `leakscan scan . --format json`. Every report ends with
a force-push warning (use `--force-with-lease`, never plain `--force`) and a
reminder that rewriting history does not undo a leak, so rotate the credential
too.

## Notifications (Slack / Discord)

Send a summary of a scan to Slack and/or Discord:

```bash
leakscan scan . --notify slack --slack-webhook https://hooks.slack.com/services/...
leakscan scan . --notify discord --discord-webhook https://discord.com/api/webhooks/...
leakscan scan . --notify both
leakscan scan . --notify slack --notify-clean
```

`--notify` accepts `slack`, `discord`, or `both`. To avoid passing webhook
URLs every time, save them once in `~/.leakscanrc`:

```
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

By default, a notification is only sent when secrets are found. Pass
`--notify-clean` to also post a message when a scan comes back clean.

## GitHub Actions

```yaml
- name: Install leakscan
  run: pip install leakscan

- name: Scan for secrets
  run: leakscan scan . --severity HIGH --no-entropy --format sarif --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Detected secret types

107 patterns in total, each with its own blast-radius explanation and rotation link.

### CRITICAL
Private keys (RSA, EC, PGP, OpenSSH, PKCS#8, DSA), AWS access keys and secret keys, GCP service accounts, Azure storage connection strings and Azure AD client secrets, Age encryption keys, MongoDB/PostgreSQL/MySQL connection strings, Kubernetes service account tokens, Firebase Admin SDK keys, WireGuard private keys

### HIGH
GitHub tokens (PAT, OAuth, App, Refresh), GitLab tokens, Stripe live keys, OpenAI keys, Anthropic keys, HuggingFace tokens, Telegram bot tokens, Discord bot tokens and webhooks, Slack tokens and webhooks, SendGrid, Mailgun, npm tokens, PyPI tokens, Shopify tokens, DigitalOcean tokens, Dropbox tokens, Notion keys, Linear keys, Terraform Cloud tokens, Vault tokens, New Relic keys, Mapbox tokens, Square tokens, Twitter bearer tokens, Mailchimp keys, Supabase keys, Vercel tokens, Cloudflare keys and API tokens, Datadog keys, PlanetScale tokens, Postman keys, Grafana tokens, Sentry tokens, Doppler tokens, Infisical tokens, Flutterwave keys, Coinbase tokens, Twitch secrets, Replicate tokens, Redis connection strings, Docker config auth, Expo access tokens, Fly.io API tokens, PagerDuty API keys, Elastic Cloud API keys, Cohere keys, Groq keys, Pinecone keys, Atlassian API tokens, PayPal client secrets, Razorpay key IDs, Postmark server tokens, Railway API tokens

### MEDIUM
Generic API keys, generic secrets, hardcoded passwords, Bearer tokens, JWT tokens, database URLs with credentials, basic auth in URLs, Stripe test keys, Firebase server keys, Google API keys, Slack app tokens, private key file paths, Sentry DSNs, PEM certificates

### LOW
High-entropy strings (Shannon entropy detection for values in .env, YAML, config files)

## How it works

```
scanner/
  cli.py           Click-based CLI with 30+ options and ignore/init/purge commands
  engine.py        Multi-threaded, chunked file scanner; git history parser; staged diff scanner
  patterns.py      107 regex patterns with severity classification
  config.py        .leakscan.yaml and pyproject.toml config loader
  entropy.py       Shannon entropy scorer for quoted and unquoted values
  verifier.py      Live API verification for 30+ services
  remediation.py   Per-pattern blast-radius, consequence, and rotation-link data
  blame.py         Git blame lookups, secret age, and scraping-risk classification
  baseline.py      Fingerprint-based baseline save/load/compare
  reporter.py      Terminal (block and brief), JSON, CSV, SARIF 2.1.0, disclosure report output
  ignorefile.py    .leakscanignore parser (gitignore syntax, ** globs, negation)
  purge.py         git filter-repo / BFG command generator for history cleanup
  notify.py        Slack and Discord webhook notifications, ~/.leakscanrc storage
  github/
    fetcher.py     GitHub API client: repos, gists, commit diffs, rate limit handling
```

## Contributing

```bash
git clone https://github.com/Vasishta03/secret-scanner
cd secret-scanner
pip install -e ".[dev]"
pytest tests/ -v
```

To add a new pattern: edit `scanner/patterns.py`, add a corresponding test in `tests/test_scanner.py`.

To add a new verifier: edit `scanner/verifier.py`, add the extractor regex and verification logic.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
