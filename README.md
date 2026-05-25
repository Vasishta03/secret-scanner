# leakscan

A fast, lightweight CLI tool that finds leaked API keys and secrets in your code, git history, and public GitHub profiles. Pure Python, zero config, installs in seconds.

[![PyPI version](https://img.shields.io/pypi/v/leakscan.svg)](https://pypi.org/project/leakscan/)
[![PyPI downloads](https://img.shields.io/pypi/dm/leakscan.svg)](https://pypi.org/project/leakscan/)
[![Tests](https://github.com/Vasishta03/secret-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Vasishta03/secret-scanner/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

![demo](https://raw.githubusercontent.com/Vasishta03/secret-scanner/main/demo.svg)

## Why leakscan?

Most secret scanners are either bloated (Docker required, YAML hell) or miss the things that matter (git history, staged changes, live verification). leakscan is different:

- **One command install:** `pip install leakscan`. No Docker, no config files, no setup.
- **84 secret patterns** covering every major provider (AWS, GCP, GitHub, Stripe, OpenAI, Supabase, Vercel, Datadog, and 70+ more).
- **Git history scanning:** Finds secrets that were committed and then deleted. Most scanners miss this entirely.
- **Staged scanning:** The `--staged` flag scans only what you're about to commit. Pre-commit hooks run in milliseconds, not minutes.
- **Live verification:** Tells you which leaked keys are still active right now.
- **Custom rules:** Drop a `.leakscan.yaml` in your repo and define your own patterns.

## Quick comparison

| Feature | leakscan | gitleaks | trufflehog |
|---------|----------|----------|------------|
| Install | `pip install` | Binary download | Binary / Docker |
| Config required | No | Yes (TOML) | No |
| Git history | Yes | Yes | Yes |
| Staged-only scan | Yes | No | No |
| Live verification | Yes (15+ services) | No | Limited |
| Custom patterns (YAML) | Yes | Yes | No |
| GitHub profile scan | Yes | No | Yes |
| Gist scanning | Yes | No | No |
| SARIF output | Yes | Yes | Yes |
| Pure Python | Yes | Go | Go |
| Pre-commit hook | Built-in | Manual | Manual |

## Installation

```bash
pip install leakscan
```

Both `secrets` and `leakscan` commands are available after install.

From source:

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

Makes safe read-only API calls to check if detected tokens are active. Supports GitHub, GitLab, Stripe, OpenAI, Anthropic, HuggingFace, SendGrid, Slack, npm, Replicate, Telegram, Google API, Sentry, and Vercel.

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

Installs a git pre-commit hook that runs `leakscan scan . --staged --severity HIGH`. Blocks commits containing secrets. Uses your `.secrets.baseline` automatically if present.

To suppress a specific line, add any of these comments:
- `# nosec`
- `# gitleaks:allow`
- `# secretscanner:allow`

## .secretignore

Create `.secretignore` in your project root to skip paths:

```
tests/fixtures/**
vendor/**
*.example
docs/
node_modules/**
```

Supports full `**` glob syntax.

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

### CRITICAL
Private keys (RSA, EC, PGP, OpenSSH, PKCS#8, DSA), AWS access keys and secret keys, GCP service accounts, Azure storage connection strings, Age encryption keys

### HIGH
GitHub tokens (PAT, OAuth, App, Refresh), GitLab tokens, Stripe live keys, OpenAI keys, Anthropic keys, HuggingFace tokens, Telegram bot tokens, Discord bot tokens and webhooks, Slack tokens and webhooks, SendGrid, Mailgun, npm tokens, PyPI tokens, Shopify tokens, DigitalOcean tokens, Dropbox tokens, Notion keys, Linear keys, Terraform Cloud tokens, Vault tokens, New Relic keys, Mapbox tokens, Square tokens, Twitter bearer tokens, Mailchimp keys, Supabase keys, Vercel tokens, Cloudflare keys, Datadog keys, PlanetScale tokens, Postman keys, Grafana tokens, Sentry tokens, Doppler tokens, Infisical tokens, Flutterwave keys, Coinbase tokens, Twitch secrets, Replicate tokens

### MEDIUM
Generic API keys, generic secrets, hardcoded passwords, Bearer tokens, JWT tokens, database URLs with credentials, basic auth in URLs, Stripe test keys, Firebase server keys, Google API keys, Slack app tokens, private key file paths, Sentry DSNs

### LOW
High-entropy strings (Shannon entropy detection for values in .env, YAML, config files)

## How it works

```
scanner/
  cli.py           Click-based CLI with 20+ options
  engine.py        Parallel file scanner (8 threads), git history parser, staged diff scanner
  patterns.py      84 regex patterns with severity classification
  config.py        .leakscan.yaml and pyproject.toml config loader
  entropy.py       Shannon entropy scorer for quoted and unquoted values
  verifier.py      Live API verification for 15+ services
  baseline.py      Fingerprint-based baseline save/load/compare
  reporter.py      Terminal, JSON, CSV, SARIF 2.1.0, disclosure report output
  ignorefile.py    .secretignore parser with ** glob support
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

## License

MIT
