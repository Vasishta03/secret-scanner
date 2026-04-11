# secret-scanner

A CLI tool that scans local codebases and public GitHub repos for leaked API keys and secrets — including secrets deleted from code but still alive in git history.

![demo](https://raw.githubusercontent.com/Vasishta03/secret-scanner/main/demo.svg)

## Features

**Detection**
- 55+ regex patterns: AWS, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, Twilio, Discord, Telegram, npm, PyPI, Shopify, DigitalOcean, Dropbox, Notion, Linear, Terraform, Vault, New Relic, Mapbox, Square, Mailchimp, and more
- Shannon entropy detection for unquoted values (`.env`, YAML, INI files)
- Inline suppression: `# nosec`, `# gitleaks:allow`, `# secretscanner:allow`
- AWS Access Key ID pattern anchored to real prefixes (`AKIA`, `AGPA`, `AROA`, etc.) — no false positives on random uppercase strings

**Verification**
- `--verify` makes live API calls to check if found secrets are still active
- Supports: GitHub, GitLab, Stripe, OpenAI, Anthropic, HuggingFace, SendGrid, Slack, npm, Replicate

**Scanning scope**
- Local file trees (parallel, 8 threads)
- Git history: commits, any branch, with `--since DATE` for date-bounded scans
- GitHub profile: all public repos for a user or org
- GitHub repo by URL: `secrets scan https://github.com/owner/repo`
- GitHub Gists: `--include-gists`

**CI/CD integration**
- Exit code `1` on any CRITICAL or HIGH finding
- SARIF output for GitHub Security tab / GitLab SAST
- Baseline mode: save known findings, only alert on new secrets
- Pre-commit hook with automatic baseline support
- `.secretignore` with full `**` glob support

**Output formats**
- Terminal (rich table with severity colors)
- JSON (with fingerprints and verification status)
- CSV
- SARIF 2.1.0
- Markdown disclosure report

## Installation

```bash
pip install leakscan
```

Or from source:

```bash
git clone https://github.com/Vasishta03/secret-scanner
cd secret-scanner
pip install -e .
```

## Usage

**Basic local scan**
```bash
secrets scan ./myproject
secrets scan . --severity HIGH --no-entropy
```

**Scan git history** (catches deleted secrets)
```bash
secrets scan . --history
secrets scan . --history --depth 500 --since 2023-01-01
secrets scan . --history --branch main
```

**Verify secrets are live**
```bash
secrets scan . --verify
secrets scan . --verify --severity HIGH
```

**Scan a public GitHub repo by URL**
```bash
secrets scan https://github.com/owner/repo
secrets scan https://github.com/owner/repo --history --verify
```

**Scan a GitHub user's repos and gists**
```bash
secrets scan --github username
secrets scan --github username --include-gists
secrets scan --github username --history --token $GITHUB_TOKEN
```

**Baseline mode** (CI-friendly: only alert on new findings)
```bash
secrets scan . --save-baseline .secrets.baseline
secrets scan . --baseline .secrets.baseline
```

**Output formats**
```bash
secrets scan . --format json --output results.json
secrets scan . --format csv  --output findings.csv
secrets scan . --format sarif --output results.sarif
secrets scan --github username --format disclosure --output report.md
```

**Redact secrets in output** (safe for shared logs)
```bash
secrets scan . --redact
secrets scan . --format json --redact --output safe-results.json
```

## Install as pre-commit hook

```bash
cd your-git-repo
secrets install-hook
```

The hook uses `.secrets.baseline` automatically if present, suppressing already-known findings.

To suppress a specific line: add `# nosec` or `# gitleaks:allow` to the line.

## .secretignore

Create `.secretignore` in your project root to exclude paths:

```
tests/fixtures/**
vendor/**
*.example
docs/
```

Supports full `**` glob syntax (like `.gitignore`).

## GitHub Actions

```yaml
- name: Scan for secrets
  run: secrets scan . --severity HIGH --no-entropy --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Severity levels

| Level    | Examples |
|----------|----------|
| CRITICAL | Private keys (RSA/EC/PGP/OpenSSH/PKCS#8), AWS credentials, Azure storage keys |
| HIGH     | GitHub/GitLab tokens, Stripe live keys, OpenAI/Anthropic keys, Slack tokens, npm/PyPI tokens, Telegram/Discord bots |
| MEDIUM   | Generic API keys, hardcoded passwords, JWT tokens, database URLs, Stripe test keys |
| LOW      | High-entropy strings (possible unknown secrets) |

## Why history scanning matters

Deleting a secret from your latest commit does **not** remove it from git history. Anyone who clones your repo can run `git log -p` and recover it. Most scanners miss this completely.

```bash
# Find secrets that were committed at any point in the last year
secrets scan . --history --depth 1000 --since 2024-01-01
```

## Architecture

```
scanner/
  cli.py           entry point (click)
  engine.py        file walker, parallel scanner, git history, shared kernel
  patterns.py      55+ regex patterns
  entropy.py       Shannon entropy scorer (quoted + unquoted values)
  verifier.py      live API verification (10 services)
  baseline.py      save/load/compare baseline fingerprints
  reporter.py      terminal/JSON/CSV/SARIF/disclosure output
  ignorefile.py    .secretignore parser with ** glob support
  github/
    fetcher.py     GitHub API client: repos, gists, commit history
```

## Contributing

```bash
git clone https://github.com/Vasishta03/secret-scanner
cd secret-scanner
pip install -e ".[dev]"
pytest tests/
```

To add a pattern: edit `scanner/patterns.py` and add a test in `tests/test_scanner.py`.

## License

MIT
