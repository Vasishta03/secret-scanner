# secret-scanner

A CLI tool that scans local codebases and public GitHub repos for leaked API keys and secrets — including secrets that were deleted from code but still exist in git history.

## Features

- 30+ regex patterns: AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Twilio, SendGrid, and more
- Shannon entropy detection for secrets not covered by regex
- **Git history scanning** — finds secrets in past commits, even after they were deleted
- Scan any public GitHub repo directly by URL
- Scan all public repos for a GitHub user or org
- CI/CD gate: exits with code `1` on any CRITICAL or HIGH finding
- Output as terminal table, JSON, CSV, or a markdown disclosure report
- `.secretignore` file support (same glob syntax as `.gitignore`)
- Pre-commit hook installer

## Installation

```bash
pip install secret-scanner
```

Or from source:

```bash
git clone https://github.com/yourusername/secret-scanner
cd secret-scanner
pip install -e .
```

## Usage

**Scan a local project**
```bash
secrets scan ./myproject
```

**Scan including git history** (catches deleted secrets)
```bash
secrets scan . --history
secrets scan . --history --depth 200
```

**Scan a public GitHub repo by URL**
```bash
secrets scan https://github.com/owner/repo
secrets scan https://github.com/owner/repo --history
```

**Scan all public repos for a GitHub user**
```bash
secrets scan --github username
secrets scan --github username --repo specific-repo
```

**Use a GitHub token** (avoids rate limiting, required for history scans)
```bash
export GITHUB_TOKEN=ghp_yourtoken
secrets scan --github username --history
```

**Filter by severity**
```bash
secrets scan . --severity HIGH
```

**Output formats**
```bash
secrets scan . --format json --output results.json
secrets scan . --format csv  --output results.csv
secrets scan --github username --format disclosure --output report.md
```

**Disable entropy detection** (regex patterns only, fewer false positives)
```bash
secrets scan . --no-entropy
```

## Install as pre-commit hook

Runs automatically before every `git commit` and blocks if CRITICAL or HIGH secrets are found.

```bash
cd your-git-repo
secrets install-hook
```

## .secretignore

Create a `.secretignore` file in your project root to exclude paths:

```
tests/fixtures/
*.example
config/local/
vendor/
```

Uses the same glob syntax as `.gitignore`.

## Severity levels

| Level | Examples |
|-------|----------|
| CRITICAL | Private keys (RSA/EC/PGP/OpenSSH), AWS credentials, GCP service accounts |
| HIGH | GitHub tokens, Stripe live keys, OpenAI/Anthropic keys, Slack tokens |
| MEDIUM | Generic API keys, hardcoded passwords, JWT tokens, database URLs |
| LOW | High-entropy strings that may be undocumented secrets |

## CI/CD

Exit code is `1` when any CRITICAL or HIGH finding is detected, `0` otherwise.

```yaml
# GitHub Actions example
- name: Scan for secrets
  run: secrets scan . --severity HIGH --no-entropy
```

## Why history scanning matters

Deleting a secret from your code does **not** remove it from git history. Anyone who clones your repo can recover it with `git log`. Tools that only scan the current file tree miss this entirely.

```bash
secrets scan . --history --depth 500
```

## Architecture

```
scanner/
  cli.py          entry point (click)
  engine.py       file walker, git history scanner, shared scan kernel
  patterns.py     30+ regex patterns
  entropy.py      Shannon entropy scorer
  reporter.py     terminal/JSON/CSV/disclosure output
  ignorefile.py   .secretignore parser
  github/
    fetcher.py    GitHub API client (no cloning)
```

## Contributing

```bash
git clone https://github.com/yourusername/secret-scanner
cd secret-scanner
pip install -e ".[dev]"
pytest tests/
```

To add a new pattern, edit `scanner/patterns.py` and add a test in `tests/test_scanner.py`.

## License

MIT
