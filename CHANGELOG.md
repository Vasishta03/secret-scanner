# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Fixed

- `.leakscanignore` / `.secretignore` patterns with more than two `**`
  segments could cause catastrophic regex backtracking, hanging a scan on
  a crafted pattern committed to the scanned repo. Such patterns are now
  rejected (treated as non-matching) instead of compiled.
- `~/.leakscanrc` is now written with `0600` permissions, since it can
  contain Slack/Discord webhook URLs.

## [0.4.0] - 2026-06-10

### Added

- 23 new secret patterns (107 total, up from 84): MongoDB, PostgreSQL, MySQL,
  and Redis connection strings, PEM certificates, Docker config auth,
  Kubernetes service account tokens, Firebase Admin SDK keys, Expo access
  tokens, Fly.io API tokens, WireGuard private keys, PagerDuty API keys,
  Elastic Cloud API keys, Azure AD client secrets, Cohere keys, Groq keys,
  Pinecone keys, Atlassian API tokens, PayPal client secrets, Razorpay key
  IDs, Postmark server tokens, Railway API tokens, and Cloudflare API tokens.
- Live verification for 11 more services (32 total, up from 21): Cohere,
  Groq, Pinecone, Notion, Linear, Mailgun, Postmark, Cloudflare, Railway,
  Supabase, and Azure AD.
- Multi-threaded scanning with a configurable `--threads` flag, a tqdm
  progress bar, and a benchmark summary (files scanned, elapsed time,
  files/sec).
- Memory-efficient chunked file reading with `--chunk-size`, automatic binary
  file detection, and `--max-file-size` to skip oversized files with a
  warning instead of loading them into memory.
- A `.pre-commit-hooks.yaml` entry so leakscan can be added to any repo's
  pre-commit configuration directly from the pre-commit hooks registry.
- Severity blast-radius blocks: every finding now explains what an attacker
  can do with the secret, how serious that is, and where to rotate it. Pass
  `--brief` for the previous compact table output.
- Git blame integration: findings in a working tree show who committed the
  secret, when, on which branch, and how long ago. Pass `--no-blame` to skip
  this.
- Secret age and scraping-risk classification (LOW, MEDIUM, HIGH, CRITICAL),
  with warnings for secrets older than 30 days ("HIGH probability scraped by
  bots") and 90 days ("ASSUME COMPROMISED").
- `.leakscanignore` file support with gitignore-style globs, `!pattern`
  negation, and trailing-slash directory rules, plus `leakscan ignore
  <pattern>` and `leakscan init` commands. The legacy `.secretignore`
  filename is still read.
- `--show-ignored` to list files skipped because of `.leakscanignore`.
- `leakscan purge`: generates (but does not run) `git filter-repo` and BFG
  Repo-Cleaner commands to remove a file, redact a commit's secrets, or
  redact every leaked value from git history, plus a force-push warning and
  a rotation reminder.
- Slack and Discord webhook notifications with `--notify slack/discord/both`,
  `--slack-webhook` / `--discord-webhook` / `--webhook`, `--notify-clean`,
  and credentials stored in `~/.leakscanrc`.

### Changed

- Default terminal output now prints a full blast-radius block per finding
  instead of a compact table. Pass `--brief` for the previous table format.
- The pre-commit hook (`leakscan install-hook` and `.pre-commit-hooks.yaml`)
  now runs with `--brief --no-blame` for faster, quieter output on staged
  changes.

## [0.3.1] - earlier release

- Bumped to 0.3.1, added GitHub Actions publish workflow.

## [0.3.0]

- Staged scanning, custom `.leakscan.yaml` / `pyproject.toml` configuration,
  20+ new patterns, and expanded live verifiers.

## [0.2.0]

- Live verification, 55+ patterns, SARIF output, baseline mode, GitHub gist
  scanning, and parallel scanning.
