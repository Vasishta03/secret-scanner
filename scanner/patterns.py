import re
from dataclasses import dataclass


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    severity: str
    description: str


def _p(name: str, pattern: str, severity: str, description: str) -> Pattern:
    return Pattern(
        name=name,
        regex=re.compile(pattern, re.IGNORECASE),
        severity=severity,
        description=description,
    )


PATTERNS: list[Pattern] = [
    _p("AWS Access Key ID",        r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",              "CRITICAL", "AWS access key ID"),
    _p("AWS Secret Access Key",    r"(?i)aws(.{0,20})?['\"\\s]([0-9a-zA-Z/+]{40})",        "CRITICAL", "AWS secret access key"),
    _p("GCP Service Account",      r'"type"\s*:\s*"service_account"',                       "CRITICAL", "GCP service account JSON"),
    _p("RSA Private Key",          r"-----BEGIN RSA PRIVATE KEY-----",                      "CRITICAL", "RSA private key"),
    _p("EC Private Key",           r"-----BEGIN EC PRIVATE KEY-----",                       "CRITICAL", "EC private key"),
    _p("PGP Private Key",          r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                "CRITICAL", "PGP private key block"),
    _p("OpenSSH Private Key",      r"-----BEGIN OPENSSH PRIVATE KEY-----",                  "CRITICAL", "OpenSSH private key"),
    _p("GitHub Personal Token",    r"ghp_[0-9a-zA-Z]{36}",                                 "HIGH", "GitHub personal access token"),
    _p("GitHub OAuth Token",       r"gho_[0-9a-zA-Z]{36}",                                 "HIGH", "GitHub OAuth token"),
    _p("GitHub App Token",         r"(ghu|ghs)_[0-9a-zA-Z]{36}",                           "HIGH", "GitHub app/server token"),
    _p("GitHub Refresh Token",     r"ghr_[0-9a-zA-Z]{76}",                                 "HIGH", "GitHub refresh token"),
    _p("Stripe Live Secret Key",   r"sk_live_[0-9a-zA-Z]{24,}",                            "HIGH", "Stripe live secret key"),
    _p("Stripe Live Publishable",  r"pk_live_[0-9a-zA-Z]{24,}",                            "HIGH", "Stripe live publishable key"),
    _p("Twilio Account SID",       r"AC[0-9a-fA-F]{32}",                                   "HIGH", "Twilio account SID"),
    _p("Twilio Auth Token",        r"(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]",          "HIGH", "Twilio auth token"),
    _p("SendGrid API Key",         r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",         "HIGH", "SendGrid API key"),
    _p("Slack Bot Token",          r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",     "HIGH", "Slack bot token"),
    _p("Slack User Token",         r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",     "HIGH", "Slack user token"),
    _p("Slack Webhook",            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "HIGH", "Slack incoming webhook"),
    _p("Mailgun API Key",          r"key-[0-9a-zA-Z]{32}",                                 "HIGH", "Mailgun API key"),
    _p("Anthropic API Key",        r"sk-ant-[0-9a-zA-Z\-]{40,}",                           "HIGH", "Anthropic API key"),
    _p("OpenAI API Key",           r"sk-[0-9a-zA-Z]{48}",                                  "HIGH", "OpenAI API key"),
    _p("HuggingFace Token",        r"hf_[a-zA-Z0-9]{34,}",                                 "HIGH", "HuggingFace API token"),
    _p("Generic API Key",          r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?", "MEDIUM", "Generic API key assignment"),
    _p("Generic Secret",           r"(?i)(secret|secret_key|client_secret)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?", "MEDIUM", "Generic secret assignment"),
    _p("Generic Password",         r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",               "MEDIUM", "Hardcoded password"),
    _p("Bearer Token",             r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",                  "MEDIUM", "Bearer token in header"),
    _p("JWT Token",                r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "MEDIUM", "JWT token"),
    _p("Database URL",             r"(?i)(mongodb|postgres|mysql|redis):\/\/[^\s'\"]+:[^\s'\"@]+@", "MEDIUM", "Database URL with credentials"),
    _p("Basic Auth in URL",        r"https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",                 "MEDIUM", "Basic auth credentials in URL"),
    _p("Stripe Test Key",          r"sk_test_[0-9a-zA-Z]{24,}",                            "MEDIUM", "Stripe test secret key"),
    _p("Firebase Config",          r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",            "MEDIUM", "Firebase server key"),
    _p("Google API Key",           r"AIza[0-9A-Za-z\-_]{35}",                              "MEDIUM", "Google API key"),
]
