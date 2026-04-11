import re
from dataclasses import dataclass


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    severity: str
    description: str


def _p(name: str, pattern: str, severity: str, description: str, flags: int = 0) -> Pattern:
    return Pattern(
        name=name,
        regex=re.compile(pattern, flags),
        severity=severity,
        description=description,
    )


PATTERNS: list[Pattern] = [
    # CRITICAL — private keys and cloud root credentials
    _p("AWS Access Key ID",
       r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|ASIA)[A-Z0-9]{16}",
       "CRITICAL", "AWS access key ID"),
    _p("AWS Secret Access Key",
       r"(?i)aws(?:.{0,20})?['\"\s]([0-9a-zA-Z/+]{40})",
       "CRITICAL", "AWS secret access key"),
    _p("GCP Service Account",
       r'"type"\s*:\s*"service_account"',
       "CRITICAL", "GCP service account JSON"),
    _p("RSA Private Key",          r"-----BEGIN RSA PRIVATE KEY-----",         "CRITICAL", "RSA private key (PKCS#1)"),
    _p("EC Private Key",           r"-----BEGIN EC PRIVATE KEY-----",          "CRITICAL", "EC private key"),
    _p("PGP Private Key",          r"-----BEGIN PGP PRIVATE KEY BLOCK-----",   "CRITICAL", "PGP private key block"),
    _p("OpenSSH Private Key",      r"-----BEGIN OPENSSH PRIVATE KEY-----",     "CRITICAL", "OpenSSH private key"),
    _p("PKCS8 Private Key",        r"-----BEGIN PRIVATE KEY-----",             "CRITICAL", "PKCS#8 unencrypted private key"),
    _p("PKCS8 Encrypted Key",      r"-----BEGIN ENCRYPTED PRIVATE KEY-----",   "CRITICAL", "PKCS#8 encrypted private key"),
    _p("DSA Private Key",          r"-----BEGIN DSA PRIVATE KEY-----",         "CRITICAL", "DSA private key"),
    _p("Azure Storage Key",
       r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==",
       "CRITICAL", "Azure storage account connection string"),

    # HIGH — service tokens and live API keys
    _p("GitHub Personal Token",    r"ghp_[0-9a-zA-Z]{36}",                    "HIGH", "GitHub personal access token"),
    _p("GitHub OAuth Token",       r"gho_[0-9a-zA-Z]{36}",                    "HIGH", "GitHub OAuth token"),
    _p("GitHub App Token",         r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",            "HIGH", "GitHub app/server token"),
    _p("GitHub Refresh Token",     r"ghr_[0-9a-zA-Z]{76}",                    "HIGH", "GitHub refresh token"),
    _p("GitLab Personal Token",    r"glpat-[A-Za-z0-9\-_]{20}",               "HIGH", "GitLab personal access token"),
    _p("GitLab CI Token",          r"glcbt-[A-Za-z0-9\-_]{20}",               "HIGH", "GitLab CI/CD token"),
    _p("Stripe Live Secret Key",   r"sk_live_[0-9a-zA-Z]{24,}",               "HIGH", "Stripe live secret key"),
    _p("Stripe Live Publishable",  r"pk_live_[0-9a-zA-Z]{24,}",               "HIGH", "Stripe live publishable key"),
    _p("Twilio Account SID",       r"\bAC[0-9a-fA-F]{32}\b",                  "HIGH", "Twilio account SID"),
    _p("Twilio Auth Token",        r"(?i)twilio(?:.{0,20})?['\"][0-9a-f]{32}['\"]", "HIGH", "Twilio auth token"),
    _p("SendGrid API Key",         r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}", "HIGH", "SendGrid API key"),
    _p("Slack Bot Token",          r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "HIGH", "Slack bot token"),
    _p("Slack User Token",         r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}", "HIGH", "Slack user token"),
    _p("Slack Webhook",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
       "HIGH", "Slack incoming webhook URL"),
    _p("Mailgun API Key",          r"key-[0-9a-zA-Z]{32}",                    "HIGH", "Mailgun API key"),
    _p("Anthropic API Key",        r"sk-ant-[0-9a-zA-Z\-]{40,}",              "HIGH", "Anthropic API key"),
    _p("OpenAI API Key",           r"sk-[0-9a-zA-Z]{48}",                     "HIGH", "OpenAI legacy API key"),
    _p("OpenAI Project Key",       r"sk-proj-[A-Za-z0-9\-_]{100,}",           "HIGH", "OpenAI project-scoped API key"),
    _p("HuggingFace Token",        r"hf_[a-zA-Z0-9]{34,}",                    "HIGH", "HuggingFace API token"),
    _p("Replicate API Token",      r"r8_[A-Za-z0-9]{40}",                     "HIGH", "Replicate API token"),
    _p("Telegram Bot Token",       r"\d{8,10}:[A-Za-z0-9_-]{35}",             "HIGH", "Telegram bot token"),
    _p("Discord Bot Token",
       r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
       "HIGH", "Discord bot token"),
    _p("Discord Webhook",
       r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9._-]{60,}",
       "HIGH", "Discord webhook URL"),
    _p("NPM Access Token",         r"npm_[A-Za-z0-9]{36}",                    "HIGH", "NPM access token"),
    _p("PyPI API Token",           r"pypi-[A-Za-z0-9_\-]{97,}",               "HIGH", "PyPI API token"),
    _p("Shopify Access Token",     r"shpat_[a-fA-F0-9]{32}",                  "HIGH", "Shopify private access token"),
    _p("Shopify Shared Secret",    r"shpss_[a-fA-F0-9]{32}",                  "HIGH", "Shopify shared secret"),
    _p("DigitalOcean Token",       r"dop_v1_[a-f0-9]{64}",                    "HIGH", "DigitalOcean personal access token"),
    _p("Dropbox Token",            r"sl\.[A-Za-z0-9_-]{135}",                 "HIGH", "Dropbox access token"),
    _p("Notion API Key",           r"secret_[A-Za-z0-9]{43}",                 "HIGH", "Notion integration token"),
    _p("Linear API Key",           r"lin_api_[A-Za-z0-9]{40}",                "HIGH", "Linear API key"),
    _p("Terraform Cloud Token",    r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}", "HIGH", "Terraform Cloud token"),
    _p("Vault Service Token",      r"hvs\.[A-Za-z0-9_-]{90,}",                "HIGH", "HashiCorp Vault service token"),
    _p("New Relic API Key",        r"NRAK-[A-Z0-9]{27}",                      "HIGH", "New Relic API key"),
    _p("New Relic License Key",    r"[A-Za-z0-9]{40}NRAL",                    "HIGH", "New Relic license key"),
    _p("Mapbox Token",             r"pk\.eyJ[A-Za-z0-9+/=._-]{40,}\.[A-Za-z0-9_-]{20,}", "HIGH", "Mapbox access token"),
    _p("Square Access Token",      r"EAAAl[A-Za-z0-9_\-]{60}",                "HIGH", "Square access token"),
    _p("Square OAuth Token",       r"sq0(?:atp|csp)-[A-Za-z0-9\-_]{22,43}",  "HIGH", "Square OAuth token"),
    _p("Twitter Bearer Token",     r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{40,}", "HIGH", "Twitter/X bearer token"),
    _p("Mailchimp API Key",        r"[0-9a-f]{32}-us[0-9]{1,2}",              "HIGH", "Mailchimp API key"),

    # MEDIUM — generic and contextual patterns
    _p("Generic API Key",
       r"(?i)(?:api_key|apikey|api-key)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?",
       "MEDIUM", "Generic API key assignment"),
    _p("Generic Secret",
       r"(?i)(?:secret|secret_key|client_secret)\s*[=:]\s*['\"]?([0-9a-zA-Z\-_]{16,})['\"]?",
       "MEDIUM", "Generic secret assignment"),
    _p("Generic Password",
       r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
       "MEDIUM", "Hardcoded password"),
    _p("Bearer Token",
       r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
       "MEDIUM", "Bearer token in header"),
    _p("JWT Token",
       r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
       "MEDIUM", "JWT token"),
    _p("Database URL",
       r"(?i)(?:mongodb|postgres|mysql|redis|amqp|elasticsearch)://[^\s'\"]+:[^\s'\"@]+@",
       "MEDIUM", "Database/broker URL with credentials"),
    _p("Basic Auth in URL",
       r"https?://[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+@",
       "MEDIUM", "Basic auth credentials in URL"),
    _p("Stripe Test Key",          r"sk_test_[0-9a-zA-Z]{24,}",               "MEDIUM", "Stripe test secret key"),
    _p("Firebase Config",          r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", "MEDIUM", "Firebase server key"),
    _p("Google API Key",           r"AIza[0-9A-Za-z\-_]{35}",                 "MEDIUM", "Google API key"),
    _p("Slack App Token",          r"xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+",        "MEDIUM", "Slack app-level token"),
    _p("Private Key File Path",
       r"(?i)(?:identity_file|private_key(?:_file)?)\s*[=:]\s*['\"]?([~\/][^\s'\"]+\.pem)['\"]?",
       "MEDIUM", "SSH/TLS private key file path in config"),
]
