from __future__ import annotations

import re
from typing import Optional

import requests

from scanner.engine import Finding

_session = requests.Session()
_session.headers["User-Agent"] = "secret-scanner/0.3.0"
_TIMEOUT = 5
_cache: dict[tuple, Optional[str]] = {}

_EXTRACTORS: dict[str, re.Pattern] = {
    "GitHub Personal Token":  re.compile(r"ghp_[A-Za-z0-9]+"),
    "GitHub OAuth Token":     re.compile(r"gho_[A-Za-z0-9]+"),
    "GitHub App Token":       re.compile(r"(?:ghu|ghs)_[A-Za-z0-9]+"),
    "GitLab Personal Token":  re.compile(r"glpat-[A-Za-z0-9\-_]+"),
    "Stripe Live Secret Key": re.compile(r"sk_live_[A-Za-z0-9]+"),
    "OpenAI API Key":         re.compile(r"sk-[A-Za-z0-9]{48}"),
    "OpenAI Project Key":     re.compile(r"sk-proj-[A-Za-z0-9\-_]+"),
    "Anthropic API Key":      re.compile(r"sk-ant-[A-Za-z0-9\-]+"),
    "HuggingFace Token":      re.compile(r"hf_[A-Za-z0-9]+"),
    "SendGrid API Key":       re.compile(r"SG\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Slack Bot Token":        re.compile(r"xoxb-[A-Za-z0-9\-]+"),
    "Slack User Token":       re.compile(r"xoxp-[A-Za-z0-9\-]+"),
    "NPM Access Token":       re.compile(r"npm_[A-Za-z0-9]+"),
    "Replicate API Token":    re.compile(r"r8_[A-Za-z0-9]+"),
    "Telegram Bot Token":     re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    "Google API Key":         re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Twilio Auth Token":      re.compile(r"[0-9a-f]{32}"),
    "AWS Access Key ID":      re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "Sentry Auth Token":      re.compile(r"sntrys_[A-Za-z0-9]+"),
    "Datadog API Key":        re.compile(r"[a-f0-9]{32}"),
    "Vercel Token":           re.compile(r"vercel_[A-Za-z0-9]+"),
}


def _extract(finding: Finding) -> Optional[str]:
    pat = _EXTRACTORS.get(finding.secret_type)
    if pat:
        m = pat.search(finding.matched_value)
        return m.group(0) if m else None
    return finding.matched_value


def _get(url: str, headers: dict) -> Optional[requests.Response]:
    try:
        return _session.get(url, headers=headers, timeout=_TIMEOUT)
    except Exception:
        return None


def _post(url: str, headers: dict, json: dict) -> Optional[requests.Response]:
    try:
        return _session.post(url, headers=headers, json=json, timeout=_TIMEOUT)
    except Exception:
        return None


def verify(finding: Finding) -> Optional[str]:
    cache_key = (finding.secret_type, finding.matched_value)
    if cache_key in _cache:
        return _cache[cache_key]

    result = _do_verify(finding)
    _cache[cache_key] = result
    return result


def _do_verify(finding: Finding) -> Optional[str]:
    token = _extract(finding)
    if not token:
        return None
    t = finding.secret_type

    if t in ("GitHub Personal Token", "GitHub OAuth Token", "GitHub App Token"):
        r = _get("https://api.github.com/user", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "GitLab Personal Token":
        r = _get("https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": token})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "Stripe Live Secret Key":
        r = _get("https://api.stripe.com/v1/account", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t in ("OpenAI API Key", "OpenAI Project Key"):
        r = _get("https://api.openai.com/v1/models", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "Anthropic API Key":
        r = _get("https://api.anthropic.com/v1/models",
                 {"x-api-key": token, "anthropic-version": "2023-06-01"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "HuggingFace Token":
        r = _get("https://huggingface.co/api/whoami-v2", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "SendGrid API Key":
        r = _get("https://api.sendgrid.com/v3/user/profile", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t in ("Slack Bot Token", "Slack User Token"):
        r = _post("https://slack.com/api/auth.test",
                  {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, {})
        if r is None:
            return None
        try:
            return "LIVE" if r.json().get("ok") else "REVOKED"
        except Exception:
            return None

    if t == "NPM Access Token":
        r = _get("https://registry.npmjs.org/-/npm/v1/user", {"Authorization": f"Bearer {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "Replicate API Token":
        r = _get("https://api.replicate.com/v1/account", {"Authorization": f"Token {token}"})
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "Telegram Bot Token":
        r = _get(f"https://api.telegram.org/bot{token}/getMe", {})
        if r is None:
            return None
        try:
            data = r.json()
            return "LIVE" if data.get("ok") else "REVOKED"
        except Exception:
            return "REVOKED" if r.status_code != 200 else None

    if t == "Google API Key":
        # Test against the Maps Geocoding API with a dummy request
        r = _get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={token}",
            {},
        )
        if r is None:
            return None
        try:
            data = r.json()
            status = data.get("status", "")
            if status in ("OK", "ZERO_RESULTS"):
                return "LIVE"
            elif status == "REQUEST_DENIED":
                # Key exists but this API not enabled, still counts as live key
                error_msg = data.get("error_message", "")
                if "not authorized" in error_msg.lower() or "enable" in error_msg.lower():
                    return "LIVE"
                return "REVOKED"
            return "REVOKED"
        except Exception:
            return None

    if t == "Twilio Auth Token":
        # Twilio verification requires Account SID + Auth Token pair.
        # We cannot verify just the auth token alone without the SID.
        return None

    if t == "AWS Access Key ID":
        # AWS verification requires both access key and secret key.
        # We can only flag the key ID, not verify without the secret.
        return None

    if t == "Sentry Auth Token":
        r = _get(
            "https://sentry.io/api/0/",
            {"Authorization": f"Bearer {token}"},
        )
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    if t == "Vercel Token":
        r = _get(
            "https://api.vercel.com/v2/user",
            {"Authorization": f"Bearer {token}"},
        )
        if r is None:
            return None
        return "LIVE" if r.status_code == 200 else "REVOKED"

    return None


def can_verify(finding: Finding) -> bool:
    return finding.secret_type in _EXTRACTORS
