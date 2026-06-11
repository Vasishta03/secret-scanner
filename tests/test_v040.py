import base64
import json
import subprocess
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from scanner import blame, ignorefile, notify, purge, remediation, reporter, verifier
from scanner.engine import (
    Finding,
    ScanResult,
    _is_binary,
    _iter_lines_chunked,
    scan_content_string,
    scan_path,
)


# ---------------------------------------------------------------------------
# blame.py
# ---------------------------------------------------------------------------

def test_format_age_buckets():
    assert blame.format_age(30) == "30s"
    assert blame.format_age(90) == "1m"
    assert blame.format_age(3661) == "1h"
    assert blame.format_age(90000) == "1d"
    assert blame.format_age(40 * 86400) == "1mo"
    assert blame.format_age(400 * 86400) == "1y"


def test_scraping_risk_buckets():
    assert blame.scraping_risk(60) == "LOW"
    assert blame.scraping_risk(2 * 3600) == "MEDIUM"
    assert blame.scraping_risk(2 * 86400) == "HIGH"
    assert blame.scraping_risk(40 * 86400) == "CRITICAL"


def test_scraping_warning_thresholds():
    assert blame.scraping_warning(86400) is None
    assert "30 days" in blame.scraping_warning(31 * 86400)
    assert "ASSUME COMPROMISED" in blame.scraping_warning(91 * 86400)


def test_is_git_repo_false_for_non_repo(tmp_path):
    assert blame.is_git_repo(tmp_path) is False


def _init_git_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True)


def test_get_blame_info_for_committed_line(tmp_path):
    _init_git_repo(tmp_path)
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n')
    subprocess.run(["git", "add", "config.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "add secret"], cwd=tmp_path, check=True)

    info = blame.get_blame_info(tmp_path, "config.py", 1)
    assert info is not None
    assert info.author_email == "dev@example.com"
    assert info.message == "add secret"
    assert info.branch is not None
    assert blame.scraping_risk(info.age_seconds) == "LOW"


def test_get_blame_info_uncommitted_line_returns_none(tmp_path):
    _init_git_repo(tmp_path)
    f = tmp_path / "file.txt"
    f.write_text("line1\n")
    subprocess.run(["git", "add", "file.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)

    f.write_text("line1\nline2\n")
    subprocess.run(["git", "add", "file.txt"], cwd=tmp_path, check=True)

    assert blame.get_blame_info(tmp_path, "file.txt", 2) is None


# ---------------------------------------------------------------------------
# notify.py
# ---------------------------------------------------------------------------

def test_load_rc_missing_file_returns_empty(tmp_path):
    assert notify.load_rc(tmp_path / "missing") == {}


def test_save_and_load_webhook(tmp_path):
    rc = tmp_path / ".leakscanrc"
    notify.save_webhook("slack", "https://hooks.slack.com/services/x", rc)
    config = notify.load_rc(rc)
    assert config["SLACK_WEBHOOK_URL"] == "https://hooks.slack.com/services/x"


def test_resolve_webhook_prefers_explicit():
    assert notify.resolve_webhook("slack", "https://explicit") == "https://explicit"


def test_resolve_webhook_falls_back_to_rc(monkeypatch):
    monkeypatch.setattr(notify, "load_rc", lambda *a, **k: {"DISCORD_WEBHOOK_URL": "https://from-rc"})
    assert notify.resolve_webhook("discord", None) == "https://from-rc"


def test_build_slack_payload_clean():
    result = ScanResult(files_scanned=5)
    payload = notify.build_slack_payload(result, "myrepo", clean=True)
    text = payload["blocks"][1]["text"]["text"]
    assert "0 secrets found" in text


def test_build_slack_payload_with_findings():
    f = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_x")
    result = ScanResult(findings=[f])
    payload = notify.build_slack_payload(result, "myrepo")
    assert "1 secret(s)" in payload["blocks"][0]["text"]["text"]


def test_build_discord_payload_with_findings():
    f = Finding("a.py", 1, "", "AWS Access Key ID", "CRITICAL", "AKIA_x")
    result = ScanResult(findings=[f])
    payload = notify.build_discord_payload(result, "myrepo")
    embed = payload["embeds"][0]
    assert embed["color"] == notify.SEVERITY_COLOR_HEX["CRITICAL"]
    assert len(embed["fields"]) == 1


def test_send_notifications_no_target_returns_empty():
    result = ScanResult(findings=[])
    assert notify.send_notifications(result, "repo", None) == []


def test_send_notifications_clean_without_notify_clean_returns_empty():
    result = ScanResult(findings=[])
    assert notify.send_notifications(result, "repo", "slack") == []


def test_send_notifications_missing_webhook_reports_message(monkeypatch):
    monkeypatch.setattr(notify, "load_rc", lambda *a, **k: {})
    result = ScanResult(findings=[])
    messages = notify.send_notifications(result, "repo", "slack", notify_clean=True)
    assert "no webhook URL is configured" in messages[0]


def test_send_notifications_success_and_failure():
    f = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_x")
    result = ScanResult(findings=[f])
    with patch("scanner.notify._post", side_effect=[True, False]):
        messages = notify.send_notifications(
            result, "repo", "both",
            slack_webhook="https://slack", discord_webhook="https://discord",
        )
    assert messages == [
        "Sent slack notification.",
        "Failed to send discord notification (request error or non-2xx response).",
    ]


# ---------------------------------------------------------------------------
# purge.py
# ---------------------------------------------------------------------------

def test_purge_report_no_args_returns_usage():
    assert purge.build_purge_report() == purge.USAGE_TEXT


def test_purge_report_file_includes_both_methods():
    report = purge.build_purge_report(file="config/secrets.yaml")
    assert "git filter-repo" in report
    assert "BFG Repo-Cleaner" in report
    assert "config/secrets.yaml" in report
    assert "--force-with-lease" in report


def test_purge_report_file_method_filter_repo_only():
    report = purge.build_purge_report(file=".env", method="filter-repo")
    assert "git filter-repo" in report
    assert "BFG Repo-Cleaner" not in report


def test_purge_report_commit_includes_show_stat():
    report = purge.build_purge_report(commit="a1b2c3d4")
    assert "git show --stat a1b2c3d4" in report


def test_purge_report_all_includes_replacements_workflow():
    report = purge.build_purge_report(purge_all=True)
    assert "replacements.txt" in report
    assert "rotate" in report.lower()


# ---------------------------------------------------------------------------
# remediation.py
# ---------------------------------------------------------------------------

def test_get_remediation_known_type():
    rem = remediation.get_remediation("AWS Access Key ID")
    assert rem.blast_radius == "Full cloud account compromise"
    assert "console.aws.amazon.com" in rem.rotation_url


def test_get_remediation_unknown_type_returns_default():
    rem = remediation.get_remediation("Some Custom Pattern")
    assert rem == remediation._DEFAULT


# ---------------------------------------------------------------------------
# ignorefile.py
# ---------------------------------------------------------------------------

def test_negation_pattern_reincludes_path():
    patterns = ["*.log", "!important.log"]
    assert ignorefile.is_ignored(Path("/tmp/p/debug.log"), Path("/tmp/p"), patterns)
    assert not ignorefile.is_ignored(Path("/tmp/p/important.log"), Path("/tmp/p"), patterns)


def test_double_star_dir_pattern_matches_any_depth():
    patterns = ["**/node_modules/**"]
    assert ignorefile.is_ignored(Path("/tmp/p/node_modules/pkg/index.js"), Path("/tmp/p"), patterns)
    assert ignorefile.is_ignored(Path("/tmp/p/src/a/node_modules/pkg/index.js"), Path("/tmp/p"), patterns)
    assert not ignorefile.is_ignored(Path("/tmp/p/src/index.js"), Path("/tmp/p"), patterns)


def test_trailing_slash_directory_pattern_matches_any_depth():
    patterns = ["tests/"]
    assert ignorefile.is_ignored(Path("/tmp/p/tests/test_foo.py"), Path("/tmp/p"), patterns)
    assert ignorefile.is_ignored(Path("/tmp/p/src/tests/test_foo.py"), Path("/tmp/p"), patterns)
    assert not ignorefile.is_ignored(Path("/tmp/p/src/main.py"), Path("/tmp/p"), patterns)


def test_append_ignore_pattern_creates_and_appends(tmp_path):
    ignorefile.append_ignore_pattern(tmp_path, "*.secret")
    ignorefile.append_ignore_pattern(tmp_path, "build/")
    content = (tmp_path / ".leakscanignore").read_text()
    assert "*.secret" in content
    assert "build/" in content


def test_write_init_template_creates_once(tmp_path):
    path, created = ignorefile.write_init_template(tmp_path)
    assert created is True
    assert path.read_text() == ignorefile.INIT_TEMPLATE

    _, created_again = ignorefile.write_init_template(tmp_path)
    assert created_again is False


def test_load_ignore_patterns_supports_legacy_secretignore(tmp_path):
    (tmp_path / ".secretignore").write_text("legacy_pattern.txt\n")
    (tmp_path / ".leakscanignore").write_text("new_pattern.txt\n")
    patterns = ignorefile.load_ignore_patterns(tmp_path)
    assert "legacy_pattern.txt" in patterns
    assert "new_pattern.txt" in patterns


# ---------------------------------------------------------------------------
# engine.py: chunked reading, binary detection, threaded scanning
# ---------------------------------------------------------------------------

def test_is_binary_detects_null_byte(tmp_path):
    binary_file = tmp_path / "data.bin"
    binary_file.write_bytes(b"\x00\x01\x02binary")
    text_file = tmp_path / "data.txt"
    text_file.write_text("just text")
    assert _is_binary(binary_file) is True
    assert _is_binary(text_file) is False


def test_iter_lines_chunked_reconstructs_lines(tmp_path):
    f = tmp_path / "lines.txt"
    f.write_text("hello\nworld\n")
    assert list(_iter_lines_chunked(f, chunk_size=4)) == [(1, "hello"), (2, "world")]


def test_iter_lines_chunked_handles_secret_split_across_chunks(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n')
    findings = scan_path(tmp_path, no_entropy=True, chunk_size=4).findings
    assert any(fr.secret_type == "GitHub Personal Token" for fr in findings)


def test_scan_path_skips_binary_files(tmp_path):
    (tmp_path / "data.dat").write_bytes(b"\x00\x00ghp_abcdefghijklmnopqrstuvwxyz123456789012")
    result = scan_path(tmp_path, no_entropy=True)
    assert result.binary_files_skipped == 1
    assert result.findings == []


def test_scan_path_skips_large_files(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 1000)
    result = scan_path(tmp_path, no_entropy=True, max_file_size=100)
    assert any(p.endswith("big.txt") for p in result.large_files_skipped)
    assert result.files_scanned == 0


def test_scan_path_streams_findings_and_progress(tmp_path):
    (tmp_path / "config.py").write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n')
    seen_findings = []
    progress = []
    result = scan_path(
        tmp_path, no_entropy=True, threads=2,
        on_finding=seen_findings.append,
        on_progress=lambda done, total: progress.append((done, total)),
    )
    assert len(seen_findings) == 1
    assert seen_findings[0].secret_type == "GitHub Personal Token"
    assert progress[-1] == (1, 1)
    assert result.files_scanned == 1
    assert result.elapsed_seconds >= 0


def test_files_per_second_property():
    assert ScanResult(files_scanned=10, elapsed_seconds=2.0).files_per_second == 5.0
    assert ScanResult(files_scanned=10, elapsed_seconds=0.0).files_per_second == 0.0


# ---------------------------------------------------------------------------
# reporter.py
# ---------------------------------------------------------------------------

def test_to_json_includes_blast_radius_and_blame():
    f = Finding("a.py", 1, "", "AWS Access Key ID", "CRITICAL", "AKIAxxxx")
    result = ScanResult(findings=[f])
    data = json.loads(reporter.to_json(result))
    finding = data["findings"][0]
    assert finding["blast_radius"] == "Full cloud account compromise"
    assert finding["rotation_url"]
    assert finding["blame"] is None


def test_to_csv_includes_new_columns():
    f = Finding("a.py", 1, "", "AWS Access Key ID", "CRITICAL", "AKIAxxxx")
    result = ScanResult(findings=[f])
    header = reporter.to_csv(result).splitlines()[0]
    for col in ("blast_radius", "rotation_url", "secret_age", "scraping_risk"):
        assert col in header


def test_print_terminal_brief_and_blocks_smoke(capsys):
    f = Finding("a.py", 1, "", "AWS Access Key ID", "CRITICAL", "AKIAxxxx")
    result = ScanResult(findings=[f])
    reporter.print_terminal(result, brief=True)
    reporter.print_terminal(result, brief=False)
    out = capsys.readouterr().out
    assert "AWS Access Key ID" in out
    assert "Blast radius" in out


# ---------------------------------------------------------------------------
# patterns.py: v0.3.2/v0.4.0 additions
# ---------------------------------------------------------------------------

NEW_PATTERN_EXAMPLES = [
    ("MongoDB Connection String", 'DATABASE_URL = "mongodb://user:pass@cluster0.mongodb.net/mydb"'),
    ("PostgreSQL Connection String", 'DATABASE_URL = "postgres://user:pass@localhost:5432/mydb"'),
    ("MySQL Connection String", 'DATABASE_URL = "mysql://user:pass@localhost:3306/mydb"'),
    ("Redis Connection String", 'REDIS_URL = "redis://:s3cr3tpass@localhost:6379/0"'),
    ("PEM Certificate", "-----BEGIN CERTIFICATE-----"),
    ("Docker Config Auth", '{"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNzd29yZA=="}}}'),
    ("Kubernetes Service Account Token",
     "eyJhbGciOiJSUzI1NiIsImtpZCI6ABCDEFGHIJ.eyJABCDEFGHIJ.ABCDEFGHIJ"),
    ("Firebase Admin SDK Key",
     '"client_email": "firebase-adminsdk-abc12@my-project.iam.gserviceaccount.com"'),
    ("Expo Access Token", "expo_" + "A" * 35),
    ("Fly.io API Token", "fm2_" + "A" * 60),
    ("WireGuard Private Key", "PrivateKey = " + "A" * 43 + "="),
    ("PagerDuty API Key", 'pagerduty_key = "u_AbCdEfGhIjKlMnOpQr"'),
    ("Elastic Cloud API Key", 'ELASTIC_API_KEY = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="'),
    ("Azure AD Client Secret", 'AZURE_CLIENT_SECRET = "' + "A" * 36 + '"'),
    ("Cohere API Key", 'COHERE_API_KEY = "' + "a" * 40 + '"'),
    ("Groq API Key", "gsk_" + "B" * 52),
    ("Pinecone API Key", 'PINECONE_API_KEY = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"'),
    ("Atlassian API Token", "ATATT3" + "x" * 180),
    ("PayPal Client Secret", 'PAYPAL_CLIENT_SECRET = "E' + "A" * 79 + '"'),
    ("Razorpay Key ID", "rzp_test_" + "A" * 14),
    ("Postmark Server Token", 'POSTMARK_TOKEN = "33333333-4444-5555-6666-777777777777"'),
    ("Railway API Token", 'RAILWAY_TOKEN = "44444444-5555-6666-7777-888888888888"'),
    ("Cloudflare API Token", 'CLOUDFLARE_API_TOKEN = "' + "A" * 40 + '"'),
]


@pytest.mark.parametrize("secret_type,content", NEW_PATTERN_EXAMPLES)
def test_new_pattern_detected(secret_type, content):
    findings = scan_content_string(content, "test_file", no_entropy=True)
    assert any(f.secret_type == secret_type for f in findings), f"{secret_type} not detected in: {content}"


# ---------------------------------------------------------------------------
# verifier.py: v0.3.2 validators
# ---------------------------------------------------------------------------

def _mock_resp(status_code=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


def test_verify_cohere_live():
    f = Finding("f", 1, "", "Cohere API Key", "HIGH", "a" * 40)
    with patch("scanner.verifier._post", return_value=_mock_resp(json_data={"valid": True})):
        assert verifier.verify(f) == "LIVE"


def test_verify_groq_live():
    f = Finding("f", 1, "", "Groq API Key", "HIGH", "gsk_" + "b" * 52)
    with patch("scanner.verifier._get", return_value=_mock_resp(200)):
        assert verifier.verify(f) == "LIVE"


def test_verify_pinecone_revoked():
    f = Finding("f", 1, "", "Pinecone API Key", "HIGH", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    with patch("scanner.verifier._get", return_value=_mock_resp(401)):
        assert verifier.verify(f) == "REVOKED"


def test_verify_notion_live():
    f = Finding("f", 1, "", "Notion API Key", "HIGH", "secret_" + "c" * 43)
    with patch("scanner.verifier._get", return_value=_mock_resp(200)):
        assert verifier.verify(f) == "LIVE"


def test_verify_linear_live():
    f = Finding("f", 1, "", "Linear API Key", "HIGH", "lin_api_" + "d" * 40)
    resp = _mock_resp(json_data={"data": {"viewer": {"id": "u1"}}})
    with patch("scanner.verifier._post", return_value=resp):
        assert verifier.verify(f) == "LIVE"


def test_verify_mailgun_live():
    f = Finding("f", 1, "", "Mailgun API Key", "HIGH", "key-" + "e" * 32)
    with patch("scanner.verifier._get_basic", return_value=_mock_resp(200)):
        assert verifier.verify(f) == "LIVE"


def test_verify_postmark_live():
    f = Finding("f", 1, "", "Postmark Server Token", "HIGH", "11111111-2222-3333-4444-555555555555")
    with patch("scanner.verifier._get", return_value=_mock_resp(200)):
        assert verifier.verify(f) == "LIVE"


def test_verify_cloudflare_live():
    f = Finding("f", 1, "", "Cloudflare API Token", "HIGH", "f" * 40)
    resp = _mock_resp(json_data={"success": True})
    with patch("scanner.verifier._get", return_value=resp):
        assert verifier.verify(f) == "LIVE"


def test_verify_railway_live():
    f = Finding("f", 1, "", "Railway API Token", "HIGH", "22222222-3333-4444-5555-666666666666")
    resp = _mock_resp(json_data={"data": {"me": {"id": "u1"}}})
    with patch("scanner.verifier._post", return_value=resp):
        assert verifier.verify(f) == "LIVE"


def _make_supabase_jwt(role, exp):
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = json.dumps({"role": role, "iss": "supabase", "ref": "abcdefghijklmnop", "exp": exp})
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
    return f"{header}.{payload_b64}.{'x' * 32}"


def test_verify_supabase_service_role_live():
    token = _make_supabase_jwt("service_role", int(time.time()) + 3600)
    f = Finding("f", 1, "", "Supabase Service Key", "HIGH", token)
    assert verifier.verify(f) == "LIVE"


def test_verify_supabase_service_role_revoked_when_expired():
    token = _make_supabase_jwt("service_role", int(time.time()) - 3600)
    f = Finding("f", 1, "", "Supabase Service Key", "HIGH", token)
    assert verifier.verify(f) == "REVOKED"


def test_verify_supabase_wrong_role_returns_none():
    token = _make_supabase_jwt("anon", int(time.time()) + 3600)
    f = Finding("f", 1, "", "Supabase Service Key", "HIGH", token)
    assert verifier.verify(f) is None


def test_verify_azure_ad_client_secret_live():
    f = Finding("f", 1, "", "Azure AD Client Secret", "CRITICAL", "g" * 36)
    resp = _mock_resp(json_data={"error_description": "AADSTS700016: unknown client"})
    with patch("scanner.verifier._post_form", return_value=resp):
        assert verifier.verify(f) == "LIVE"


def test_verify_azure_ad_client_secret_revoked():
    f = Finding("f", 1, "", "Azure AD Client Secret", "CRITICAL", "h" * 36)
    resp = _mock_resp(json_data={"error_description": "AADSTS7000215: Invalid client secret"})
    with patch("scanner.verifier._post_form", return_value=resp):
        assert verifier.verify(f) == "REVOKED"


def test_can_verify_new_types():
    for secret_type in (
        "Cohere API Key", "Groq API Key", "Pinecone API Key", "Notion API Key",
        "Linear API Key", "Mailgun API Key", "Postmark Server Token",
        "Cloudflare API Token", "Railway API Token", "Supabase Service Key",
        "Azure AD Client Secret",
    ):
        assert verifier.can_verify(Finding("f", 1, "", secret_type, "HIGH", "x"))
