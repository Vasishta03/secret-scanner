import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scanner.entropy import scan_line, score
from scanner.engine import scan_content_string, scan_patch_string, _iter_diff_additions, Finding
from scanner.patterns import PATTERNS


def test_high_entropy_string_detected():
    line = 'api_key = "sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM"'
    assert len(scan_line(line, 1, threshold=3.5)) > 0


def test_low_entropy_string_ignored():
    assert len(scan_line('message = "hello world this is plain text"', 1, threshold=4.5)) == 0


def test_entropy_score_range():
    high = score("sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM5nAaBbCcDd")
    low = score("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert high > low and high > 3.0


def test_entropy_unquoted_dotenv():
    line = "API_KEY=sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM5nAaBb"
    findings = scan_line(line, 1, threshold=3.5)
    assert len(findings) > 0


def test_entropy_unquoted_yaml():
    line = "token: sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM5nAaBb"
    findings = scan_line(line, 1, threshold=3.5)
    assert len(findings) > 0


def test_github_token_detected():
    content = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"'
    findings = scan_content_string(content, "test.py", no_entropy=True)
    assert "GitHub Personal Token" in [f.secret_type for f in findings]


def test_openai_key_detected():
    content = 'key = "sk-abcdefghijklmnopqrstuvwxyz1234567890123456789012"'
    findings = scan_content_string(content, "config.py", no_entropy=True)
    assert any("OpenAI" in f.secret_type for f in findings)


def test_openai_project_key_detected():
    key = "sk-proj-" + "A" * 100
    findings = scan_content_string(f'key = "{key}"', "config.py", no_entropy=True)
    assert any("OpenAI Project Key" in f.secret_type for f in findings)


def test_aws_access_key_precise():
    content = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
    findings = scan_content_string(content, "env", no_entropy=True)
    assert any(f.secret_type == "AWS Access Key ID" for f in findings)


def test_aws_no_false_positive_on_generic_uppercase():
    content = 'IDENTIFIER=ABCDEFGHIJKLMNOPQRST'
    findings = scan_content_string(content, "env", no_entropy=True)
    assert not any(f.secret_type == "AWS Access Key ID" for f in findings)


def test_no_false_positive_on_clean_file():
    content = """
def add(a, b):
    return a + b

print(add(1, 2))
"""
    assert len(scan_content_string(content, "clean.py", no_entropy=True)) == 0


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = scan_content_string(f'token = "{jwt}"', "auth.py", no_entropy=True)
    assert any("JWT" in f.secret_type for f in findings)


def test_telegram_token_detected():
    content = 'BOT_TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcde1234"'
    findings = scan_content_string(content, "bot.py", no_entropy=True)
    assert any(f.secret_type == "Telegram Bot Token" for f in findings)


def test_npm_token_detected():
    content = 'NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890'
    findings = scan_content_string(content, ".env", no_entropy=True)
    assert any(f.secret_type == "NPM Access Token" for f in findings)


def test_nosec_suppresses_finding():
    content = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"  # nosec'
    findings = scan_content_string(content, "test.py", no_entropy=True)
    assert len(findings) == 0


def test_gitleaks_allow_suppresses_finding():
    content = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"  # gitleaks:allow'
    findings = scan_content_string(content, "test.py", no_entropy=True)
    assert len(findings) == 0


def test_severity_ordering():
    from scanner.reporter import _sorted
    f1 = Finding("a.py", 1, "", "Low thing", "LOW", "x")
    f2 = Finding("a.py", 2, "", "Critical thing", "CRITICAL", "y")
    assert _sorted([f1, f2])[0].severity == "CRITICAL"


def test_default_ignores_png():
    from scanner.ignorefile import is_ignored, DEFAULT_IGNORES
    assert is_ignored(Path("/tmp/project/assets/logo.png"), Path("/tmp/project"), DEFAULT_IGNORES)


def test_default_ignores_pyc():
    from scanner.ignorefile import is_ignored, DEFAULT_IGNORES
    assert is_ignored(Path("/tmp/project/scanner/__pycache__/cli.pyc"), Path("/tmp/project"), DEFAULT_IGNORES)


def test_ignorefile_double_star_glob():
    from scanner.ignorefile import is_ignored
    patterns = ["tests/**"]
    assert is_ignored(Path("/tmp/p/tests/fixtures/key.env"), Path("/tmp/p"), patterns)
    assert not is_ignored(Path("/tmp/p/src/main.py"), Path("/tmp/p"), patterns)


def test_github_url_https():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("https://github.com/owner/repo") == ("owner", "repo")


def test_github_url_no_scheme():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("github.com/owner/repo") == ("owner", "repo")


def test_github_url_git_suffix():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo")


def test_github_url_not_local_path():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("./myproject") is None
    assert _parse_github_url(".") is None


def test_iter_diff_additions_local_diff():
    diff = (
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,2 +1,3 @@\n"
        " existing = 1\n"
        '+SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890123456789012"\n'
        " end = True\n"
    )
    results = list(_iter_diff_additions(diff))
    assert len(results) == 1
    filepath, line_num, content = results[0]
    assert filepath == "config.py"
    assert "SECRET" in content


def test_iter_diff_additions_github_patch():
    patch = (
        "@@ -1,2 +1,3 @@\n"
        " existing = 1\n"
        '+TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n'
        " end = True\n"
    )
    results = list(_iter_diff_additions(patch, filepath="config.py"))
    assert len(results) == 1
    assert "TOKEN" in results[0][2]


def test_scan_patch_string_detects_secret():
    patch = "@@ -0,0 +1,1 @@\n+KEY = \"ghp_abcdefghijklmnopqrstuvwxyz123456789012\"\n"
    findings = scan_patch_string(patch, "config.py", "abc123def456", no_entropy=True)
    assert len(findings) > 0
    assert findings[0].commit == "abc123def456"
    assert "GitHub Personal Token" in findings[0].secret_type


def test_finding_fingerprint_stable():
    f1 = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_test")
    f2 = Finding("b.py", 5, "", "GitHub Personal Token", "HIGH", "ghp_test")
    assert f1.fingerprint() == f2.fingerprint()


def test_finding_fingerprint_differs_on_value():
    f1 = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_test1")
    f2 = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_test2")
    assert f1.fingerprint() != f2.fingerprint()


def test_baseline_save_and_load(tmp_path):
    from scanner.baseline import save, load, filter_new
    from scanner.engine import ScanResult
    f1 = Finding("a.py", 1, "", "GitHub Personal Token", "HIGH", "ghp_known")
    f2 = Finding("b.py", 2, "", "OpenAI API Key", "HIGH", "sk-newkey")
    result = ScanResult(findings=[f1])
    bfile = tmp_path / "baseline.json"
    save(result, bfile)
    known = load(bfile)
    new_findings = filter_new([f1, f2], known)
    assert len(new_findings) == 1
    assert new_findings[0].matched_value == "sk-newkey"


def test_sarif_output_valid():
    from scanner.reporter import to_sarif
    from scanner.engine import ScanResult
    f = Finding("src/config.py", 10, "", "GitHub Personal Token", "HIGH",
                "ghp_abcdefghijklmnopqrstuvwxyz123456789012")
    result = ScanResult(findings=[f])
    sarif_str = to_sarif(result)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "GitHub Personal Token"


def test_sarif_line_number_present():
    from scanner.reporter import to_sarif
    from scanner.engine import ScanResult
    f = Finding("app.py", 42, "", "OpenAI API Key", "HIGH", "sk-" + "a" * 48)
    sarif = json.loads(to_sarif(ScanResult(findings=[f])))
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42


def test_redact_masks_value():
    from scanner.reporter import _redact
    token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"
    masked = _redact(token)
    assert masked.startswith("ghp_")
    assert masked.endswith("9012")
    assert "****" in masked
    assert token not in masked


def test_verifier_github_live():
    from scanner.verifier import verify
    f = Finding("test.py", 1, "", "GitHub Personal Token", "HIGH",
                "ghp_abcdefghijklmnopqrstuvwxyz123456789012")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("scanner.verifier._get", return_value=mock_resp):
        assert verify(f) == "LIVE"


def test_verifier_github_revoked():
    from scanner.verifier import verify
    f = Finding("test.py", 1, "", "GitHub Personal Token", "HIGH",
                "ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    with patch("scanner.verifier._get", return_value=mock_resp):
        assert verify(f) == "REVOKED"


def test_verifier_network_error_returns_none():
    from scanner.verifier import verify
    f = Finding("test.py", 1, "", "GitHub Personal Token", "HIGH",
                "ghp_NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN")
    with patch("scanner.verifier._get", return_value=None):
        assert verify(f) is None


def test_verifier_unverifiable_type_returns_none():
    from scanner.verifier import verify
    f = Finding("test.py", 1, "", "Generic Password", "MEDIUM", "somepassword")
    assert verify(f) is None


def test_can_verify_known_types():
    from scanner.verifier import can_verify
    assert can_verify(Finding("f", 1, "", "GitHub Personal Token", "HIGH", "ghp_x"))
    assert can_verify(Finding("f", 1, "", "OpenAI API Key", "HIGH", "sk-x"))
    assert not can_verify(Finding("f", 1, "", "Generic Password", "MEDIUM", "x"))
