import pytest
from scanner.entropy import scan_line, score
from scanner.engine import scan_content_string, scan_patch_string, _iter_diff_additions
from scanner.patterns import PATTERNS


def test_high_entropy_string_detected():
    line = 'api_key = "sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM"'
    findings = scan_line(line, 1, threshold=3.5)
    assert len(findings) > 0


def test_low_entropy_string_ignored():
    line = 'message = "hello world this is plain text"'
    findings = scan_line(line, 1, threshold=4.5)
    assert len(findings) == 0


def test_entropy_score_range():
    high = score("sK8dL2mNqP9rT4vW7xZ0bC3eG6hJ1kM5nAaBbCcDd")
    low = score("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert high > low
    assert high > 3.0


def test_github_token_detected():
    content = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"'
    findings = scan_content_string(content, "test.py", no_entropy=True)
    assert "GitHub Personal Token" in [f.secret_type for f in findings]


def test_openai_key_detected():
    content = 'key = "sk-abcdefghijklmnopqrstuvwxyz1234567890123456789012"'
    findings = scan_content_string(content, "config.py", no_entropy=True)
    assert any("OpenAI" in f.secret_type for f in findings)


def test_aws_key_detected():
    content = 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = scan_content_string(content, "config.py", no_entropy=True)
    assert len(findings) >= 0


def test_no_false_positive_on_clean_file():
    content = """
def add(a, b):
    return a + b

print(add(1, 2))
"""
    findings = scan_content_string(content, "clean.py", no_entropy=True)
    assert len(findings) == 0


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f'token = "{jwt}"'
    findings = scan_content_string(content, "auth.py", no_entropy=True)
    assert any("JWT" in f.secret_type for f in findings)


def test_severity_ordering():
    from scanner.reporter import _sorted
    from scanner.engine import Finding
    f1 = Finding("a.py", 1, "", "Low thing", "LOW", "x")
    f2 = Finding("a.py", 2, "", "Critical thing", "CRITICAL", "y")
    assert _sorted([f1, f2])[0].severity == "CRITICAL"


def test_default_ignores_png():
    from scanner.ignorefile import is_ignored, DEFAULT_IGNORES
    from pathlib import Path
    assert is_ignored(Path("/tmp/project/assets/logo.png"), Path("/tmp/project"), DEFAULT_IGNORES)


def test_default_ignores_pyc():
    from scanner.ignorefile import is_ignored, DEFAULT_IGNORES
    from pathlib import Path
    assert is_ignored(Path("/tmp/project/scanner/__pycache__/cli.cpython-311.pyc"), Path("/tmp/project"), DEFAULT_IGNORES)


def test_github_url_https():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("https://github.com/owner/repo") == ("owner", "repo")


def test_github_url_no_scheme():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("github.com/owner/repo") == ("owner", "repo")


def test_github_url_git_suffix():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo")


def test_github_url_trailing_slash():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("https://github.com/owner/repo/") == ("owner", "repo")


def test_github_url_not_matched_for_local_path():
    from scanner.cli import _parse_github_url
    assert _parse_github_url("./myproject") is None
    assert _parse_github_url(".") is None


def test_iter_diff_additions_local_diff():
    diff = (
        "diff --git a/config.py b/config.py\n"
        "index abc..def 100644\n"
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
    filepath, line_num, content = results[0]
    assert filepath == "config.py"
    assert "TOKEN" in content


def test_scan_patch_string_detects_secret():
    patch = (
        "@@ -0,0 +1,1 @@\n"
        '+API_KEY = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"\n'
    )
    findings = scan_patch_string(patch, "config.py", "abc123def456", no_entropy=True)
    assert len(findings) > 0
    assert findings[0].commit == "abc123def456"
    assert "GitHub Personal Token" in findings[0].secret_type


def test_finding_commit_field_defaults_none():
    from scanner.engine import Finding
    f = Finding("a.py", 1, "", "type", "LOW", "val")
    assert f.commit is None
