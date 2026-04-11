from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Iterator, Optional

import requests

BASE_URL = "https://api.github.com"
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf",
    ".zip", ".tar", ".gz", ".bin", ".exe", ".pyc", ".lock",
    ".woff", ".woff2", ".ttf", ".eot",
}
MAX_FILE_SIZE = 500_000


@dataclass
class RepoFile:
    repo: str
    path: str
    content: str


class GitHubFetcher:
    def __init__(self, token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _get(self, url: str, params: dict = None) -> dict | list:
        resp = self.session.get(url, params=params, timeout=15)
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), 1)
            raise RateLimitError(wait)
        resp.raise_for_status()
        return resp.json()

    def list_repos(self, username: str) -> list[str]:
        repos = []
        page = 1
        while True:
            data = self._get(
                f"{BASE_URL}/users/{username}/repos",
                params={"per_page": 100, "page": page, "type": "public"},
            )
            if not data:
                break
            repos.extend(r["full_name"] for r in data)
            if len(data) < 100:
                break
            page += 1
        return repos

    def list_gists(self, username: str) -> list[str]:
        gists = []
        page = 1
        while True:
            data = self._get(
                f"{BASE_URL}/users/{username}/gists",
                params={"per_page": 100, "page": page},
            )
            if not data:
                break
            gists.extend(g["id"] for g in data)
            if len(data) < 100:
                break
            page += 1
        return gists

    def get_default_branch(self, full_name: str) -> str:
        data = self._get(f"{BASE_URL}/repos/{full_name}")
        return data.get("default_branch", "main")

    def list_files(self, full_name: str, branch: str) -> list[dict]:
        data = self._get(
            f"{BASE_URL}/repos/{full_name}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        return [item for item in data.get("tree", []) if item["type"] == "blob"]

    def fetch_file(self, full_name: str, path: str) -> Optional[str]:
        from pathlib import PurePosixPath
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            return None
        try:
            data = self._get(f"{BASE_URL}/repos/{full_name}/contents/{path}")
        except requests.HTTPError:
            return None
        if data.get("size", 0) > MAX_FILE_SIZE:
            return None
        if data.get("encoding") != "base64":
            return None
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception:
            return None

    def iter_repo_files(self, full_name: str) -> Iterator[RepoFile]:
        try:
            branch = self.get_default_branch(full_name)
            files = self.list_files(full_name, branch)
        except Exception:
            return
        for item in files:
            content = self.fetch_file(full_name, item["path"])
            if content is not None:
                yield RepoFile(repo=full_name, path=item["path"], content=content)

    def iter_gist_files(self, gist_id: str) -> Iterator[RepoFile]:
        try:
            data = self._get(f"{BASE_URL}/gists/{gist_id}")
        except Exception:
            return
        for filename, file_info in data.get("files", {}).items():
            content = file_info.get("content")
            if content:
                yield RepoFile(repo=f"gist:{gist_id}", path=filename, content=content)

    def iter_commit_diffs(self, full_name: str, depth: int = 50) -> Iterator[tuple[str, str, str]]:
        page = 1
        fetched = 0
        while fetched < depth:
            per_page = min(100, depth - fetched)
            try:
                commits = self._get(
                    f"{BASE_URL}/repos/{full_name}/commits",
                    params={"per_page": per_page, "page": page},
                )
            except Exception:
                break
            if not commits:
                break
            for commit_info in commits:
                if fetched >= depth:
                    break
                sha = commit_info["sha"]
                try:
                    detail = self._get(f"{BASE_URL}/repos/{full_name}/commits/{sha}")
                    for file_info in detail.get("files", []):
                        patch = file_info.get("patch")
                        if patch:
                            yield sha, file_info["filename"], patch
                except Exception:
                    pass
                fetched += 1
            if len(commits) < per_page:
                break
            page += 1


class RateLimitError(Exception):
    def __init__(self, wait_seconds: int):
        self.wait_seconds = wait_seconds
        super().__init__(f"Rate limited. Reset in {wait_seconds}s")
