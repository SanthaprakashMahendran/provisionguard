"""Create or update a single "sticky" ProvisionGuard comment on a pull request."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Optional, Tuple

MARKER = "<!-- provisionguard-ai -->"
MAX_BODY = 65_000  # GitHub rejects comment bodies over 65,536 characters.


def _request(method: str, url: str, token: str, body: Optional[dict] = None) -> Tuple[Any, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp), resp.headers.get("Link", "")


def _next_page(link_header: str) -> Optional[str]:
    match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
    return match.group(1) if match else None


def _find_existing(api: str, repo: str, pr_number: int, token: str) -> Optional[int]:
    url: Optional[str] = f"{api}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    while url:
        comments, link = _request("GET", url, token)
        for comment in comments:
            if comment["body"].startswith(MARKER):
                return comment["id"]
        url = _next_page(link)
    return None


def upsert_comment(repo: str, pr_number: int, body: str, token: str) -> str:
    """Post the review, replacing the previous one so each push updates in place."""
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    body = f"{MARKER}\n{body}"
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY] + "\n\n_…truncated, see the workflow run for the full report._"

    existing = _find_existing(api, repo, pr_number, token)
    if existing:
        result, _ = _request("PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
    else:
        result, _ = _request("POST", f"{api}/repos/{repo}/issues/{pr_number}/comments", token, {"body": body})
    return result["html_url"]
