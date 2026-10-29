"""Decide whether a pull request touches anything ProvisionGuard reviews, so the action can skip the rest.

A workflow's `on.pull_request.paths` filter can't use inputs, so the folder check happens here instead.
Prints "true" or "false":  python -m provisionguard.changes
"""
from __future__ import annotations

import os
import sys
from typing import List

from .config import config_path, load_config, terraform_dir
from .github_comment import _next_page, _request


def relevant_paths() -> List[str]:
    """Folders (ending in /) and files whose change means the review must run."""
    folder = terraform_dir()
    paths = ["" if folder == "." else folder + "/", "policy/", config_path().as_posix()]
    paths += [str(p) for p in (load_config().get("policies") or {}).values() if p]
    return paths


def is_relevant(files: List[str], paths: List[str]) -> bool:
    """A file counts when it is one of the watched files or lies inside a watched folder ("" = everything)."""
    return any(f == p or ((p == "" or p.endswith("/")) and f.startswith(p)) for f in files for p in paths)


def changed_files(repo: str, pr_number: int, token: str) -> List[str]:
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    url = f"{api}/repos/{repo}/pulls/{pr_number}/files?per_page=100"
    files: List[str] = []
    while url:
        page, link = _request("GET", url, token)
        for item in page:
            files.append(item["filename"])
            if item.get("previous_filename"):  # a rename out of the folder counts too
                files.append(item["previous_filename"])
        url = _next_page(link)
    return files


def should_review() -> bool:
    if os.environ.get("PROVISIONGUARD_SKIP_UNCHANGED", "true").lower() == "false":
        return True
    pr_number = os.environ.get("PR_NUMBER")
    if not pr_number:  # not a pull request (push, manual run): always review
        return True
    try:
        files = changed_files(os.environ["GITHUB_REPOSITORY"], int(pr_number), os.environ["GITHUB_TOKEN"])
    except Exception as exc:  # when in doubt, review: never skip silently because of an API hiccup
        print(f"::warning::Couldn't list the pull request's files ({exc!r}); reviewing anyway", file=sys.stderr)
        return True
    paths = relevant_paths()
    if is_relevant(files, paths):
        return True
    watched = ", ".join(p or "(whole repository)" for p in paths)
    print(f"No changes under {watched}; skipping the review.", file=sys.stderr)
    return False


if __name__ == "__main__":
    print("true" if should_review() else "false")
