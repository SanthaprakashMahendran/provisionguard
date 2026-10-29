"""Entry point: run every check on plan.json, assemble one review, and post it to the PR."""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Dict, List, Tuple

from .cost import cost_review
from .diagram import diagram_review
from .existing import existing_review
from .github_comment import upsert_comment
from .plan_parser import ResourceChange, load_plan, plan_region, resource_changes
from .quotas import quota_review
from .report import WARN, Section, assemble, overall
from .rightsizing import rightsizing_review
from .security import security_review
from .tagging import tagging_review

ACTION_ICONS = {"create": "🟢", "update": "🟡", "replace": "🟠", "delete": "🔴"}


def plan_details_review(plan: Dict, changes: List[ResourceChange]) -> Section:
    actionable = [c for c in changes if c.action != "no-op"]
    counts = Counter(c.action for c in actionable)
    summary = ", ".join(f"{n} to {a}" for a, n in sorted(counts.items())) or "no changes"
    by_type = Counter((c.type, c.action) for c in actionable)
    rows = "\n".join(
        f"| `{rtype}` | {ACTION_ICONS.get(action, '⚪')} {action} | {n} |" for (rtype, action), n in sorted(by_type.items())
    )
    body = (
        f"<details><summary>{summary} · {plan_region(plan)} · Terraform {plan.get('terraform_version', '?')}"
        "</summary>\n\n"
        f"| Resource type | Action | Count |\n|---|---|---:|\n{rows}\n\n</details>"
    )
    return Section("📋 Plan details", body)


# Blockers first, then policy, then cost, then the picture and the raw plan.
REVIEWS: List[Tuple[str, Callable[[Dict, List[ResourceChange]], Section]]] = [
    ("🔒 Security", security_review),
    ("💥 Existing infrastructure", existing_review),
    ("📊 Service quotas", quota_review),
    ("📏 Right-sizing", rightsizing_review),
    ("🏷️ Tagging", tagging_review),
    ("💰 Cost", cost_review),
    ("🗺️ Architecture", diagram_review),
    ("📋 Plan details", plan_details_review),
]


def build_report(plan: Dict) -> str:
    return build_review(plan)[0]


def build_review(plan: Dict) -> Tuple[str, str]:
    """The comment text and the overall verdict ("caution", "warning" or "ok")."""
    changes = resource_changes(plan)
    sections = []
    for title, review in REVIEWS:
        try:
            sections.append(review(plan, changes))
        except Exception as exc:  # One broken check shouldn't hide the rest of the review.
            print(f"::warning::{review.__name__} failed: {exc!r}", file=sys.stderr)
            sections.append(Section(title, f"⚠️ This check failed: {exc}", WARN, score="⚠️ check failed",
                                    reasons=[f"the {title.split(' ', 1)[1].lower()} check failed"]))
    updated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    return assemble(sections, os.environ.get("HEAD_SHA"), updated), overall(sections)


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a Terraform plan and comment on the PR.")
    parser.add_argument("--plan", required=True, help="Path to `terraform show -json` output")
    parser.add_argument("--dry-run", action="store_true", help="Print the report instead of posting it")
    args = parser.parse_args()

    report, verdict = build_review(load_plan(args.plan))
    if os.environ.get("GITHUB_OUTPUT"):  # lets the action expose the verdict and optionally fail on it
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"verdict={verdict}\n")

    if args.dry_run:
        print(report)
        return 0

    repo = os.environ["GITHUB_REPOSITORY"]
    pr_number = int(os.environ["PR_NUMBER"])
    url = upsert_comment(repo, pr_number, report, os.environ["GITHUB_TOKEN"])
    print(f"Posted review: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
