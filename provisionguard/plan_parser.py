"""Load a `terraform show -json` plan and normalise its resource changes."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ResourceChange:
    address: str
    type: str
    name: str
    actions: List[str]
    before: Optional[Dict[str, Any]]
    after: Optional[Dict[str, Any]]
    after_unknown: Dict[str, Any]
    replace_paths: List[List[Any]] = field(default_factory=list)  # attributes that force a replacement
    action_reason: str = ""  # e.g. "delete_because_no_resource_config"

    @property
    def action(self) -> str:
        """Collapse Terraform's action list into one word."""
        actions = set(self.actions)
        if actions == {"create", "delete"}:
            return "replace"
        if actions <= {"no-op", "read"}:
            return "no-op"
        return "/".join(self.actions)

    @property
    def values(self) -> Dict[str, Any]:
        """Attributes after the change, or before it for deletes."""
        return self.after if self.after is not None else (self.before or {})

    @property
    def tags(self) -> Dict[str, str]:
        """Tags including provider default_tags (`tags_all`), if known at plan time."""
        return self.values.get("tags_all") or self.values.get("tags") or {}


def load_plan(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def resource_changes(plan: Dict[str, Any]) -> List[ResourceChange]:
    """Managed resources in the plan; data sources are skipped."""
    changes = []
    for rc in plan.get("resource_changes", []):
        if rc.get("mode") != "managed":
            continue
        change = rc["change"]
        changes.append(
            ResourceChange(
                address=rc["address"],
                type=rc["type"],
                name=rc["name"],
                actions=change["actions"],
                before=change.get("before"),
                after=change.get("after"),
                after_unknown=change.get("after_unknown") or {},
                replace_paths=change.get("replace_paths") or [],
                action_reason=rc.get("action_reason", ""),
            )
        )
    return changes


def plan_region(plan: Dict[str, Any]) -> str:
    """Region from the `aws_region` variable, falling back to the CI environment."""
    region = plan.get("variables", {}).get("aws_region", {}).get("value")
    return region or os.environ.get("AWS_REGION", "us-east-1")
