"""Check required tags (the tagging policy) and suggest fixes from the rest of the plan."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import policy_label, policy_path
from .plan_parser import ResourceChange
from .report import INFO, OK, WARN, Section, count
from .rightsizing import load_policy



@dataclass
class TagProblem:
    address: str
    problems: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    hint: str = ""


def _taggable(change: ResourceChange) -> bool:
    """Resources that can carry tags have a tags_all attribute in the plan."""
    return change.after is not None and "tags_all" in change.after


def _tag_references(plan: Dict) -> Dict[str, List[str]]:
    """What each root-module resource's `tags` expression refers to, e.g. {"aws_vpc.main": ["local.common_tags"]}."""
    refs = {}
    for resource in plan.get("configuration", {}).get("root_module", {}).get("resources", []):
        tags = resource.get("expressions", {}).get("tags", {})
        refs[resource.get("address", "")] = tags.get("references", []) if isinstance(tags, dict) else []
    return refs


def _suggest(key: str, others: List[ResourceChange]) -> str:
    values = Counter(c.tags[key] for c in others if c.tags.get(key))
    if not values:
        return f"`{key}`: no other resource sets it, please choose a value"
    value, count = values.most_common(1)[0]
    if len(values) == 1:
        return f'`{key} = "{value}"` (used by all {count} other taggable resources)'
    return f'`{key} = "{value}"` (most common: {count} of {sum(values.values())} resources, check this is right)'


def check_tags(plan: Dict, changes: List[ResourceChange], policy: Dict[str, Any]) -> List[TagProblem]:
    required: List[str] = policy.get("required_tags", [])
    allowed: Dict[str, List[str]] = policy.get("allowed_values", {})
    taggable = [c for c in changes if c.action in ("create", "update", "replace") and _taggable(c)]
    refs = _tag_references(plan)

    # The local most resources build their tags from, e.g. local.common_tags.
    shared = Counter(r for c in taggable for r in refs.get(f"{c.type}.{c.name}", []) if r.startswith("local."))
    shared_local = shared.most_common(1)[0][0] if shared else None

    results = []
    for change in taggable:
        tags = change.tags
        lower = {k.lower(): k for k in tags}
        problem = TagProblem(change.address)
        missing = [key for key in required if key not in tags]
        for key in missing:
            if key.lower() in lower:
                problem.problems.append(f"`{key}` is written as `{lower[key.lower()]}` (tag keys are case-sensitive)")
            else:
                problem.problems.append(f"missing `{key}`")
                others = [c for c in taggable if c is not change]
                problem.suggestions.append(_suggest(key, others))
        for key, values in allowed.items():
            if key in tags and tags[key] not in values:
                problem.problems.append(f"`{key} = \"{tags[key]}\"` is not one of {', '.join(values)}")

        own_refs = refs.get(f"{change.type}.{change.name}", [])
        if missing and shared_local and shared_local not in own_refs:
            problem.hint = (
                f"Most resources build their tags with `merge({shared_local}, {{...}})`; this one sets its tags "
                f"directly, which is why it misses shared tags."
            )
        if problem.problems:
            results.append(problem)
    return results


def tagging_review(plan: Dict, changes: List[ResourceChange], policy: Optional[Dict[str, Any]] = None) -> Section:
    policy = load_policy(policy_path("tagging")) if policy is None else policy
    taggable = [c for c in changes if c.action in ("create", "update", "replace") and _taggable(c)]
    problems = check_tags(plan, changes, policy)
    required = ", ".join(f"`{t}`" for t in policy.get("required_tags", []))

    parts = []
    if not taggable:
        parts.append("No taggable resources in this change.")
    elif not problems:
        parts.append(f"✅ All {len(taggable)} taggable resources have the required tags ({required}).")
    else:
        parts.append(f"⚠️ **{len(problems)} of {count(len(taggable), 'taggable resource')}** {'breaks' if len(problems) == 1 else 'break'} the tagging policy")
        rows = "\n".join(
            f"| `{p.address}` | {'<br>'.join(p.problems)} | {'<br>'.join(p.suggestions) or '-'} |" for p in problems
        )
        parts.append(f"| Resource | Problem | Suggested fix |\n|---|---|---|\n{rows}")
        parts += [f"💡 `{p.address}`: {p.hint}" for p in problems if p.hint]
    plain = ", ".join(policy.get("required_tags", []))
    parts.append(f"<sub>Required tags {plain} from {policy_label('tagging')}.</sub>")
    body = "\n\n".join(parts)
    if not taggable:
        return Section("🏷️ Tagging", body, INFO)
    if not problems:
        return Section("🏷️ Tagging", body, OK, score=f"✅ all {len(taggable)} resources tagged")
    return Section("🏷️ Tagging", body, WARN, score=f"⚠️ {len(problems)} of {len(taggable)} resources {'breaks' if len(problems) == 1 else 'break'} the policy",
                   reasons=[f"{count(len(problems), 'resource')} missing required tags"])


def tagging_section(plan: Dict, changes: List[ResourceChange], policy: Optional[Dict[str, Any]] = None) -> str:
    return tagging_review(plan, changes, policy).markdown()
