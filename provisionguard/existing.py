"""Impact on infrastructure that already exists.

6a  Name clashes: resources the plan creates whose name is already taken in AWS (wrong or lost state file,
    or another team's resource). Read-only AWS lookups.
6b  Changes to existing resources: replacements and deletions from plan.json (and why), what else in this
    repo depends on them, and what is attached to them in AWS. Read-only AWS lookups.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .aws import AwsClients, error_code, pages
from .plan_parser import ResourceChange, plan_region
from .report import FAIL, OK, WARN, Section, count

# ---- 6a: name clashes ----------------------------------------------------------------------------------------

NOT_FOUND = {"NoSuchEntity", "DBInstanceNotFound", "DBInstanceNotFoundFault", "DBSubnetGroupNotFoundFault",
             "ResourceNotFoundException", "404", "NoSuchBucket"}


def _exists(call: Callable[[], Any], taken_codes: Tuple[str, ...] = ()) -> bool:
    try:
        call()
        return True
    except Exception as exc:
        if error_code(exc) in NOT_FOUND:
            return False
        if error_code(exc) in taken_codes:
            return True
        raise


# Resource types whose name must be unique: creating a second one fails on apply.
UNIQUE_NAME_LOOKUPS: Dict[str, Callable[[AwsClients, str], bool]] = {
    "aws_iam_role": lambda aws, n: _exists(lambda: aws["iam"].get_role(RoleName=n)),
    "aws_db_instance": lambda aws, n: _exists(lambda: aws["rds"].describe_db_instances(DBInstanceIdentifier=n)),
    "aws_db_subnet_group": lambda aws, n: _exists(lambda: aws["rds"].describe_db_subnet_groups(DBSubnetGroupName=n)),
    "aws_eks_cluster": lambda aws, n: _exists(lambda: aws["eks"].describe_cluster(name=n)),
    # Bucket names are global: 403 means another account owns the name.
    "aws_s3_bucket": lambda aws, n: _exists(lambda: aws["s3"].head_bucket(Bucket=n), taken_codes=("403",)),
}
NAME_ATTRIBUTES = {"aws_db_instance": "identifier", "aws_s3_bucket": "bucket"}

# Resource types AWS lets you duplicate: a second one is created silently. Matched by their Name tag.
NAME_TAG_LOOKUPS = {
    "aws_vpc": ("describe_vpcs", "Vpcs"),
    "aws_subnet": ("describe_subnets", "Subnets"),
    "aws_internet_gateway": ("describe_internet_gateways", "InternetGateways"),
    "aws_route_table": ("describe_route_tables", "RouteTables"),
    "aws_nat_gateway": ("describe_nat_gateways", "NatGateways"),
    "aws_instance": ("describe_instances", "Reservations"),
}


@dataclass
class Clash:
    address: str
    name: str
    fails: bool  # True: apply fails; False: apply creates a duplicate


def _tag_value(tags: List[Dict[str, str]], key: str) -> Optional[str]:
    return next((t.get("Value") for t in tags or [] if t.get("Key") == key), None)


def _existing_name_tags(aws: AwsClients, rtype: str, names: List[str]) -> Set[str]:
    operation, key = NAME_TAG_LOOKUPS[rtype]
    filters = [{"Name": "tag:Name", "Values": names}]
    if rtype == "aws_nat_gateway":
        items = pages(aws["ec2"], operation, key, Filter=filters)  # this one call spells it "Filter"
        items = [i for i in items if i.get("State") not in ("deleted", "deleting", "failed")]
    elif rtype == "aws_instance":
        filters.append({"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]})
        items = [i for r in pages(aws["ec2"], operation, key, Filters=filters) for i in r.get("Instances", [])]
    else:
        items = pages(aws["ec2"], operation, key, Filters=filters)
    return {v for v in (_tag_value(i.get("Tags", []), "Name") for i in items) if v}


def find_clashes(changes: List[ResourceChange], aws: AwsClients) -> Tuple[List[Clash], List[str]]:
    clashes, errors = [], []
    creates = [c for c in changes if c.action == "create" and c.after is not None]

    for change in creates:
        lookup = UNIQUE_NAME_LOOKUPS.get(change.type)
        name = change.after.get(NAME_ATTRIBUTES.get(change.type, "name"))
        if not lookup or not isinstance(name, str):
            continue
        try:
            if lookup(aws, name):
                clashes.append(Clash(change.address, name, fails=True))
        except Exception as exc:
            print(f"::warning::Name check for {change.address} failed: {exc!r}", file=sys.stderr)
            errors.append(change.address)

    by_type: Dict[str, List[ResourceChange]] = defaultdict(list)
    for change in creates:
        if change.type in NAME_TAG_LOOKUPS and isinstance((change.after.get("tags") or {}).get("Name"), str):
            by_type[change.type].append(change)
    for rtype, typed in by_type.items():
        try:
            taken = _existing_name_tags(aws, rtype, sorted({c.after["tags"]["Name"] for c in typed}))
        except Exception as exc:
            print(f"::warning::Name-tag check for {rtype} failed: {exc!r}", file=sys.stderr)
            errors += [c.address for c in typed]
            continue
        clashes += [Clash(c.address, c.after["tags"]["Name"], fails=False) for c in typed
                    if c.after["tags"]["Name"] in taken]
    return clashes, errors


# ---- 6b: changes to existing resources -----------------------------------------------------------------------

# Replacing or deleting these loses data or takes running workloads down.
STATEFUL_TYPES = {
    "aws_db_instance": "stored data is lost unless restored from a snapshot",
    "aws_rds_cluster": "stored data is lost unless restored from a snapshot",
    "aws_ebs_volume": "the disk and its data are lost",
    "aws_s3_bucket": "the bucket and its objects are lost",
    "aws_dynamodb_table": "the table and its data are lost",
    "aws_efs_file_system": "the file system and its data are lost",
    "aws_instance": "the server is rebuilt: local data is lost and it gets new IP addresses",
    "aws_eks_cluster": "every workload running on the cluster goes down",
    "aws_vpc": "everything inside the VPC must be rebuilt",
    "aws_iam_role": "the role gets a new ID; anything that trusts or refers to the old role loses access",
}
NOT_RESOURCE_PREFIXES = ("local.", "var.", "each.", "count.", "data.", "module.", "path.", "self.", "terraform.")


@dataclass
class Impact:
    address: str
    action: str
    why: str
    severity: str  # "high", "medium" or "low"
    effects: List[str]


def _references(expressions: Any) -> Set[str]:
    """Every resource address an expression tree refers to, e.g. {"aws_iam_role.eks_node"}."""
    found: Set[str] = set()
    if isinstance(expressions, dict):
        for key, value in expressions.items():
            if key == "references" and isinstance(value, list):
                for ref in value:
                    parts = ref.split(".")
                    if len(parts) >= 2 and not ref.startswith(NOT_RESOURCE_PREFIXES):
                        found.add(f"{parts[0]}.{parts[1].split('[')[0]}")
            else:
                found |= _references(value)
    elif isinstance(expressions, list):
        for item in expressions:
            found |= _references(item)
    return found


def dependents(plan: Dict) -> Dict[str, List[str]]:
    """For each resource in the root module, the other resources in this repo that refer to it."""
    users: Dict[str, Set[str]] = defaultdict(set)
    for resource in plan.get("configuration", {}).get("root_module", {}).get("resources", []):
        address = resource.get("address", "")
        targets = _references(resource.get("expressions", {})) | set(resource.get("depends_on", []))
        for target in targets:
            if target != address:
                users[target].add(address)
    return {k: sorted(v) for k, v in users.items()}


def _changed_attributes(change: ResourceChange) -> List[str]:
    before, after = change.before or {}, change.after or {}
    return sorted(k for k in after if before.get(k) != after.get(k) and not change.after_unknown.get(k))


def _attached_iam_role(aws: AwsClients, before: Dict[str, Any]) -> List[str]:
    name = before["name"]
    iam = aws["iam"]
    policies = len(pages(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name))
    profiles = len(pages(iam, "list_instance_profiles_for_role", "InstanceProfiles", RoleName=name))
    last_used = iam.get_role(RoleName=name)["Role"].get("RoleLastUsed", {}).get("LastUsedDate")
    used = last_used.strftime("%Y-%m-%d") if hasattr(last_used, "strftime") else (last_used or "never")
    return [f"{policies} polic{'y' if policies == 1 else 'ies'} attached",
            count(profiles, "instance profile"), f"last used: {used}"]


def _attached_network(filter_name: str) -> Callable[[AwsClients, Dict[str, Any]], List[str]]:
    def attached(aws: AwsClients, before: Dict[str, Any]) -> List[str]:
        interfaces = pages(aws["ec2"], "describe_network_interfaces", "NetworkInterfaces",
                           Filters=[{"Name": filter_name, "Values": [before["id"]]}])
        if not interfaces:
            return ["nothing attached in AWS"]
        kinds = defaultdict(int)
        for interface in interfaces:
            kinds[interface.get("InterfaceType") or "instance"] += 1
        detail = ", ".join(f"{n} {kind}" for kind, n in sorted(kinds.items()))
        return [f"{count(len(interfaces), 'network interface')} attached in AWS ({detail})"]
    return attached


ATTACHED_LOOKUPS: Dict[str, Callable[[AwsClients, Dict[str, Any]], List[str]]] = {
    "aws_iam_role": _attached_iam_role,
    "aws_security_group": _attached_network("group-id"),
    "aws_subnet": _attached_network("subnet-id"),
    "aws_vpc": _attached_network("vpc-id"),
}


def find_impacts(plan: Dict, changes: List[ResourceChange], aws: AwsClients) -> List[Impact]:
    users = dependents(plan)
    impacts = []
    for change in changes:
        if change.action not in ("replace", "delete", "update"):
            continue
        base = f"{change.type}.{change.name}"
        effects: List[str] = []
        if change.action == "replace":
            fields = [".".join(str(p) for p in path) for path in change.replace_paths]
            why = f"`{'`, `'.join(fields)}` can't change in place" if fields else "Terraform must recreate it"
            severity = "high" if change.type in STATEFUL_TYPES else "medium"
        elif change.action == "delete":
            why = "removed from the code" if "no_resource_config" in change.action_reason else (
                change.action_reason.replace("_", " ") or "deleted")
            severity = "high" if change.type in STATEFUL_TYPES else "medium"
        else:
            changed = _changed_attributes(change)
            if set(changed) <= {"tags", "tags_all"}:
                impacts.append(Impact(change.address, "update", "tags only", "low", ["safe, no downtime"]))
                continue
            why = "changes " + ", ".join(f"`{a}`" for a in changed[:5]) + (" …" if len(changed) > 5 else "")
            severity = "low"

        if change.action in ("replace", "delete") and change.type in STATEFUL_TYPES:
            effects.append(STATEFUL_TYPES[change.type])
        in_repo = [u for u in users.get(base, []) if u != base]
        if in_repo:
            effects.append(f"{count(len(in_repo), 'resource')} in this repo {'depends' if len(in_repo) == 1 else 'depend'} on it: "
                           + ", ".join(f"`{u}`" for u in in_repo[:4]) + (" …" if len(in_repo) > 4 else ""))
        lookup = ATTACHED_LOOKUPS.get(change.type)
        if lookup and change.before:
            try:
                effects += lookup(aws, change.before)
            except Exception as exc:
                print(f"::warning::Attachment lookup for {change.address} failed: {exc!r}", file=sys.stderr)
                effects.append("couldn't check what's attached in AWS")
        impacts.append(Impact(change.address, change.action, why, severity, effects))
    return impacts


# ---- report --------------------------------------------------------------------------------------------------

ACTION_LABELS = {"replace": "♻️ replace", "delete": "🗑️ delete", "update": "✏️ update"}
SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def existing_review(plan: Dict, changes: List[ResourceChange], aws: Optional[AwsClients] = None) -> Section:
    aws = aws or AwsClients(plan_region(plan))
    clashes, errors = find_clashes(changes, aws)
    impacts = find_impacts(plan, changes, aws)
    parts = []

    if clashes:
        failing = sum(c.fails for c in clashes)
        parts.append(f"🔴 **{count(len(clashes), 'name clash', 'name clashes')}**: these already exist in AWS but aren't in this stack's "
                     "state. Wrong state file, or another team's resource?")
        rows = "\n".join(
            f"| `{c.address}` | {c.name} | "
            + ("🔴 apply will fail: name already taken. Import it or rename it |" if c.fails
               else "⚠️ apply would create a duplicate with the same Name tag |")
            for c in clashes
        )
        parts.append(f"| Resource | Name | Result |\n|---|---|---|\n{rows}")
        if failing < len(clashes):
            parts.append("<sub>Duplicates are matched by Name tag, so check before assuming it's the same resource.</sub>")
    else:
        parts.append("✅ No name clashes: nothing this change creates already exists in AWS.")

    if impacts:
        order = {"high": 0, "medium": 1, "low": 2}
        impacts.sort(key=lambda i: (order[i.severity], i.address))
        risky = sum(i.severity != "low" for i in impacts)
        parts.append(f"{'🔴' if risky else '🟡'} **{count(len(impacts), 'existing resource')} {'changes' if len(impacts) == 1 else 'change'}**"
                     + (f", {risky} of them destructive" if risky else ", none destructive"))
        rows = "\n".join(
            f"| {SEVERITY_ICONS[i.severity]} `{i.address}` | {ACTION_LABELS[i.action]} | {i.why} | "
            f"{'<br>'.join(i.effects) or '-'} |"
            for i in impacts
        )
        parts.append(f"| Resource | Action | Why | Impact |\n|---|---|---|---|\n{rows}")
    else:
        parts.append("✅ No existing resources are changed or destroyed.")
    if errors:
        parts.append("⚠️ Couldn't check names for: " + ", ".join(f"`{e}`" for e in errors) + " (see the workflow log)")
    body = "\n\n".join(parts)

    fails = sum(c.fails for c in clashes)
    duplicates = len(clashes) - fails
    by_severity = {level: sum(i.severity == level for i in impacts) for level in ("high", "medium", "low")}
    blockers = [f"{count(fails, 'name clash', 'name clashes')} that {'fails' if fails == 1 else 'fail'} on apply"] if fails else []
    blockers += [f"{count(by_severity['high'], 'destructive change')} to existing resources"] if by_severity["high"] else []
    warnings = [count(duplicates, "possible duplicate")] if duplicates else []
    warnings += [f"{count(by_severity['medium'], 'existing resource')} replaced or deleted"] if by_severity["medium"] else []
    warnings += [f"couldn't check {count(len(errors), 'name')}"] if errors else []

    score_parts = [f"🔴 {count(fails, 'name clash', 'name clashes')}"] if fails else []
    score_parts += [f"🔴 {by_severity['high']} destructive"] if by_severity["high"] else []
    score_parts += [f"⚠️ {count(duplicates, 'possible duplicate')}"] if duplicates else []
    score_parts += [f"🟠 {by_severity['medium']} replaced or deleted"] if by_severity["medium"] else []
    score_parts += [f"🟡 {count(by_severity['low'], 'in-place update')}"] if by_severity["low"] else []
    score = " · ".join(score_parts) or "✅ nothing existing affected"

    title = "💥 Existing infrastructure"
    if blockers:
        return Section(title, body, FAIL, score=score, reasons=blockers)
    if warnings:
        return Section(title, body, WARN, score=score, reasons=warnings)
    return Section(title, body, OK, score=score)


def existing_section(plan: Dict, changes: List[ResourceChange], aws: Optional[AwsClients] = None) -> str:
    return existing_review(plan, changes, aws).markdown()
