"""Check that current usage plus this plan stays within the account's service quotas (read-only AWS calls)."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .aws import AwsClients, error_code as _error_code, pages as _pages
from .plan_parser import ResourceChange, plan_region
from .report import FAIL, INFO, OK, WARN, Section, count

WARN_RATIO = 0.8

# Families counted by the "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances" vCPU quota.
STANDARD_FAMILY_LETTERS = set("acdhimrtz")
OTHER_QUOTA_PREFIXES = ("inf", "dl", "trn", "hpc", "mac", "u-")


def quota_limit(aws: AwsClients, service_code: str, quota_code: str) -> float:
    """The account's applied quota value, or AWS's default when the account never changed it."""
    sq = aws["service-quotas"]
    try:
        return sq.get_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]["Value"]
    except Exception as exc:
        if _error_code(exc) != "NoSuchResourceException":
            raise
        return sq.get_aws_default_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]["Value"]


def _is_standard(instance_type: str) -> bool:
    family = instance_type.split(".")[0].lower()
    return family[:1] in STANDARD_FAMILY_LETTERS and not family.startswith(OTHER_QUOTA_PREFIXES)


# ---- current usage -------------------------------------------------------------------------------------------

def used_standard_vcpus(aws: AwsClients) -> float:
    instances = [
        i
        for r in _pages(aws["ec2"], "describe_instances", "Reservations",
                        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}])
        for i in r.get("Instances", [])
    ]
    return sum(
        i["CpuOptions"]["CoreCount"] * i["CpuOptions"]["ThreadsPerCore"]
        for i in instances
        if _is_standard(i["InstanceType"]) and i.get("InstanceLifecycle") != "spot"
    )


def used_vpcs(aws: AwsClients) -> float:
    return len(_pages(aws["ec2"], "describe_vpcs", "Vpcs"))


def used_internet_gateways(aws: AwsClients) -> float:
    return len(_pages(aws["ec2"], "describe_internet_gateways", "InternetGateways"))


def used_elastic_ips(aws: AwsClients) -> float:
    addresses = aws["ec2"].describe_addresses(Filters=[{"Name": "domain", "Values": ["vpc"]}])["Addresses"]
    return len(addresses)


def used_db_instances(aws: AwsClients) -> float:
    return len(_pages(aws["rds"], "describe_db_instances", "DBInstances"))


# ---- what the plan adds --------------------------------------------------------------------------------------

def _delta(change: ResourceChange) -> int:
    return {"create": 1, "delete": -1}.get(change.action, 0)


def _count(rtype: str) -> Callable[[List[ResourceChange], AwsClients], "Planned"]:
    def planned(changes: List[ResourceChange], aws: AwsClients) -> Planned:
        n = sum(_delta(c) for c in changes if c.type == rtype)
        return Planned(n, n)
    return planned


@dataclass
class Planned:
    expected: float
    worst_case: float  # e.g. EKS node groups scaled to max_size


def planned_standard_vcpus(changes: List[ResourceChange], aws: AwsClients) -> Planned:
    """vCPUs this plan adds: EC2 instances plus EKS node groups (desired size, and max size as worst case)."""
    wanted = []  # (instance type, expected count, worst-case count)
    for c in changes:
        sign = _delta(c)
        if not sign:
            continue
        if c.type == "aws_instance":
            wanted.append((c.values.get("instance_type", ""), sign, sign))
        elif c.type == "aws_eks_node_group":
            scaling = (c.values.get("scaling_config") or [{}])[0]
            desired = scaling.get("desired_size") or 1
            types = c.values.get("instance_types") or ["t3.medium"]
            wanted.append((types[0], sign * desired, sign * (scaling.get("max_size") or desired)))

    types = sorted({t for t, _, _ in wanted if t and _is_standard(t)})
    if not types:
        return Planned(0, 0)
    described = aws["ec2"].describe_instance_types(InstanceTypes=types)["InstanceTypes"]
    vcpus = {t["InstanceType"]: t["VCpuInfo"]["DefaultVCpus"] for t in described}
    expected = sum(vcpus.get(t, 0) * n for t, n, _ in wanted)
    worst = sum(vcpus.get(t, 0) * n for t, _, n in wanted)
    return Planned(expected, worst)


@dataclass
class QuotaCheck:
    name: str
    service_code: str
    quota_code: str
    used: Callable[[AwsClients], float]
    planned: Callable[[List[ResourceChange], AwsClients], Planned]


QUOTAS = [
    QuotaCheck("EC2 on-demand vCPUs (standard families)", "ec2", "L-1216C47A", used_standard_vcpus,
               planned_standard_vcpus),
    QuotaCheck("VPCs", "vpc", "L-F678F1CE", used_vpcs, _count("aws_vpc")),
    QuotaCheck("Internet gateways", "vpc", "L-A4707A72", used_internet_gateways, _count("aws_internet_gateway")),
    QuotaCheck("Elastic IPs", "ec2", "L-0263D0A3", used_elastic_ips, _count("aws_eip")),
    QuotaCheck("RDS DB instances", "rds", "L-7B6409FD", used_db_instances, _count("aws_db_instance")),
]


# ---- report --------------------------------------------------------------------------------------------------

def _num(value: float) -> str:
    return f"{value:,.0f}"


def _status(after: float, limit: float) -> str:
    if after > limit:
        return "🔴 will fail on apply"
    if after >= WARN_RATIO * limit:
        return f"⚠️ {after / limit:.0%} of limit"
    return f"✅ {after / limit:.0%}"


def quota_review(
    plan: Dict, changes: List[ResourceChange], aws: Optional[AwsClients] = None, quotas: Optional[List] = None
) -> Section:
    region = plan_region(plan)
    aws = aws or AwsClients(region)
    rows, failing, warning, errors = [], 0, 0, []

    for quota in quotas or QUOTAS:
        try:
            planned = quota.planned(changes, aws)
            if not planned.expected and not planned.worst_case:
                continue  # this PR doesn't touch the quota
            used = quota.used(aws)
            limit = quota_limit(aws, quota.service_code, quota.quota_code)
        except Exception as exc:  # A refused call loses one row, not the whole review.
            print(f"::warning::Quota check '{quota.name}' failed: {exc!r}", file=sys.stderr)
            errors.append(quota.name)
            continue

        after = used + planned.expected
        status = _status(after, limit)
        added = f"+{_num(planned.expected)}"
        if planned.worst_case != planned.expected:
            added += f" (+{_num(planned.worst_case - planned.expected)} when scaled out)"
            if used + planned.worst_case > limit >= after:
                status += "; ⚠️ over the limit if scaled out"
        failing += status.startswith("🔴")
        warning += status.startswith("⚠️") or "over the limit if scaled out" in status
        rows.append(f"| {quota.name} | {_num(used)} | {added} | **{_num(after)}** | {_num(limit)} | {status} |")

    parts = []
    if failing:
        parts.append(f"🔴 **{count(failing, 'quota')} will be exceeded**: `terraform apply` will fail. "
                     "Request an increase in Service Quotas before merging.")
    elif warning:
        parts.append(f"⚠️ **{count(warning, 'quota')} close to the limit** after this change")
    elif rows:
        parts.append(f"✅ {'The' if len(rows) == 1 else 'All'} {count(len(rows), 'quota')} this change uses {'stays' if len(rows) == 1 else 'stay'} under {WARN_RATIO:.0%} of the limit")
    else:
        parts.append("This change doesn't add anything the checked quotas count.")
    if rows:
        parts.append("| Quota | In use | This PR | After | Limit | Status |\n|---|---:|---|---:|---:|---|\n"
                     + "\n".join(rows))
    if errors:
        parts.append("⚠️ Couldn't read: " + ", ".join(errors) + " (see the workflow log)")
    parts.append(f"<sub>Live values from the AWS account in {region}. Usage is account-wide, so other teams count too.</sub>")
    body = "\n\n".join(parts)

    title = "📊 Service quotas"
    if failing:
        return Section(title, body, FAIL, score=f"🔴 {failing} will be exceeded",
                       reasons=[f"{count(failing, 'service quota')} will be exceeded on apply"])
    if warning or errors:
        reasons = [f"{count(warning, 'quota')} near the limit"] if warning else []
        reasons += [f"couldn't check {count(len(errors), 'quota')}"] if errors else []
        return Section(title, body, WARN, score="⚠️ " + " · ".join(reasons), reasons=reasons)
    if rows:
        return Section(title, body, OK, score=f"✅ {count(len(rows), 'quota')} under {WARN_RATIO:.0%}")
    return Section(title, body, INFO)


def quota_section(
    plan: Dict, changes: List[ResourceChange], aws: Optional[AwsClients] = None, quotas: Optional[List] = None
) -> str:
    return quota_review(plan, changes, aws, quotas).markdown()
