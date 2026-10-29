"""Estimate the monthly cost of each resource in the plan."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .plan_parser import ResourceChange, plan_region
from .pricing import HOURS_PER_MONTH, Pricer, default_pricer
from .report import INFO, Section, count

# Resource types AWS doesn't charge for on their own.
FREE_TYPES = {
    "aws_vpc",
    "aws_subnet",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route_table_association",
    "aws_security_group",
    "aws_db_subnet_group",
    "aws_iam_role",
    "aws_iam_role_policy_attachment",
}

DEFAULT_ROOT_GB = 8  # Size of most Amazon Linux AMI root volumes when the config doesn't set one.
DEFAULT_NODE_DISK_GB = 20  # EKS managed node group default when disk_size isn't set.
DEFAULT_NODE_TYPE = "t3.medium"  # EKS managed node group default when instance_types isn't set.


@dataclass
class CostLine:
    address: str
    details: str
    monthly: Optional[float]
    note: str = ""


def _root_volume(change: ResourceChange) -> Tuple[int, str, str]:
    """(size in GB, volume type, note) for an instance's root disk."""
    blocks = change.values.get("root_block_device") or [{}]
    size = blocks[0].get("volume_size")
    volume_type = blocks[0].get("volume_type") or "gp3"
    if size:
        return size, volume_type, ""
    return DEFAULT_ROOT_GB, volume_type, f"root disk size comes from the AMI, assumed {DEFAULT_ROOT_GB} GB"


def ec2_instance_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    instance_type = change.values.get("instance_type", "?")
    disk_gb, disk_type, note = _root_volume(change)

    hourly = pricer.ec2_instance_hourly(region, instance_type)
    gb_month = pricer.ebs_gb_month(region, disk_type)
    details = f"{instance_type} · {disk_gb} GB {disk_type}"

    if hourly is None or gb_month is None:
        return CostLine(change.address, details, None, "price not found")
    return CostLine(change.address, details, hourly * HOURS_PER_MONTH + disk_gb * gb_month, note)


# Terraform names → Pricing API names.
RDS_ENGINES = {"postgres": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB"}
RDS_STORAGE = {
    "gp2": "General Purpose",
    "gp3": "General Purpose-GP3",
    "io1": "Provisioned IOPS",
    "standard": "Magnetic",
}


def rds_instance_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    values = change.values
    instance_class = values.get("instance_class", "?")
    engine = values.get("engine", "?")
    multi_az = bool(values.get("multi_az"))
    storage_gb = values.get("allocated_storage") or 0
    storage_type = values.get("storage_type") or "gp2"
    details = (
        f"{instance_class} · {engine} · {'Multi-AZ' if multi_az else 'Single-AZ'} · {storage_gb} GB {storage_type}"
    )

    if engine not in RDS_ENGINES or storage_type not in RDS_STORAGE:
        return CostLine(change.address, details, None, f"pricing for {engine}/{storage_type} not supported yet")

    hourly = pricer.rds_instance_hourly(region, instance_class, RDS_ENGINES[engine], multi_az)
    gb_month = pricer.rds_storage_gb_month(region, RDS_STORAGE[storage_type], multi_az)
    if hourly is None or gb_month is None:
        return CostLine(change.address, details, None, "price not found")
    return CostLine(change.address, details, hourly * HOURS_PER_MONTH + storage_gb * gb_month)


def eks_cluster_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    version = change.values.get("version")
    status = pricer.eks_version_status(region, version) if version else None
    extended = status in ("EXTENDED_SUPPORT", "UNSUPPORTED")
    details = f"control plane · Kubernetes {version or 'latest'}"

    if extended:
        note = f"⚠️ {version} is past standard support: extended-support fee applies"
    elif status is None and version:
        note = "support status unknown, standard fee assumed"
    else:
        note = ""

    hourly = pricer.eks_cluster_hourly(region, extended)
    if hourly is None:
        return CostLine(change.address, details, None, "price not found")
    return CostLine(change.address, details, hourly * HOURS_PER_MONTH, note)


def eks_node_group_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    values = change.values
    instance_type = (values.get("instance_types") or [DEFAULT_NODE_TYPE])[0]
    scaling = (values.get("scaling_config") or [{}])[0]
    desired = scaling.get("desired_size") or 1
    maximum = scaling.get("max_size") or desired
    disk_gb = values.get("disk_size") or DEFAULT_NODE_DISK_GB
    details = f"{desired} × {instance_type} (max {maximum}) · {disk_gb} GB gp3 each"

    hourly = pricer.ec2_instance_hourly(region, instance_type)
    gb_month = pricer.ebs_gb_month(region, "gp3")
    if hourly is None or gb_month is None:
        return CostLine(change.address, details, None, "price not found")
    per_node = hourly * HOURS_PER_MONTH + disk_gb * gb_month

    notes = []
    if maximum > desired:
        notes.append(f"up to {_money(maximum * per_node)} at {maximum} nodes")
    if values.get("capacity_type") == "SPOT":
        notes.append("Spot nodes: on-demand price shown as upper bound")
    return CostLine(change.address, details, desired * per_node, "; ".join(notes))


def nat_gateway_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    hourly = pricer.nat_gateway_hourly(region)
    if hourly is None:
        return CostLine(change.address, "hourly fee", None, "price not found")
    return CostLine(change.address, "hourly fee", hourly * HOURS_PER_MONTH, "plus a per-GB fee for data processed")


def eip_cost(change: ResourceChange, region: str, pricer: Pricer) -> CostLine:
    hourly = pricer.public_ipv4_hourly(region)
    if hourly is None:
        return CostLine(change.address, "public IPv4 address", None, "price not found")
    return CostLine(change.address, "public IPv4 address", hourly * HOURS_PER_MONTH)


ESTIMATORS: Dict[str, Callable[[ResourceChange, str, Pricer], CostLine]] = {
    "aws_instance": ec2_instance_cost,
    "aws_db_instance": rds_instance_cost,
    "aws_eks_cluster": eks_cluster_cost,
    "aws_eks_node_group": eks_node_group_cost,
    "aws_nat_gateway": nat_gateway_cost,
    "aws_eip": eip_cost,
}


def _money(amount: float) -> str:
    return f"${amount:,.2f}"


def cost_review(plan: Dict, changes: List[ResourceChange], pricer: Optional[Pricer] = None) -> Section:
    region = plan_region(plan)
    creating = [c for c in changes if c.action in ("create", "update", "replace")]

    lines: List[CostLine] = []
    not_priced = set()
    for change in creating:
        estimator = ESTIMATORS.get(change.type)
        if estimator:
            pricer = pricer or default_pricer()
            lines.append(estimator(change, region, pricer))
        elif change.type not in FREE_TYPES:
            not_priced.add(change.type)

    total = sum(line.monthly for line in lines if line.monthly is not None)
    lines.sort(key=lambda line: line.monthly or 0, reverse=True)
    rows = "\n".join(
        f"| `{line.address}` | {line.details} | "
        f"{_money(line.monthly) if line.monthly is not None else 'n/a'} | {line.note} |"
        for line in lines
    )

    parts = [f"**Estimated monthly cost: {_money(total)}** for {count(len(lines), 'priced resource')} in {region}"]
    if lines:
        parts.append(f"| Resource | Details | Monthly | Note |\n|---|---|---:|---|\n{rows}")
    if not_priced:
        parts.append("⏳ Not priced yet: " + ", ".join(f"`{t}`" for t in sorted(not_priced)))
    parts.append(
        f"<sub>On-demand list prices × {HOURS_PER_MONTH} h/month. "
        "Excludes usage-based charges such as data transfer.</sub>"
    )
    counts = Counter(c.action for c in changes if c.action != "no-op")
    planned = ", ".join(f"{n} to {action}" for action, n in sorted(counts.items())) or "no changes"
    return Section("💰 Cost", "\n\n".join(parts), INFO, score=f"{_money(total)}/month · {planned}")


def cost_section(plan: Dict, changes: List[ResourceChange], pricer: Optional[Pricer] = None) -> str:
    return cost_review(plan, changes, pricer).markdown()
