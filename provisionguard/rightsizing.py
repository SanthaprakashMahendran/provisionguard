"""Flag resources that break their environment's size rules (the right-sizing policy)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import policy_label, policy_path
from .cost import RDS_ENGINES, RDS_STORAGE
from .plan_parser import ResourceChange, plan_region
from .pricing import HOURS_PER_MONTH, Pricer, default_pricer
from .report import OK, WARN, Section, count

ENVIRONMENT_ALIASES = {"development": "dev", "stage": "staging", "stg": "staging", "production": "prod", "prd": "prod"}


@dataclass
class Finding:
    address: str
    environment: str
    current: str
    rule: str
    suggested: str
    monthly_saving: Optional[float]  # negative when the fix costs more (e.g. adding Multi-AZ)


def load_policy(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    import yaml

    path = path or policy_path("rightsizing")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def environment_of(change: ResourceChange) -> Optional[str]:
    """Value of the `environment` or `env` tag, normalised (e.g. "Production" → "prod")."""
    for key, value in change.tags.items():
        if key.lower() in ("environment", "env"):
            env = str(value).strip().lower()
            return ENVIRONMENT_ALIASES.get(env, env)
    return None


def _ec2_finding(
    change: ResourceChange, env: str, instance_type: str, count: int, limits: Dict, region: str, pricer: Pricer
) -> Optional[Finding]:
    cap = limits.get("max_ec2")
    if not cap or instance_type == cap:
        return None
    current = pricer.ec2_instance_hourly(region, instance_type)
    allowed = pricer.ec2_instance_hourly(region, cap)
    if current is None or allowed is None or current <= allowed:
        return None
    prefix = f"{count} × " if count > 1 else ""
    return Finding(
        address=change.address,
        environment=env,
        current=f"{prefix}{instance_type}",
        rule=f"{env}: max {cap}",
        suggested=f"{prefix}{cap}",
        monthly_saving=(current - allowed) * HOURS_PER_MONTH * count,
    )


def check_instance(change: ResourceChange, env: str, limits: Dict, region: str, pricer: Pricer) -> List[Finding]:
    finding = _ec2_finding(change, env, change.values.get("instance_type", ""), 1, limits, region, pricer)
    return [finding] if finding else []


def check_node_group(change: ResourceChange, env: str, limits: Dict, region: str, pricer: Pricer) -> List[Finding]:
    values = change.values
    instance_type = (values.get("instance_types") or ["t3.medium"])[0]
    desired = ((values.get("scaling_config") or [{}])[0].get("desired_size")) or 1
    finding = _ec2_finding(change, env, instance_type, desired, limits, region, pricer)
    return [finding] if finding else []


def _rds_monthly(
    pricer: Pricer, region: str, instance_class: str, engine: str, multi_az: bool, storage_gb: int, storage: str
) -> Optional[float]:
    hourly = pricer.rds_instance_hourly(region, instance_class, engine, multi_az)
    gb_month = pricer.rds_storage_gb_month(region, storage, multi_az)
    if hourly is None or gb_month is None:
        return None
    return hourly * HOURS_PER_MONTH + storage_gb * gb_month


def check_database(change: ResourceChange, env: str, limits: Dict, region: str, pricer: Pricer) -> List[Finding]:
    """Size cap first, then the Multi-AZ rule priced on the suggested size, so savings add up without overlap."""
    values = change.values
    instance_class = values.get("instance_class", "")
    multi_az = bool(values.get("multi_az"))
    engine = RDS_ENGINES.get(values.get("engine", ""))
    storage = RDS_STORAGE.get(values.get("storage_type") or "gp2")
    storage_gb = values.get("allocated_storage") or 0
    priceable = engine is not None and storage is not None

    def monthly(cls: str, maz: bool) -> Optional[float]:
        return _rds_monthly(pricer, region, cls, engine, maz, storage_gb, storage) if priceable else None

    findings = []
    cap = limits.get("max_rds")
    if cap and instance_class != cap and priceable:
        current, allowed = monthly(instance_class, multi_az), monthly(cap, multi_az)
        if current is not None and allowed is not None and current > allowed:
            findings.append(Finding(change.address, env, instance_class, f"{env}: max {cap}", cap, current - allowed))
            instance_class = cap

    rule = limits.get("rds_multi_az")
    if rule == "forbidden" and multi_az:
        before, after = monthly(instance_class, True), monthly(instance_class, False)
        saving = before - after if before is not None and after is not None else None
        findings.append(Finding(change.address, env, "Multi-AZ", f"{env}: Multi-AZ not needed", "Single-AZ", saving))
    elif rule == "required" and not multi_az:
        before, after = monthly(instance_class, False), monthly(instance_class, True)
        saving = before - after if before is not None and after is not None else None
        findings.append(Finding(change.address, env, "Single-AZ", f"{env}: Multi-AZ required", "Multi-AZ", saving))
    return findings


CHECKS: Dict[str, Callable[[ResourceChange, str, Dict, str, Pricer], List[Finding]]] = {
    "aws_instance": check_instance,
    "aws_eks_node_group": check_node_group,
    "aws_db_instance": check_database,
}


def _money(amount: float) -> str:
    return f"${amount:,.2f}"


def _impact(saving: Optional[float]) -> str:
    if saving is None:
        return "n/a"
    return f"saves {_money(saving)}" if saving >= 0 else f"adds {_money(-saving)}"


def rightsizing_review(
    plan: Dict,
    changes: List[ResourceChange],
    pricer: Optional[Pricer] = None,
    policy: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Section:
    region = plan_region(plan)
    policy = load_policy() if policy is None else policy

    findings: List[Finding] = []
    untagged: List[str] = []
    no_rules = set()
    for change in changes:
        check = CHECKS.get(change.type)
        if not check or change.action not in ("create", "update", "replace"):
            continue
        env = environment_of(change)
        if env is None:
            untagged.append(change.address)
        elif env not in policy:
            no_rules.add(env)
        else:
            findings += check(change, env, policy[env] or {}, region, pricer or default_pricer())

    parts = []
    savings = extra = 0.0
    if findings:
        findings.sort(key=lambda f: f.monthly_saving or 0, reverse=True)
        savings = sum(f.monthly_saving for f in findings if f.monthly_saving and f.monthly_saving > 0)
        extra = -sum(f.monthly_saving for f in findings if f.monthly_saving and f.monthly_saving < 0)
        headline = f"⚠️ **{count(len(findings), 'policy finding')}**"
        if savings:
            headline += f" · possible saving **{_money(savings)}/month**"
        if extra:
            headline += f" · required fixes add **{_money(extra)}/month**"
        rows = "\n".join(
            f"| `{f.address}` | {f.current} → **{f.suggested}**<br><sub>{f.rule}</sub> | {_impact(f.monthly_saving)} |"
            for f in findings
        )
        parts.append(headline)
        parts.append(f"| Resource | Change | Monthly impact |\n|---|---|---:|\n{rows}")
    else:
        parts.append("✅ All checked resources are within their environment's size limits.")
    if untagged:
        parts.append("ℹ️ No `environment` tag, so not checked: " + ", ".join(f"`{a}`" for a in untagged))
    if no_rules:
        parts.append(f"ℹ️ No policy for {'environment' if len(no_rules) == 1 else 'environments'}: " + ", ".join(f"`{e}`" for e in sorted(no_rules)))
    parts.append(f"<sub>Limits from {policy_label('rightsizing')}. Impact compares on-demand list prices.</sub>")

    if not findings:
        return Section("📏 Right-sizing", "\n\n".join(parts), OK, score="✅ within the size policy")
    score = f"⚠️ {len(findings)} over policy"
    score += f" · save {_money(savings)}/month" if savings else ""
    score += f" · required fixes add {_money(extra)}/month" if extra else ""
    reason = f"{count(len(findings), 'size-policy finding')}" + (f" (save {_money(savings)}/month)" if savings else "")
    return Section("📏 Right-sizing", "\n\n".join(parts), WARN, score=score, reasons=[reason])


def rightsizing_section(
    plan: Dict,
    changes: List[ResourceChange],
    pricer: Optional[Pricer] = None,
    policy: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    return rightsizing_review(plan, changes, pricer, policy).markdown()
