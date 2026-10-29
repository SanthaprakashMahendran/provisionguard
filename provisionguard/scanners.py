"""Read the JSON output of each supported security scanner into one common format.

The action runs the chosen scanners; each writes its own JSON file. Adding a scanner means
adding a reader here and an entry in SCANNERS.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .config import terraform_dir



@dataclass
class SecurityFinding:
    check_id: str
    check_name: str
    resource: str
    file_path: str  # relative to the repository root, e.g. "infra/security_groups.tf"
    lines: Tuple[int, int]
    guideline: str = ""
    tool: str = "Checkov"
    severity: str = ""  # the scanner's own rating ("critical", "high", ...); Checkov's free version gives none


@dataclass
class ScanReport:
    tool: str
    findings: List[SecurityFinding]
    passed: Optional[int]  # only Checkov reports how many checks passed
    version: str


def _read_json(path: str) -> Optional[object]:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _unique(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    """Drop exact repeats (Trivy reports some checks once per setting on the same resource)."""
    seen, unique = set(), []
    for f in findings:
        key = (f.check_id, f.resource, f.lines)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def load_checkov(path: str) -> Optional[ScanReport]:
    data = _read_json(path)
    if data is None:
        return None
    # One framework gives a single report object; several give a list of them.
    reports = data if isinstance(data, list) else [data]
    findings, passed, version = [], 0, ""
    for report in reports:
        summary = report.get("summary", {})
        passed += summary.get("passed", 0)
        version = version or summary.get("checkov_version", "")
        for check in report.get("results", {}).get("failed_checks", []):
            file_path = check.get("repo_file_path") or f"/{terraform_dir()}{check.get('file_path', '')}"
            start, end = (check.get("file_line_range") or [0, 0])[:2]
            findings.append(SecurityFinding(
                check_id=check["check_id"],
                check_name=check.get("check_name", ""),
                resource=check.get("resource", "?"),
                file_path=file_path.lstrip("/"),
                lines=(start, end),
                guideline=check.get("guideline") or "",
            ))
    return ScanReport("Checkov", findings, passed, version)


def load_trivy(path: str) -> Optional[ScanReport]:
    """`trivy config --format json`: Results[].Misconfigurations[], one result per scanned file."""
    data = _read_json(path)
    if data is None:
        return None
    findings = []
    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        file_path = f"{terraform_dir()}/{target}" if target not in ("", ".") else terraform_dir()
        for item in result.get("Misconfigurations") or []:
            if item.get("Status", "FAIL") != "FAIL":
                continue
            cause = item.get("CauseMetadata") or {}
            findings.append(SecurityFinding(
                check_id=item.get("ID") or item.get("AVDID") or "?",
                check_name=" ".join((item.get("Title") or "").split())[:120],
                resource=cause.get("Resource") or "?",
                file_path=file_path,
                lines=(cause.get("StartLine") or 0, cause.get("EndLine") or 0),
                guideline=item.get("PrimaryURL") or "",
                tool="Trivy",
                severity=(item.get("Severity") or "").lower(),
            ))
    return ScanReport("Trivy", _unique(findings), None, (data.get("Trivy") or {}).get("Version", ""))


SEARCH_KEY = re.compile(r"^([A-Za-z0-9_]+)\[([^\]]+)\]")


def load_kics(path: str) -> Optional[ScanReport]:
    """`kics scan --report-formats json`: queries[] (one per rule) with the files[] it matched."""
    data = _read_json(path)
    if data is None:
        return None
    findings = []
    for query in data.get("queries") or []:
        query_id = query.get("query_id") or ""
        check_id = f"KICS-{query_id.split('-')[0]}" if query_id else "KICS-?"
        for match in query.get("files") or []:
            # search_key looks like "aws_security_group[bastion].ingress.cidr_blocks"
            key = SEARCH_KEY.match(match.get("search_key") or "")
            resource = (f"{key.group(1)}.{key.group(2)}" if key
                        else f"{match.get('resource_type', '?')}.{match.get('resource_name', '?')}")
            line = match.get("line") or 0
            findings.append(SecurityFinding(
                check_id=check_id,
                check_name=query.get("query_name", ""),
                resource=resource,
                file_path=f"{terraform_dir()}/{os.path.basename(match.get('file_name') or '')}",
                lines=(line, line),
                guideline=query.get("query_url") or "",
                tool="KICS",
                severity=(query.get("severity") or "").lower(),
            ))
    return ScanReport("KICS", _unique(findings), None, data.get("kics_version", ""))


@dataclass
class Scanner:
    label: str
    results_env: str  # environment variable naming its JSON file
    default_results: str
    load: Callable[[str], Optional[ScanReport]]


SCANNERS: Dict[str, Scanner] = {
    "checkov": Scanner("Checkov", "CHECKOV_RESULTS", "checkov.json", load_checkov),
    "trivy": Scanner("Trivy", "TRIVY_RESULTS", "trivy.json", load_trivy),
    "kics": Scanner("KICS", "KICS_RESULTS", "kics/results.json", load_kics),
}
