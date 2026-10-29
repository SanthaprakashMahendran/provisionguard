"""Settings for a review: the Terraform folder, provisionguard.yaml (optional) and which policies apply.

The action asks this module which scanners to run:  python -m provisionguard.config scanners
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

KNOWN_SCANNERS = ("checkov", "trivy", "kics")
DEFAULT_SCANNERS = ["checkov"]
BUNDLED_POLICIES = Path(__file__).resolve().parent / "policies"


def terraform_dir() -> str:
    """The folder being reviewed, relative to the repository root (the action's terraform-dir input)."""
    return os.environ.get("TF_DIR", "infra").strip().rstrip("/") or "."


def config_path() -> Path:
    return Path(os.environ.get("PROVISIONGUARD_CONFIG", "provisionguard.yaml"))


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or config_path()
    if not path.exists():
        return {}
    import yaml

    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def policy_path(name: str) -> Path:
    """The team's policy file if they have one, else ProvisionGuard's default.

    Looks at policies.<name> in provisionguard.yaml, then policy/<name>.yaml in the repository.
    """
    configured = (load_config().get("policies") or {}).get(name)
    if configured:
        return Path(configured)
    local = Path("policy") / f"{name}.yaml"
    return local if local.exists() else BUNDLED_POLICIES / f"{name}.yaml"


def policy_label(name: str) -> str:
    """How a section footer names the policy it used."""
    path = policy_path(name)
    return "ProvisionGuard's default policy" if path.parent == BUNDLED_POLICIES else path.as_posix()


def selected_scanners(config: Optional[Dict[str, Any]] = None) -> List[str]:
    """Scanners from the action's scanners input, else security.scanners in provisionguard.yaml; Checkov by default.

    Unknown names are dropped with a warning.
    """
    override = os.environ.get("PROVISIONGUARD_SCANNERS", "").strip()
    config = load_config() if config is None and not override else (config or {})
    raw = override or (config.get("security") or {}).get("scanners") or []
    if isinstance(raw, str):
        raw = raw.split(",")
    names: List[str] = []
    for item in raw:
        name = str(item).strip().lower()
        if name in KNOWN_SCANNERS and name not in names:
            names.append(name)
        elif name and name not in KNOWN_SCANNERS:
            print(f"::warning::Unknown scanner '{name}' in provisionguard.yaml; "
                  f"choose from {', '.join(KNOWN_SCANNERS)}", file=sys.stderr)
    return names or list(DEFAULT_SCANNERS)


if __name__ == "__main__":
    if sys.argv[1:] == ["scanners"]:
        print(",".join(selected_scanners()))
    else:
        sys.exit("usage: python -m provisionguard.config scanners")
