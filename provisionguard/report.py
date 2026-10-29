"""Assemble the PR comment: verdict, scorecard, then each check's section in a fixed order.

Each check returns a Section (its status, a one-line score and its body). This module alone decides the layout,
so every section looks the same and the verdict is computed by rules from the statuses, never by the AI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

FAIL, WARN, OK, INFO = "fail", "warn", "ok", "info"


def count(n: int, singular: str, plural: Optional[str] = None) -> str:
    """'1 name clash', '2 name clashes': readable counts instead of 'name clash(es)'."""
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


@dataclass
class Section:
    title: str  # e.g. "🔒 Security"
    body: str  # Markdown, without the heading
    status: str = INFO  # FAIL blocks merging, WARN needs a look, OK passed, INFO is information only
    score: str = ""  # one line for the scorecard; empty means no scorecard row
    reasons: List[str] = field(default_factory=list)  # short phrases the verdict quotes for FAIL or WARN
    lead: str = ""  # optional sentence shown under the verdict (e.g. what the change builds)

    def markdown(self) -> str:
        return f"### {self.title}\n\n{self.body}"


def overall(sections: List[Section]) -> str:
    """The verdict as one word for automation: "caution", "warning" or "ok"."""
    if any(s.status == FAIL for s in sections):
        return "caution"
    return "warning" if any(s.status == WARN for s in sections) else "ok"


def verdict(sections: List[Section]) -> str:
    """A GitHub alert box: red when anything blocks merging, yellow when something needs a look, green otherwise."""
    blockers = [r for s in sections if s.status == FAIL for r in s.reasons]
    warnings = [r for s in sections if s.status == WARN for r in s.reasons]
    if blockers:
        return "> [!CAUTION]\n> **Not ready to merge:** " + " · ".join(blockers)
    if warnings:
        return "> [!WARNING]\n> **Review before merging:** " + " · ".join(warnings)
    return "> [!TIP]\n> **Looks good:** no blocking issues found."


def scorecard(sections: List[Section]) -> str:
    rows = [f"| {s.title} | {s.score} |" for s in sections if s.score]
    return "| Check | Result |\n|---|---|\n" + "\n".join(rows) if rows else ""


def assemble(sections: List[Section], commit: Optional[str], updated: str) -> str:
    reviewed = f"Commit {commit[:7]} · " if commit else ""
    parts = ["## 🛡️ ProvisionGuard review", f"<sub>{reviewed}updated {updated}</sub>", verdict(sections)]
    parts += [s.lead for s in sections if s.lead]
    card = scorecard(sections)
    if card:
        parts.append(card)
    for section in sections:
        if section.body:
            parts += ["---", section.markdown()]  # a full-width line before each section
    parts += ["---", "<sub>ProvisionGuard reviews terraform plan output. Costs are list-price estimates; "
                     "parts marked as written by Claude can be wrong.</sub>"]
    return "\n\n".join(parts)
