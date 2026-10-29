"""The single place the reviewer talks to an AI model, so the provider can change without touching the checks.

AI_PROVIDER selects the backend:
  claude-code  Claude Code CLI, authenticated with CLAUDE_CODE_OAUTH_TOKEN (a Claude Pro/Max subscription)
  none         AI disabled; sections fall back to their plain output
Bedrock or Azure OpenAI slot in here later as further providers.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

TIMEOUT_SECONDS = 300


class AIError(Exception):
    pass


def ask_json(system: str, prompt: str, schema: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Ask the configured model for a JSON object matching `schema`. Returns None if AI is off or fails."""
    provider = os.environ.get("AI_PROVIDER", "none").strip().lower()
    if provider == "none":
        return None
    try:
        if provider == "claude-code":
            return _claude_code(system, prompt, schema)
        raise AIError(f"unknown AI_PROVIDER {provider!r}")
    except (AIError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"::warning::AI request failed ({provider}): {exc}", file=sys.stderr)
        return None


def _claude_code(system: str, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    cmd = [
        os.environ.get("CLAUDE_BIN", "claude"),
        "--print",
        "--output-format", "json",
        "--tools", "",  # no file, shell or web access: Claude only reads what we send
        "--no-session-persistence",
        "--system-prompt", system,
        "--json-schema", json.dumps(schema),
    ]
    if os.environ.get("AI_MODEL"):
        cmd += ["--model", os.environ["AI_MODEL"]]

    # Run in an empty directory so Claude Code picks up no project files or CLAUDE.md.
    with tempfile.TemporaryDirectory() as workdir:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, cwd=workdir
        )
    if proc.returncode != 0:
        raise AIError(f"claude exited with {proc.returncode}: {(proc.stderr or proc.stdout)[-500:]}")

    envelope = json.loads(proc.stdout)
    if envelope.get("is_error"):
        raise AIError(str(envelope.get("result"))[:500])
    structured = envelope.get("structured_output")
    if isinstance(structured, dict):
        return structured
    return _json_from_text(envelope.get("result") or "")


def _json_from_text(text: str) -> Dict[str, Any]:
    """Accept a bare JSON object or one wrapped in a ```json fence."""
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    data = json.loads(fenced.group(1) if fenced else text)
    if not isinstance(data, dict):
        raise AIError("model reply was not a JSON object")
    return data
