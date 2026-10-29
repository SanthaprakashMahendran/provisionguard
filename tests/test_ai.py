import json
import os
import subprocess
import unittest
from unittest import mock

from provisionguard import ai

SCHEMA = {"type": "object"}


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class AskJsonTest(unittest.TestCase):
    def ask(self, run_result, provider="claude-code"):
        with mock.patch.dict(os.environ, {"AI_PROVIDER": provider}), \
                mock.patch("provisionguard.ai.subprocess.run", return_value=run_result) as run:
            return ai.ask_json("system", "prompt", SCHEMA), run

    def test_ai_off_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("provisionguard.ai.subprocess.run") as run:
            self.assertIsNone(ai.ask_json("s", "p", SCHEMA))
        run.assert_not_called()

    def test_structured_output_is_used(self):
        envelope = {"type": "result", "is_error": False, "result": "", "structured_output": {"summary": "ok"}}
        result, run = self.ask(completed(json.dumps(envelope)))
        self.assertEqual(result, {"summary": "ok"})

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")  # every tool disabled
        self.assertNotIn("--bare", cmd)  # --bare would ignore the OAuth token
        self.assertEqual(json.loads(cmd[cmd.index("--json-schema") + 1]), SCHEMA)
        self.assertEqual(run.call_args.kwargs["input"], "prompt")
        self.assertNotEqual(run.call_args.kwargs["cwd"], os.getcwd())  # empty temp dir, not the repo

    def test_fenced_json_in_result_text(self):
        envelope = {"is_error": False, "result": 'Here you go:\n```json\n{"summary": "fenced"}\n```'}
        result, _ = self.ask(completed(json.dumps(envelope)))
        self.assertEqual(result, {"summary": "fenced"})

    def test_failures_return_none(self):
        cases = [
            completed("", returncode=1, stderr="Invalid API key"),
            completed(json.dumps({"is_error": True, "result": "usage limit reached"})),
            completed("not json"),
            completed(json.dumps({"is_error": False, "result": "no json here"})),
        ]
        for case in cases:
            with self.subTest(case=case):
                result, _ = self.ask(case)
                self.assertIsNone(result)

    def test_missing_cli_returns_none(self):
        with mock.patch.dict(os.environ, {"AI_PROVIDER": "claude-code"}), \
                mock.patch("provisionguard.ai.subprocess.run", side_effect=FileNotFoundError("claude")):
            self.assertIsNone(ai.ask_json("s", "p", SCHEMA))

    def test_unknown_provider_returns_none(self):
        result, run = self.ask(completed("{}"), provider="mystery")
        self.assertIsNone(result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
