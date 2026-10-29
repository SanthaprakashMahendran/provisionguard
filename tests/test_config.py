import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provisionguard import main
from provisionguard.config import BUNDLED_POLICIES, policy_label, policy_path, selected_scanners, terraform_dir
from provisionguard.report import FAIL, OK, WARN, Section, overall


class InDirectory:
    """Run a test from a temporary 'repository' directory."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.getcwd()
        os.chdir(self.tmp.name)
        return Path(self.tmp.name)

    def __exit__(self, *exc):
        os.chdir(self.old)
        self.tmp.cleanup()


class SettingsTest(unittest.TestCase):
    def test_terraform_dir(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(terraform_dir(), "infra")
        with mock.patch.dict(os.environ, {"TF_DIR": "terraform/prod/"}):
            self.assertEqual(terraform_dir(), "terraform/prod")

    def test_bundled_policies_by_default(self):
        with InDirectory(), mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(policy_path("tagging"), BUNDLED_POLICIES / "tagging.yaml")
            self.assertEqual(policy_label("tagging"), "ProvisionGuard's default policy")
        self.assertTrue((BUNDLED_POLICIES / "rightsizing.yaml").exists())

    def test_the_teams_own_policy_wins(self):
        with InDirectory() as repo, mock.patch.dict(os.environ, {}, clear=True):
            (repo / "policy").mkdir()
            (repo / "policy" / "tagging.yaml").write_text("required_tags: [owner]\n")
            self.assertEqual(policy_path("tagging"), Path("policy/tagging.yaml"))
            self.assertEqual(policy_label("tagging"), "policy/tagging.yaml")

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not installed")
    def test_policy_path_from_settings_file(self):
        with InDirectory() as repo, mock.patch.dict(os.environ, {}, clear=True):
            (repo / "provisionguard.yaml").write_text("policies:\n  rightsizing: rules/sizes.yaml\n")
            self.assertEqual(policy_path("rightsizing"), Path("rules/sizes.yaml"))

    def test_action_input_overrides_the_file(self):
        with mock.patch.dict(os.environ, {"PROVISIONGUARD_SCANNERS": "trivy, kics"}):
            self.assertEqual(selected_scanners({"security": {"scanners": ["checkov"]}}), ["trivy", "kics"])
        with mock.patch.dict(os.environ, {"PROVISIONGUARD_SCANNERS": ""}):
            self.assertEqual(selected_scanners({"security": {"scanners": ["kics"]}}), ["kics"])


class VerdictOutputTest(unittest.TestCase):
    def test_overall(self):
        self.assertEqual(overall([Section("a", "x", FAIL), Section("b", "x", WARN)]), "caution")
        self.assertEqual(overall([Section("a", "x", OK), Section("b", "x", WARN)]), "warning")
        self.assertEqual(overall([Section("a", "x", OK)]), "ok")

    def test_main_writes_the_verdict_for_the_action(self):
        reviews = [("🔒 Security", lambda p, c: Section("🔒 Security", "x", FAIL, "🔴", ["1 high"]))]
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "github_output")
            with mock.patch.object(main, "REVIEWS", reviews), \
                    mock.patch.dict(os.environ, {"GITHUB_OUTPUT": out}), \
                    mock.patch("sys.argv", ["provisionguard", "--plan", "tests/fixtures/sample_plan.json", "--dry-run"]), \
                    mock.patch("builtins.print"):
                self.assertEqual(main.main(), 0)
            self.assertEqual(open(out).read(), "verdict=caution\n")


if __name__ == "__main__":
    unittest.main()
