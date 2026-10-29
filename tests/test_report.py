import json
import os
import tempfile
import unittest
from unittest import mock

from provisionguard import main
from provisionguard.cost import cost_review
from provisionguard.existing import existing_review
from provisionguard.pricing import Pricer
from provisionguard.quotas import quota_review
from provisionguard.report import FAIL, INFO, OK, WARN, Section, assemble, scorecard, verdict
from provisionguard.rightsizing import rightsizing_review
from provisionguard.security import security_review
from provisionguard.tagging import tagging_review
from tests import test_existing, test_quotas, test_rightsizing, test_security, test_tagging
from tests.test_cost import FakeEksClient, FakePricingClient


class VerdictTest(unittest.TestCase):
    def test_blockers_win(self):
        sections = [Section("A", "x", FAIL, "s", ["2 high-risk security issues"]),
                    Section("B", "x", WARN, "s", ["1 resource missing required tags"])]
        self.assertEqual(verdict(sections), "> [!CAUTION]\n> **Not ready to merge:** 2 high-risk security issues")

    def test_warnings_without_blockers(self):
        sections = [Section("A", "x", OK, "s"), Section("B", "x", WARN, "s", ["a"]), Section("C", "x", WARN, "s", ["b"])]
        self.assertEqual(verdict(sections), "> [!WARNING]\n> **Review before merging:** a · b")

    def test_all_clear(self):
        self.assertEqual(verdict([Section("A", "x", OK, "s"), Section("B", "x", INFO)]),
                         "> [!TIP]\n> **Looks good:** no blocking issues found.")

    def test_scorecard_skips_sections_without_a_score(self):
        card = scorecard([Section("🔒 Security", "x", OK, "✅ fine"), Section("📋 Plan details", "x")])
        self.assertEqual(card, "| Check | Result |\n|---|---|\n| 🔒 Security | ✅ fine |")

    def test_assemble_layout(self):
        sections = [Section("🔒 Security", "body", OK, "✅ fine"),
                    Section("🗺️ Architecture", "", lead="🗺️ **This change:** builds a VPC")]
        text = assemble(sections, "98cfc5d1234567", "23 Oct 2026, 14:05 UTC")
        self.assertTrue(text.startswith("## 🛡️ ProvisionGuard review\n\n<sub>Commit 98cfc5d · updated 23 Oct 2026"))
        self.assertLess(text.index("[!TIP]"), text.index("This change"))
        self.assertLess(text.index("This change"), text.index("| Check | Result |"))
        self.assertNotIn("### 🗺️ Architecture", text)  # empty body: section left out
        self.assertNotIn("<sub>`", text)  # no code boxes inside small text
        # A line before each section and before the footer, each with blank lines around it
        # (without them, Markdown would turn the line into a heading underline).
        self.assertIn("\n\n---\n\n### 🔒 Security\n\n", text)
        self.assertEqual(text.count("\n\n---\n\n"), 2)


class StatusTest(unittest.TestCase):
    """Each check reports a status and one scorecard line from its own findings."""

    def test_security(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=True):
            path = os.path.join(d, "checkov.json")
            with open(path, "w") as f:
                json.dump(test_security.REPORT, f)
            section = security_review({}, [], path, assess=lambda *a: test_security.ASSESSMENT)
            self.assertEqual((section.status, section.score), (FAIL, "🔴 1 high · 🟡 1 low"))
            self.assertEqual(section.reasons, ["1 high-risk security issue"])
            unassessed = security_review({}, [], path, assess=lambda *a: None)
            self.assertEqual((unassessed.status, unassessed.score), (WARN, "⚠️ 3 findings, not assessed"))

    def test_existing_infrastructure(self):
        section = existing_review(test_existing.PLAN_CONFIG, test_existing.demo_creates(), test_existing.aws())
        self.assertEqual((section.status, section.score), (FAIL, "🔴 1 name clash"))
        self.assertEqual(section.reasons, ["1 name clash that fails on apply"])

    def test_quotas(self):
        ec2 = test_quotas.FakeEc2(instances=[test_quotas.running("m5.2xlarge", 4), test_quotas.running("c5.xlarge", 2),
                                             test_quotas.running("m5.large", 1)], vpcs=4)
        section = quota_review(test_quotas.PLAN, test_quotas.demo_changes(), test_quotas.aws(ec2=ec2))
        self.assertEqual((section.status, section.score), (FAIL, "🔴 1 will be exceeded"))
        ok = quota_review(test_quotas.PLAN, test_quotas.demo_changes(), test_quotas.aws())
        self.assertEqual((ok.status, ok.score), (OK, "✅ 5 quotas under 80%"))

    def test_rightsizing(self):
        dev = {"environment": "dev"}
        changes = [test_rightsizing.instance("worker", "m5.2xlarge", dev),
                   test_rightsizing.node_group("t3.large", 2, dev), test_rightsizing.database("db.m5.large", False, dev)]
        section = rightsizing_review(test_rightsizing.PLAN, changes, Pricer(FakePricingClient(), FakeEksClient()),
                                     test_rightsizing.POLICY)
        self.assertEqual((section.status, section.score), (WARN, "⚠️ 3 over policy · save $388.07/month"))
        self.assertNotIn("`", section.body.split("<sub>")[-1])  # footer has no code boxes

    def test_tagging(self):
        section = tagging_review(test_tagging.DEMO_PLAN, test_tagging.demo_changes(), test_tagging.POLICY)
        self.assertEqual((section.status, section.score), (WARN, "⚠️ 1 of 4 resources breaks the policy"))

    def test_cost_is_information_only(self):
        section = cost_review({"variables": {"aws_region": {"value": "us-east-1"}}},
                              [test_tagging.resource("aws_vpc.main", test_tagging.COMMON)])
        self.assertEqual((section.status, section.score), (INFO, "$0.00/month · 1 to create"))


class BuildReportTest(unittest.TestCase):
    def test_a_crashing_check_becomes_a_warning_row(self):
        def broken(plan, changes):
            raise RuntimeError("boom")

        reviews = [("🔒 Security", lambda p, c: Section("🔒 Security", "fine", OK, "✅ fine")),
                   ("📊 Service quotas", broken)]
        with mock.patch.object(main, "REVIEWS", reviews), mock.patch.dict(os.environ, {"HEAD_SHA": "abcdef123"}):
            text = main.build_report({"resource_changes": []})
        print("\n" + text)
        self.assertIn("> [!WARNING]\n> **Review before merging:** the service quotas check failed", text)
        self.assertIn("| 📊 Service quotas | ⚠️ check failed |", text)
        self.assertIn("<sub>Commit abcdef1 · updated", text)


if __name__ == "__main__":
    unittest.main()
