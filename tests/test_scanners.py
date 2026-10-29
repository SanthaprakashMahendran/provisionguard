import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provisionguard.config import selected_scanners
from provisionguard.report import FAIL, OK, WARN
from provisionguard.scanners import load_kics, load_trivy
from provisionguard.security import security_review
from tests.test_security import ASSESSMENT, REPORT


def misconfig(check_id, title, severity, resource, start, end):
    return {"ID": check_id, "Title": title, "Severity": severity, "Status": "FAIL",
            "PrimaryURL": f"https://avd.aquasec.com/misconfig/{check_id.lower()}",
            "CauseMetadata": {"Resource": resource, "Provider": "AWS", "StartLine": start, "EndLine": end}}


# Shaped like real `trivy config --format json` output: one result per file, "." has none,
# and some checks repeat on the same resource.
TRIVY = {
    "SchemaVersion": 2, "Trivy": {"Version": "0.76.1"},
    "Results": [
        {"Target": ".", "Class": "config", "Type": "terraform"},
        {"Target": "security_groups.tf", "Class": "config", "Type": "terraform", "Misconfigurations": [
            misconfig("AWS-0107", "Security groups should not allow unrestricted ingress to SSH or RDP from any IP "
                      "address.", "HIGH", "aws_security_group.bastion", 9, 13)]},
        {"Target": "eks.tf", "Class": "config", "Type": "terraform", "Misconfigurations": [
            misconfig("AWS-0038", "EKS Clusters should have cluster control plane logging turned on", "MEDIUM",
                      "aws_eks_cluster.main", 21, 35),
            misconfig("AWS-0038", "EKS Clusters should have cluster control plane logging turned on", "MEDIUM",
                      "aws_eks_cluster.main", 21, 35)]},
    ],
}

# Shaped like KICS's documented results.json.
KICS = {
    "kics_version": "v2.2.0",
    "queries": [{
        "query_name": "Security Group With Unrestricted Access To SSH",
        "query_id": "65905cec-d691-4320-b320-2000436cb696",
        "query_url": "https://docs.kics.io/latest/queries/terraform-queries/aws/65905cec",
        "severity": "HIGH", "platform": "Terraform",
        "files": [{"file_name": "../../path/security_groups.tf", "line": 12,
                   "resource_type": "aws_security_group", "resource_name": "provisionguard-demo-bastion",
                   "search_key": "aws_security_group[bastion].ingress.cidr_blocks"}],
    }],
}


class ConfigTest(unittest.TestCase):
    def test_default_is_checkov(self):
        self.assertEqual(selected_scanners({}), ["checkov"])
        self.assertEqual(selected_scanners({"security": {}}), ["checkov"])

    def test_list_string_unknown_and_repeats(self):
        self.assertEqual(selected_scanners({"security": {"scanners": ["Checkov", "trivy", "trivy"]}}),
                         ["checkov", "trivy"])
        self.assertEqual(selected_scanners({"security": {"scanners": "kics, checkov"}}), ["kics", "checkov"])
        self.assertEqual(selected_scanners({"security": {"scanners": ["tfsec"]}}), ["checkov"])  # unknown → default

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not installed")
    def test_file_and_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "provisionguard.yaml")
            path.write_text("security:\n  scanners: [checkov, trivy]\n")
            env = dict(os.environ, PROVISIONGUARD_CONFIG=str(path))
            out = subprocess.run([sys.executable, "-m", "provisionguard.config", "scanners"],
                                 capture_output=True, text=True, env=env, check=True)
            self.assertEqual(out.stdout.strip(), "checkov,trivy")

    def test_missing_file_means_defaults(self):
        with mock.patch.dict(os.environ, {"PROVISIONGUARD_CONFIG": "/nonexistent/provisionguard.yaml"}):
            self.assertEqual(selected_scanners(), ["checkov"])


class ReaderTest(unittest.TestCase):
    def write(self, data, name):
        path = os.path.join(self.dir.name, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_trivy(self):
        report = load_trivy(self.write(TRIVY, "trivy.json"))
        self.assertEqual((report.tool, report.version, report.passed), ("Trivy", "0.76.1", None))
        self.assertEqual(len(report.findings), 2)  # the repeated AWS-0038 is kept once
        ssh = report.findings[0]
        self.assertEqual((ssh.check_id, ssh.severity, ssh.resource, ssh.file_path, ssh.lines),
                         ("AWS-0107", "high", "aws_security_group.bastion", "infra/security_groups.tf", (9, 13)))

    def test_kics(self):
        report = load_kics(self.write(KICS, "results.json"))
        finding = report.findings[0]
        self.assertEqual((report.tool, report.version), ("KICS", "v2.2.0"))
        # The block label from search_key, not the resource's Name tag
        self.assertEqual((finding.check_id, finding.resource, finding.file_path, finding.lines, finding.severity),
                         ("KICS-65905cec", "aws_security_group.bastion", "infra/security_groups.tf", (12, 12), "high"))

    def test_missing_files(self):
        self.assertIsNone(load_trivy(os.path.join(self.dir.name, "nope.json")))
        self.assertIsNone(load_kics(os.path.join(self.dir.name, "nope.json")))


class MultiScannerReviewTest(ReaderTest):
    def review(self, scanners, assessment):
        env = {"CHECKOV_RESULTS": self.write(REPORT, "checkov.json"),
               "TRIVY_RESULTS": self.write(TRIVY, "trivy.json"),
               "KICS_RESULTS": os.path.join(self.dir.name, "kics-not-run.json")}
        with mock.patch.dict(os.environ, env, clear=True):
            return security_review({}, [], assess=lambda *a: assessment, scanners=scanners)

    def test_checkov_and_trivy(self):
        merged = dict(ASSESSMENT, risks=[
            dict(ASSESSMENT["risks"][1], check_ids=["CKV_AWS_24", "AWS-0107"]),  # same issue, both tools
            dict(ASSESSMENT["risks"][0], check_ids=["CKV_AWS_293", "AWS-0038"]),
        ])
        section = self.review(["checkov", "trivy"], merged)
        print("\n" + section.body)
        self.assertEqual(section.status, FAIL)
        self.assertIn("⚠️ **5 findings** from Checkov and Trivy · **1 high needs attention**", section.body)
        self.assertIn("`CKV_AWS_24` (Checkov), `AWS-0107` (Trivy)", section.body)
        self.assertIn("<details><summary>All 3 Checkov findings</summary>", section.body)
        self.assertIn("<details><summary>All 2 Trivy findings</summary>", section.body)
        self.assertIn("<sub>Checkov 3.2.0 · Trivy 0.76.1 · assessment by Claude", section.body)
        self.assertNotIn("Not covered by the assessment", section.body)  # every finding from both tools covered

    def test_a_scanner_that_did_not_run_is_reported(self):
        clean = {"summary": "Only low risks.", "risks": [],
                 "not_applicable": [{"check_ids": ["CKV_AWS_24", "CKV_AWS_16", "CKV_AWS_293"], "reason": "x"}]}
        section = self.review(["checkov", "kics"], clean)
        self.assertIn("⚠️ KICS did not run, so its findings are missing.", section.body)
        self.assertEqual((section.status, section.reasons), (WARN, ["KICS didn't run"]))

    def test_checkov_only_keeps_its_wording(self):
        section = self.review(["checkov"], ASSESSMENT)
        self.assertIn("⚠️ **3 failed checks** · 40 passed", section.body)
        self.assertNotIn("(Checkov)", section.body)  # one tool: no tool labels needed

    def test_nothing_ran(self):
        with mock.patch.dict(os.environ, {"TRIVY_RESULTS": "/nonexistent.json"}, clear=True):
            section = security_review({}, [], assess=lambda *a: None, scanners=["trivy"])
        self.assertEqual((section.status, section.body),
                         (WARN, "⚠️ Trivy did not run, so no security checks are shown."))

    def test_clean_trivy_run(self):
        empty = self.write({"Trivy": {"Version": "0.76.1"}, "Results": []}, "empty.json")
        with mock.patch.dict(os.environ, {"TRIVY_RESULTS": empty}, clear=True):
            section = security_review({}, [], assess=lambda *a: None, scanners=["trivy"])
        self.assertEqual((section.status, section.score), (OK, "✅ no findings"))


if __name__ == "__main__":
    unittest.main()
