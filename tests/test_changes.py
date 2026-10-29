import os
import unittest
from unittest import mock

from provisionguard import changes
from provisionguard.changes import is_relevant, relevant_paths, should_review

PR_ENV = {"PR_NUMBER": "7", "GITHUB_REPOSITORY": "team/infra", "GITHUB_TOKEN": "t",
          "PROVISIONGUARD_CONFIG": "/nonexistent/provisionguard.yaml"}


def api(*pages):
    """Fake GitHub API answers for /pulls/7/files, one tuple per page."""
    answers = [(page, '<https://api.github.com/next>; rel="next"' if i < len(pages) - 1 else "")
               for i, page in enumerate(pages)]
    return mock.patch.object(changes, "_request", side_effect=answers)


class RelevanceTest(unittest.TestCase):
    def test_any_folder_name(self):
        with mock.patch.dict(os.environ, {"TF_DIR": "stacks/prod", "PROVISIONGUARD_CONFIG": "provisionguard.yaml"}):
            paths = relevant_paths()
        self.assertEqual(paths[:3], ["stacks/prod/", "policy/", "provisionguard.yaml"])
        self.assertTrue(is_relevant(["stacks/prod/main.tf"], paths))
        self.assertTrue(is_relevant(["policy/tagging.yaml"], paths))
        self.assertTrue(is_relevant(["provisionguard.yaml"], paths))
        self.assertFalse(is_relevant(["stacks/prod-old/main.tf"], paths))  # similar name, different folder
        self.assertFalse(is_relevant(["README.md", "app/src/main.py"], paths))

    def test_whole_repository(self):
        with mock.patch.dict(os.environ, {"TF_DIR": "."}):
            self.assertTrue(is_relevant(["anything.tf"], relevant_paths()))


class ShouldReviewTest(unittest.TestCase):
    def test_terraform_change_is_reviewed(self):
        env = dict(PR_ENV, TF_DIR="terraform")
        with mock.patch.dict(os.environ, env, clear=True), api([{"filename": "README.md"}],
                                                               [{"filename": "terraform/vpc.tf"}]):
            self.assertTrue(should_review())  # found on the second page

    def test_unrelated_change_is_skipped(self):
        env = dict(PR_ENV, TF_DIR="terraform")
        with mock.patch.dict(os.environ, env, clear=True), api([{"filename": "docs/guide.md"}]), \
                mock.patch("sys.stderr"):
            self.assertFalse(should_review())

    def test_rename_out_of_the_folder_counts(self):
        env = dict(PR_ENV, TF_DIR="terraform")
        moved = {"filename": "archive/vpc.tf", "previous_filename": "terraform/vpc.tf"}
        with mock.patch.dict(os.environ, env, clear=True), api([moved]):
            self.assertTrue(should_review())

    def test_not_a_pull_request_or_switched_off(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(should_review())
        with mock.patch.dict(os.environ, dict(PR_ENV, PROVISIONGUARD_SKIP_UNCHANGED="false"), clear=True), \
                api([{"filename": "docs/guide.md"}]):
            self.assertTrue(should_review())

    def test_api_failure_means_review(self):
        with mock.patch.dict(os.environ, PR_ENV, clear=True), \
                mock.patch.object(changes, "_request", side_effect=OSError("network")), mock.patch("sys.stderr"):
            self.assertTrue(should_review())


if __name__ == "__main__":
    unittest.main()
