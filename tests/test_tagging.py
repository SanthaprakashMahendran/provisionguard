import importlib.util
import unittest

from provisionguard.plan_parser import ResourceChange
from provisionguard.rightsizing import load_policy
from provisionguard.config import policy_path
from provisionguard.tagging import check_tags, tagging_section

POLICY = {"required_tags": ["owner", "cost-center", "environment"],
          "allowed_values": {"environment": ["dev", "staging", "prod"]}}
COMMON = {"environment": "dev", "owner": "platform-team", "cost-center": "platform-eng"}
DEFAULTS = {"managed-by": "terraform", "project": "demo"}


def resource(address, tags=None, action="create", taggable=True):
    rtype, name = address.split(".")[0], address.split(".")[1].split("[")[0]
    after = {"tags_all": {**DEFAULTS, **tags}} if taggable else {"route_table_id": "x"}
    actions = {"create": ["create"], "update": ["update"], "delete": ["delete"]}[action]
    return ResourceChange(address, rtype, name, actions, None, None if action == "delete" else after, {})


def plan_with_refs(refs):
    return {"configuration": {"root_module": {"resources": [
        {"address": a, "expressions": {"tags": {"references": r}}} for a, r in refs.items()]}}}


DEMO_PLAN = plan_with_refs({
    "aws_vpc.main": ["local.common_tags", "var.project"],
    "aws_instance.this": ["local.common_tags", "var.project", "each.key"],
    "aws_db_instance.main": ["var.project"],
})


def demo_changes():
    return [
        resource("aws_vpc.main", COMMON),
        resource('aws_instance.this["app-1"]', COMMON),
        resource('aws_instance.this["worker"]', COMMON),
        resource("aws_db_instance.main", {"environment": "dev", "owner": "platform-team"}),
        resource("aws_route_table_association.public[0]", taggable=False),
    ]


class TaggingTest(unittest.TestCase):
    def test_demo_finds_missing_cost_center_with_suggestion_and_root_cause(self):
        problems = check_tags(DEMO_PLAN, demo_changes(), POLICY)
        self.assertEqual([p.address for p in problems], ["aws_db_instance.main"])
        problem = problems[0]
        self.assertEqual(problem.problems, ["missing `cost-center`"])
        self.assertEqual(problem.suggestions,
                         ['`cost-center = "platform-eng"` (used by all 3 other taggable resources)'])
        self.assertIn("merge(local.common_tags, {...})", problem.hint)

    def test_section_output(self):
        text = tagging_section(DEMO_PLAN, demo_changes(), POLICY)
        print("\n" + text)
        self.assertIn("⚠️ **1 of 4 taggable resources** breaks the tagging policy", text)  # association skipped
        self.assertIn('| `aws_db_instance.main` | missing `cost-center` | `cost-center = "platform-eng"`', text)
        self.assertIn("💡 `aws_db_instance.main`: Most resources build their tags", text)

    def test_all_compliant(self):
        changes = [resource("aws_vpc.main", COMMON), resource("aws_subnet.a", COMMON)]
        self.assertIn("✅ All 2 taggable resources have the required tags", tagging_section({}, changes, POLICY))

    def test_wrong_case_key_and_bad_value(self):
        tags = {"Owner": "me", "cost-center": "x", "environment": "Dev"}
        problems = check_tags({}, [resource("aws_vpc.main", tags), resource("aws_subnet.a", COMMON)], POLICY)
        self.assertEqual(problems[0].problems, [
            "`owner` is written as `Owner` (tag keys are case-sensitive)",
            '`environment = "Dev"` is not one of dev, staging, prod',
        ])

    def test_suggestion_when_neighbours_disagree_or_are_missing(self):
        changes = [
            resource("aws_vpc.main", {"owner": "a", "environment": "dev"}),
            resource("aws_subnet.a", {**COMMON, "cost-center": "team-a"}),
            resource("aws_subnet.b", {**COMMON, "cost-center": "team-a"}),
            resource("aws_subnet.c", {**COMMON, "cost-center": "team-b"}),
        ]
        problem = check_tags({}, changes, POLICY)[0]
        self.assertEqual(problem.suggestions,
                         ['`cost-center = "team-a"` (most common: 2 of 3 resources, check this is right)'])

        alone = check_tags({}, [resource("aws_vpc.main", {"owner": "a", "environment": "dev"})], POLICY)[0]
        self.assertEqual(alone.suggestions, ["`cost-center`: no other resource sets it, please choose a value"])

    def test_deletes_are_ignored_and_no_hint_without_config(self):
        changes = [resource("aws_vpc.main", {}, action="delete"),
                   resource("aws_subnet.a", {"owner": "a", "environment": "dev"}, action="update")]
        problems = check_tags({}, changes, POLICY)
        self.assertEqual([p.address for p in problems], ["aws_subnet.a"])
        self.assertEqual(problems[0].hint, "")

    def test_no_taggable_resources(self):
        text = tagging_section({}, [resource("aws_route_table_association.x", taggable=False)], POLICY)
        self.assertIn("No taggable resources in this change.", text)


@unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not installed")
class PolicyFileTest(unittest.TestCase):
    def test_policy_file(self):
        self.assertEqual(load_policy(policy_path("tagging")), POLICY)


if __name__ == "__main__":
    unittest.main()
