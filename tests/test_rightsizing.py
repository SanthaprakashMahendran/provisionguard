import importlib.util
import unittest

from provisionguard.pricing import Pricer
from provisionguard.rightsizing import environment_of, load_policy, rightsizing_section
from tests.test_cost import REGION, FakeEksClient, FakePricingClient, change

POLICY = {
    "dev": {"max_ec2": "t3.medium", "max_rds": "db.t3.medium", "rds_multi_az": "forbidden"},
    "staging": {"max_ec2": "m5.large", "max_rds": "db.m5.large"},
    "prod": {"rds_multi_az": "required"},
}
PLAN = {"variables": {"aws_region": {"value": REGION}}}


def instance(name, instance_type, tags):
    return change(f'aws_instance.this["{name}"]', "aws_instance", {"instance_type": instance_type, "tags_all": tags})


def node_group(instance_type, desired, tags):
    return change("aws_eks_node_group.main", "aws_eks_node_group", {
        "instance_types": [instance_type], "tags_all": tags,
        "scaling_config": [{"desired_size": desired, "min_size": 1, "max_size": desired + 1}]})


def database(instance_class, multi_az, tags, engine="postgres"):
    return change("aws_db_instance.main", "aws_db_instance", {
        "instance_class": instance_class, "engine": engine, "multi_az": multi_az,
        "allocated_storage": 100, "storage_type": "gp3", "tags_all": tags})


def review(changes):
    return rightsizing_section(PLAN, changes, Pricer(FakePricingClient(), FakeEksClient()), POLICY)


class EnvironmentTagTest(unittest.TestCase):
    def test_reads_environment_or_env_any_case(self):
        self.assertEqual(environment_of(instance("a", "t3.micro", {"environment": "dev"})), "dev")
        self.assertEqual(environment_of(instance("a", "t3.micro", {"Env": "Production"})), "prod")
        self.assertEqual(environment_of(instance("a", "t3.micro", {"ENVIRONMENT": "stg"})), "staging")
        self.assertIsNone(environment_of(instance("a", "t3.micro", {"owner": "me"})))


class RightsizingTest(unittest.TestCase):
    def test_oversized_dev_instance_is_flagged_with_saving(self):
        text = review([instance("worker", "m5.2xlarge", {"environment": "dev"})])
        print("\n" + text)
        # (0.384 - 0.0416) × 730 = $249.95
        self.assertIn('| `aws_instance.this["worker"]` | m5.2xlarge → **t3.medium**<br><sub>dev: max t3.medium</sub> | saves $249.95 |', text)
        self.assertIn("possible saving **$249.95/month**", text)

    def test_instances_within_limit_pass(self):
        text = review([instance("app", "t3.medium", {"environment": "dev"}),
                       instance("bastion", "t3.micro", {"environment": "dev"})])
        self.assertIn("✅ All checked resources", text)

    def test_prod_has_no_size_cap(self):
        self.assertIn("✅", review([instance("x", "m5.2xlarge", {"environment": "prod"})]))

    def test_node_group_saving_multiplies_by_node_count(self):
        text = review([node_group("t3.large", 2, {"environment": "dev"})])
        # (0.0832 - 0.0416) × 730 × 2 = $60.74
        self.assertIn("| 2 × t3.large → **2 × t3.medium**<br><sub>dev: max t3.medium</sub> | saves $60.74 |", text)

    def test_missing_tag_and_unknown_environment_are_reported(self):
        text = review([instance("a", "m5.2xlarge", {}), instance("b", "m5.2xlarge", {"environment": "qa"})])
        self.assertIn('No `environment` tag, so not checked: `aws_instance.this["a"]`', text)
        self.assertIn("No policy for environment: `qa`", text)

    def test_full_demo_plan(self):
        dev = {"environment": "dev"}
        text = review([instance("worker", "m5.2xlarge", dev), instance("app-1", "t3.medium", dev),
                       instance("bastion", "t3.micro", dev), node_group("t3.large", 2, dev),
                       database("db.m5.large", False, dev)])
        print("\n" + text)
        # $249.95 worker + $60.74 nodes + $77.38 database
        self.assertIn("**3 policy findings** · possible saving **$388.07/month**", text)


class DatabaseTest(unittest.TestCase):
    def test_oversized_dev_database(self):
        text = review([database("db.m5.large", False, {"environment": "dev"})])
        # (0.178 - 0.072) × 730 = $77.38
        self.assertIn("| db.m5.large → **db.t3.medium**<br><sub>dev: max db.t3.medium</sub> | saves $77.38 |", text)

    def test_multi_az_in_dev_is_flagged(self):
        text = review([database("db.t3.medium", True, {"environment": "dev"})])
        # (0.144 - 0.072) × 730 + 100 GB × (0.23 - 0.115) = $64.06
        self.assertIn("| Multi-AZ → **Single-AZ**<br><sub>dev: Multi-AZ not needed</sub> | saves $64.06 |", text)

    def test_oversized_and_multi_az_savings_do_not_overlap(self):
        text = review([database("db.m5.large", True, {"environment": "dev"})])
        # Size first at Multi-AZ prices: (0.356 - 0.144) × 730 = $154.76
        # Then Multi-AZ on the suggested db.t3.medium: $64.06
        self.assertIn("saves $154.76", text)
        self.assertIn("saves $64.06", text)
        # Together they equal the full drop from db.m5.large Multi-AZ ($282.88) to db.t3.medium Single-AZ ($64.06).
        self.assertIn("possible saving **$218.82/month**", text)

    def test_prod_requires_multi_az_and_shows_extra_cost(self):
        text = review([database("db.m5.large", False, {"environment": "prod"})])
        # (0.356 - 0.178) × 730 + 100 GB × (0.23 - 0.115) = $141.44
        self.assertIn("| Single-AZ → **Multi-AZ**<br><sub>prod: Multi-AZ required</sub> | adds $141.44 |", text)
        self.assertIn("required fixes add **$141.44/month**", text)
        self.assertNotIn("possible saving", text)

    def test_prod_multi_az_passes(self):
        self.assertIn("✅", review([database("db.m5.large", True, {"environment": "prod"})]))

    def test_unpriceable_engine_still_gets_multi_az_rule(self):
        text = review([database("db.m5.large", False, {"environment": "prod"}, engine="oracle-ee")])
        self.assertIn("| Single-AZ → **Multi-AZ**<br><sub>prod: Multi-AZ required</sub> | n/a |", text)


@unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not installed")
class PolicyFileTest(unittest.TestCase):
    def test_policy_file_matches_agreed_defaults(self):
        self.assertEqual(load_policy(), POLICY)


if __name__ == "__main__":
    unittest.main()
