import unittest

from provisionguard.aws import AwsClients
from provisionguard.existing import dependents, existing_section, find_clashes, find_impacts
from provisionguard.plan_parser import ResourceChange

PLAN_CONFIG = {"configuration": {"root_module": {"resources": [
    {"address": "aws_iam_role.eks_node", "expressions": {"name": {"references": ["var.project"]}}},
    {"address": "aws_iam_role_policy_attachment.eks_node",
     "expressions": {"role": {"references": ["aws_iam_role.eks_node.name", "aws_iam_role.eks_node"]},
                     "policy_arn": {"references": ["each.value"]}}},
    {"address": "aws_eks_node_group.main",
     "expressions": {"node_role_arn": {"references": ["aws_iam_role.eks_node.arn", "aws_iam_role.eks_node"]},
                     "scaling_config": [{"desired_size": {"constant_value": 2}}]},
     "depends_on": ["aws_iam_role_policy_attachment.eks_node"]},
    {"address": "aws_security_group.app", "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
]}}}


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Paginator:
    def __init__(self, items_by_key):
        self.items_by_key = items_by_key

    def paginate(self, **_):
        return iter([self.items_by_key])


class FakeIam:
    def __init__(self, roles=("provisionguard-demo-eks-node",), policies=0, profiles=0, broken=False):
        self.roles, self.policies, self.profiles, self.broken = set(roles), policies, profiles, broken

    def get_role(self, RoleName):
        if self.broken:
            raise ClientError("AccessDenied")
        if RoleName not in self.roles:
            raise ClientError("NoSuchEntity")
        return {"Role": {"RoleName": RoleName, "RoleLastUsed": {}}}

    def get_paginator(self, operation):
        if operation == "list_attached_role_policies":
            return Paginator({"AttachedPolicies": [{}] * self.policies})
        return Paginator({"InstanceProfiles": [{}] * self.profiles})


class FakeRds:
    def describe_db_instances(self, DBInstanceIdentifier):
        raise ClientError("DBInstanceNotFound")

    def describe_db_subnet_groups(self, DBSubnetGroupName):
        raise ClientError("DBSubnetGroupNotFoundFault")


class FakeEks:
    def describe_cluster(self, name):
        raise ClientError("ResourceNotFoundException")


class FakeS3:
    def __init__(self, taken_elsewhere=()):
        self.taken_elsewhere = set(taken_elsewhere)

    def head_bucket(self, Bucket):
        raise ClientError("403" if Bucket in self.taken_elsewhere else "404")


class FakeEc2:
    def __init__(self, name_tags=(), interfaces=()):
        self.name_tags, self.interfaces = set(name_tags), list(interfaces)

    def get_paginator(self, operation):
        tagged = [{"Tags": [{"Key": "Name", "Value": n}]} for n in self.name_tags]
        return {
            "describe_vpcs": Paginator({"Vpcs": tagged}),
            "describe_subnets": Paginator({"Subnets": []}),
            "describe_internet_gateways": Paginator({"InternetGateways": []}),
            "describe_route_tables": Paginator({"RouteTables": []}),
            "describe_nat_gateways": Paginator({"NatGateways": []}),
            "describe_instances": Paginator({"Reservations": [{"Instances": []}]}),
            "describe_network_interfaces": Paginator({"NetworkInterfaces": self.interfaces}),
        }[operation]


def aws(iam=None, ec2=None, s3=None):
    return AwsClients("us-east-1", {"iam": iam or FakeIam(), "rds": FakeRds(), "eks": FakeEks(),
                                    "s3": s3 or FakeS3(), "ec2": ec2 or FakeEc2()})


def rc(address, actions, before=None, after=None, replace_paths=None, reason="", unknown=None):
    rtype, name = address.split(".")[0], address.split(".")[1].split("[")[0]
    return ResourceChange(address, rtype, name, actions, before, after, unknown or {}, replace_paths or [], reason)


def demo_creates():
    """What today's demo plan creates (no state yet)."""
    return [
        rc("aws_iam_role.eks_node", ["create"], after={"name": "provisionguard-demo-eks-node"}),
        rc("aws_iam_role.eks_cluster", ["create"], after={"name": "provisionguard-demo-eks-cluster"}),
        rc("aws_db_instance.main", ["create"], after={"identifier": "provisionguard-demo-db"}),
        rc("aws_eks_cluster.main", ["create"], after={"name": "provisionguard-demo-eks"}),
        rc("aws_vpc.main", ["create"], after={"tags": {"Name": "provisionguard-demo-vpc"}}),
    ]


def rename_role():
    return rc("aws_iam_role.eks_node", ["delete", "create"],
              before={"name": "provisionguard-demo-eks-node", "arn": "arn:aws:iam::1:role/x"},
              after={"name": "provisionguard-demo-eks-nodes"}, replace_paths=[["name"]])


class NameClashTest(unittest.TestCase):
    def test_handmade_role_is_caught_today(self):
        clashes, errors = find_clashes(demo_creates(), aws())
        self.assertEqual([(c.address, c.fails) for c in clashes], [("aws_iam_role.eks_node", True)])
        self.assertEqual(errors, [])

    def test_section_for_todays_demo(self):
        text = existing_section(PLAN_CONFIG, demo_creates(), aws())
        print("\n" + text)
        self.assertIn("🔴 **1 name clash**", text)
        self.assertIn("| `aws_iam_role.eks_node` | provisionguard-demo-eks-node | 🔴 apply will fail", text)
        self.assertIn("✅ No existing resources are changed or destroyed.", text)

    def test_duplicate_by_name_tag(self):
        clashes, _ = find_clashes(demo_creates(), aws(ec2=FakeEc2(name_tags=["provisionguard-demo-vpc"])))
        self.assertIn(("aws_vpc.main", False), [(c.address, c.fails) for c in clashes])

    def test_bucket_owned_by_another_account(self):
        bucket = rc("aws_s3_bucket.logs", ["create"], after={"bucket": "logs"})
        clashes, _ = find_clashes([bucket], aws(iam=FakeIam(roles=()), s3=FakeS3(taken_elsewhere=["logs"])))
        self.assertEqual([c.address for c in clashes], ["aws_s3_bucket.logs"])

    def test_refused_lookup_is_reported_not_fatal(self):
        clashes, errors = find_clashes(demo_creates(), aws(iam=FakeIam(broken=True)))
        self.assertEqual(errors, ["aws_iam_role.eks_node", "aws_iam_role.eks_cluster"])
        self.assertEqual(clashes, [])

    def test_unknown_names_are_skipped(self):
        unknown = rc("aws_iam_role.x", ["create"], after={"name": None}, unknown={"name": True})
        self.assertEqual(find_clashes([unknown], aws()), ([], []))


class ImpactTest(unittest.TestCase):
    def test_dependents_from_configuration(self):
        users = dependents(PLAN_CONFIG)
        self.assertEqual(users["aws_iam_role.eks_node"],
                         ["aws_eks_node_group.main", "aws_iam_role_policy_attachment.eks_node"])
        self.assertEqual(users["aws_iam_role_policy_attachment.eks_node"], ["aws_eks_node_group.main"])
        self.assertEqual(users["aws_vpc.main"], ["aws_security_group.app"])

    def test_role_rename_is_a_destructive_replace(self):
        impact = find_impacts(PLAN_CONFIG, [rename_role()], aws(iam=FakeIam(policies=1)))[0]
        self.assertEqual((impact.action, impact.severity), ("replace", "high"))
        self.assertEqual(impact.why, "`name` can't change in place")
        self.assertIn("anything that trusts or refers to the old role loses access", impact.effects[0])
        self.assertIn("2 resources in this repo depend on it", impact.effects[1])
        self.assertEqual(impact.effects[2:], ["1 policy attached", "0 instance profiles", "last used: never"])

    def test_section_for_rename_demo(self):
        text = existing_section(PLAN_CONFIG, [rename_role()], aws())
        print("\n" + text)
        self.assertIn("✅ No name clashes", text)
        self.assertIn("🔴 **1 existing resource changes**, 1 of them destructive", text)
        self.assertIn("| 🔴 `aws_iam_role.eks_node` | ♻️ replace | `name` can't change in place |", text)

    def test_database_removed_from_code(self):
        delete = rc("aws_db_instance.main", ["delete"], before={"id": "db-1"},
                    reason="delete_because_no_resource_config")
        impact = find_impacts({}, [delete], aws())[0]
        self.assertEqual((impact.action, impact.severity, impact.why), ("delete", "high", "removed from the code"))
        self.assertIn("stored data is lost", impact.effects[0])

    def test_tags_only_update_is_safe(self):
        update = rc("aws_iam_role.eks_node", ["update"], before={"name": "r", "tags": {}},
                    after={"name": "r", "tags": {"owner": "x"}})
        impact = find_impacts({}, [update], aws())[0]
        self.assertEqual((impact.severity, impact.why, impact.effects), ("low", "tags only", ["safe, no downtime"]))

    def test_security_group_rule_change_shows_what_is_attached(self):
        update = rc("aws_security_group.app", ["update"], before={"id": "sg-1", "ingress": [1]},
                    after={"id": "sg-1", "ingress": [2]})
        interfaces = [{"InterfaceType": "interface"}, {"InterfaceType": "interface"}, {"InterfaceType": "lambda"}]
        impact = find_impacts({}, [update], aws(ec2=FakeEc2(interfaces=interfaces)))[0]
        self.assertEqual(impact.why, "changes `ingress`")
        self.assertEqual(impact.effects, ["3 network interfaces attached in AWS (2 interface, 1 lambda)"])

    def test_creates_and_no_ops_are_not_impacts(self):
        noop = rc("aws_vpc.main", ["no-op"], before={"id": "vpc-1"}, after={"id": "vpc-1"})
        self.assertEqual(find_impacts({}, demo_creates() + [noop], aws()), [])

    def test_failed_attachment_lookup_keeps_the_row(self):
        impact = find_impacts({}, [rename_role()], aws(iam=FakeIam(broken=True)))[0]
        self.assertIn("couldn't check what's attached in AWS", impact.effects)


if __name__ == "__main__":
    unittest.main()
