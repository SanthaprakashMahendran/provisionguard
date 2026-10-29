import unittest

from provisionguard.plan_parser import ResourceChange
from provisionguard.quotas import AwsClients, _is_standard, planned_standard_vcpus, quota_limit, quota_section

PLAN = {"variables": {"aws_region": {"value": "us-east-1"}}}
VCPUS = {"t3.micro": 2, "t3.medium": 2, "t3.large": 2, "m5.2xlarge": 8}


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class FakeEc2:
    def __init__(self, instances=(), vpcs=1, igws=1, eips=0):
        self.instances, self.vpcs, self.igws, self.eips = list(instances), vpcs, igws, eips

    def get_paginator(self, operation):
        pages = {
            # Split across two pages to prove pagination is followed.
            "describe_instances": [{"Reservations": [{"Instances": self.instances[:1]}]},
                                   {"Reservations": [{"Instances": self.instances[1:]}]}],
            "describe_vpcs": [{"Vpcs": [{}] * self.vpcs}],
            "describe_internet_gateways": [{"InternetGateways": [{}] * self.igws}],
        }[operation]
        return Paginator(pages)

    def describe_addresses(self, **_):
        return {"Addresses": [{}] * self.eips}

    def describe_instance_types(self, InstanceTypes):
        return {"InstanceTypes": [{"InstanceType": t, "VCpuInfo": {"DefaultVCpus": VCPUS[t]}} for t in InstanceTypes]}


class FakeRds:
    def __init__(self, databases=0):
        self.databases = databases

    def get_paginator(self, operation):
        return Paginator([{"DBInstances": [{}] * self.databases}])


class FakeQuotas:
    DEFAULTS = {"L-1216C47A": 32, "L-F678F1CE": 5, "L-A4707A72": 5, "L-0263D0A3": 5, "L-7B6409FD": 40}

    def __init__(self, applied=None, broken=()):
        self.applied, self.broken = applied or {}, set(broken)

    def get_service_quota(self, ServiceCode, QuotaCode):
        if QuotaCode in self.broken:
            raise ClientError("AccessDeniedException")
        if QuotaCode not in self.applied:
            raise ClientError("NoSuchResourceException")
        return {"Quota": {"Value": self.applied[QuotaCode]}}

    def get_aws_default_service_quota(self, ServiceCode, QuotaCode):
        return {"Quota": {"Value": self.DEFAULTS[QuotaCode]}}


def running(instance_type, cores, threads=2, spot=False):
    instance = {"InstanceType": instance_type, "CpuOptions": {"CoreCount": cores, "ThreadsPerCore": threads}}
    if spot:
        instance["InstanceLifecycle"] = "spot"
    return instance


def aws(ec2=None, rds=None, quotas=None):
    return AwsClients("us-east-1", {"ec2": ec2 or FakeEc2(), "rds": rds or FakeRds(),
                                    "service-quotas": quotas or FakeQuotas()})


def change(address, rtype, after, action="create"):
    return ResourceChange(address, rtype, "x", [action], None, after, {})


def demo_changes():
    """The demo plan: 5 instances (16 vCPU) + a 2-node t3.large group (4 vCPU, up to 6) + VPC, IGW, EIP, RDS."""
    instances = [("bastion", "t3.micro"), ("app-1", "t3.medium"), ("app-2", "t3.medium"),
                 ("app-3", "t3.medium"), ("worker", "m5.2xlarge")]
    changes = [change(f'aws_instance.this["{n}"]', "aws_instance", {"instance_type": t}) for n, t in instances]
    changes.append(change("aws_eks_node_group.main", "aws_eks_node_group", {
        "instance_types": ["t3.large"], "scaling_config": [{"desired_size": 2, "max_size": 3}]}))
    for rtype in ("aws_vpc", "aws_internet_gateway", "aws_eip", "aws_db_instance"):
        changes.append(change(f"{rtype}.main", rtype, {}))
    return changes


class QuotaTest(unittest.TestCase):
    def test_standard_families(self):
        self.assertTrue(_is_standard("m5.2xlarge"))
        self.assertTrue(_is_standard("t3.micro"))
        self.assertFalse(_is_standard("g5.xlarge"))   # GPU: separate quota
        self.assertFalse(_is_standard("inf2.xlarge"))  # Inferentia: separate quota
        self.assertFalse(_is_standard("p4d.24xlarge"))

    def test_planned_vcpus_for_demo(self):
        planned = planned_standard_vcpus(demo_changes(), aws())
        self.assertEqual((planned.expected, planned.worst_case), (20, 22))

    def test_applied_value_wins_over_default(self):
        self.assertEqual(quota_limit(aws(quotas=FakeQuotas({"L-1216C47A": 256})), "ec2", "L-1216C47A"), 256)
        self.assertEqual(quota_limit(aws(), "ec2", "L-1216C47A"), 32)

    def test_empty_account_all_ok(self):
        text = quota_section(PLAN, demo_changes(), aws())
        print("\n" + text)
        self.assertIn("✅ All 5 quotas this change uses stay under 80% of the limit", text)
        self.assertIn("| EC2 on-demand vCPUs (standard families) | 0 | +20 (+2 when scaled out) | **20** | 32 |", text)
        self.assertIn("| VPCs | 1 | +1 | **2** | 5 | ✅ 40% |", text)

    def test_busy_shared_account_fails_on_vcpus(self):
        # 14 vCPU already running (8 + 4 + 2; the spot and GPU instances don't count), 4 VPCs already exist.
        ec2 = FakeEc2(instances=[running("m5.2xlarge", 4), running("c5.xlarge", 2), running("m5.large", 1),
                                 running("m5.4xlarge", 8, spot=True), running("g5.xlarge", 2)], vpcs=4)
        text = quota_section(PLAN, demo_changes(), aws(ec2=ec2))
        print("\n" + text)
        self.assertIn("🔴 **1 quota will be exceeded**", text)
        self.assertIn("| EC2 on-demand vCPUs (standard families) | 14 | +20 (+2 when scaled out) | **34** | 32 | 🔴 will fail on apply |", text)
        self.assertIn("| VPCs | 4 | +1 | **5** | 5 | ⚠️ 100% of limit |", text)

    def test_only_over_when_scaled_out(self):
        ec2 = FakeEc2(instances=[running("m5.2xlarge", 4), running("m5.xlarge", 2)])  # 12 vCPU in use
        text = quota_section(PLAN, demo_changes(), aws(ec2=ec2, quotas=FakeQuotas({"L-1216C47A": 33})))
        # 12 + 20 = 32 of 33 is close; 12 + 22 = 34 would exceed it.
        self.assertIn("⚠️ 97% of limit; ⚠️ over the limit if scaled out", text)

    def test_refused_call_loses_only_that_row(self):
        text = quota_section(PLAN, demo_changes(), aws(quotas=FakeQuotas(broken={"L-0263D0A3"})))
        self.assertIn("⚠️ Couldn't read: Elastic IPs", text)
        self.assertIn("| VPCs |", text)

    def test_refused_vcpu_lookup_loses_only_that_row(self):
        class NoTypes(FakeEc2):
            def describe_instance_types(self, InstanceTypes):
                raise ClientError("UnauthorizedOperation")

        text = quota_section(PLAN, demo_changes(), aws(ec2=NoTypes()))
        self.assertIn("⚠️ Couldn't read: EC2 on-demand vCPUs (standard families)", text)
        self.assertIn("| VPCs |", text)

    def test_untouched_quotas_are_not_shown(self):
        text = quota_section(PLAN, [change("aws_s3_bucket.logs", "aws_s3_bucket", {})], aws())
        self.assertIn("This change doesn't add anything the checked quotas count.", text)


if __name__ == "__main__":
    unittest.main()
