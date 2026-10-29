import json
import unittest

from provisionguard.cost import (
    cost_section,
    ec2_instance_cost,
    eip_cost,
    eks_cluster_cost,
    eks_node_group_cost,
    nat_gateway_cost,
    rds_instance_cost,
)
from provisionguard.plan_parser import ResourceChange
from provisionguard.pricing import Pricer

REGION = "us-east-1"
EC2_LINUX = {"operatingSystem": "Linux", "tenancy": "Shared", "preInstalledSw": "NA",
             "capacitystatus": "Used", "licenseModel": "No License required"}
RDS = {"locationType": "AWS Region"}

# (service, attributes, unit, USD) using real us-east-1 on-demand prices.
PRODUCTS = [
    ("AmazonEC2", {**EC2_LINUX, "instanceType": "t3.micro"}, "Hrs", 0.0104),
    ("AmazonEC2", {**EC2_LINUX, "instanceType": "t3.medium"}, "Hrs", 0.0416),
    ("AmazonEC2", {**EC2_LINUX, "instanceType": "t3.large"}, "Hrs", 0.0832),
    ("AmazonEC2", {**EC2_LINUX, "instanceType": "m5.2xlarge"}, "Hrs", 0.384),
    ("AmazonEC2", {"productFamily": "Storage", "volumeApiName": "gp3"}, "GB-Mo", 0.08),
    ("AmazonEC2", {"locationType": "AWS Region", "productFamily": "NAT Gateway"}, "Hrs", 0.045),
    ("AmazonEC2", {"locationType": "AWS Region", "productFamily": "NAT Gateway"}, "GB", 0.045),
    ("AmazonVPC", {"usagetype": "USE1-PublicIPv4:InUseAddress"}, "Hrs", 0.005),
    ("AmazonVPC", {"usagetype": "USE1-PublicIPv4:IdleAddress"}, "Hrs", 0.005),
    ("AmazonEKS", {"usagetype": "USE1-AmazonEKS-Hours:perCluster"}, "Hours", 0.10),  # EKS says "Hours"
    ("AmazonEKS", {"usagetype": "USE1-AmazonEKS-Hours:extendedSupport"}, "hours", 0.50),  # surcharge
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.m5.large",
                   "databaseEngine": "PostgreSQL", "deploymentOption": "Single-AZ"}, "Hrs", 0.178),
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.m5.large",
                   "databaseEngine": "PostgreSQL", "deploymentOption": "Multi-AZ"}, "Hrs", 0.356),
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.t3.medium",
                   "databaseEngine": "PostgreSQL", "deploymentOption": "Single-AZ"}, "Hrs", 0.072),
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.t3.medium",
                   "databaseEngine": "PostgreSQL", "deploymentOption": "Multi-AZ"}, "Hrs", 0.144),
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.t3.medium",
                   "databaseEngine": "MySQL", "deploymentOption": "Single-AZ"}, "Hrs", 0.068),
    ("AmazonRDS", {**RDS, "productFamily": "Database Instance", "instanceType": "db.t3.medium",
                   "databaseEngine": "MySQL", "deploymentOption": "Single-AZ"}, "Hrs", 0.072),  # duplicate match
    ("AmazonRDS", {**RDS, "productFamily": "Database Storage", "volumeType": "General Purpose-GP3",
                   "deploymentOption": "Single-AZ"}, "GB-Mo", 0.115),
    ("AmazonRDS", {**RDS, "productFamily": "Database Storage", "volumeType": "General Purpose-GP3",
                   "deploymentOption": "Multi-AZ"}, "GB-Mo", 0.23),
]


class FakePricingClient:
    """Answers get_products like the real API: every filter must match the product's attributes."""

    def __init__(self):
        self.calls = 0

    def get_products(self, ServiceCode, Filters, **_):
        self.calls += 1
        results = []
        for service, attributes, unit, price in PRODUCTS:
            attributes = {**attributes, "regionCode": REGION}
            if service == ServiceCode and all(self._matches(f, attributes) for f in Filters):
                results.append(json.dumps({"terms": {"OnDemand": {"T": {"priceDimensions": {"D": {
                    "unit": unit, "pricePerUnit": {"USD": str(price)}}}}}}}))
        return {"PriceList": results}

    @staticmethod
    def _matches(f, attributes):
        value = attributes.get(f["Field"])
        if value is None:
            return False
        return f["Value"] in value if f["Type"] == "CONTAINS" else value == f["Value"]


class FakeEksClient:
    STATUS = {"1.34": "STANDARD_SUPPORT", "1.29": "EXTENDED_SUPPORT"}

    def describe_cluster_versions(self, clusterVersions):
        version = clusterVersions[0]
        if version not in self.STATUS:
            return {"clusterVersions": []}
        return {"clusterVersions": [{"clusterVersion": version, "versionStatus": self.STATUS[version]}]}


def pricer():
    return Pricer(FakePricingClient(), FakeEksClient())


def change(address, rtype, after):
    return ResourceChange(address, rtype, address.split(".")[1], ["create"], None, after, {})


def instance(name, instance_type, root=None):
    after = {"instance_type": instance_type, "root_block_device": [root] if root else []}
    return change(f'aws_instance.this["{name}"]', "aws_instance", after)


def database(instance_class="db.m5.large", engine="postgres", multi_az=False, storage=100, storage_type="gp3"):
    return change("aws_db_instance.main", "aws_db_instance", {
        "instance_class": instance_class, "engine": engine, "multi_az": multi_az,
        "allocated_storage": storage, "storage_type": storage_type})


def cluster(version="1.34"):
    return change("aws_eks_cluster.main", "aws_eks_cluster", {"version": version})


def node_group(desired=2, maximum=3, instance_types=("t3.large",), capacity_type="ON_DEMAND"):
    return change("aws_eks_node_group.main", "aws_eks_node_group", {
        "instance_types": list(instance_types), "capacity_type": capacity_type, "disk_size": None,
        "scaling_config": [{"desired_size": desired, "min_size": 1, "max_size": maximum}]})


class Ec2Test(unittest.TestCase):
    def test_instance_with_root_disk(self):
        line = ec2_instance_cost(instance("worker", "m5.2xlarge", {"volume_size": 30, "volume_type": "gp3"}),
                                 REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.384 * 730 + 30 * 0.08)  # $282.72
        self.assertEqual(line.details, "m5.2xlarge · 30 GB gp3")

    def test_default_root_disk_is_assumed(self):
        line = ec2_instance_cost(instance("x", "t3.micro"), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.0104 * 730 + 8 * 0.08)
        self.assertIn("assumed 8 GB", line.note)

    def test_unknown_instance_type(self):
        self.assertIsNone(ec2_instance_cost(instance("x", "zz.huge"), REGION, pricer()).monthly)


class RdsTest(unittest.TestCase):
    def test_single_az(self):
        line = rds_instance_cost(database(), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.178 * 730 + 100 * 0.115)  # $141.44
        self.assertEqual(line.details, "db.m5.large · postgres · Single-AZ · 100 GB gp3")

    def test_multi_az_doubles(self):
        line = rds_instance_cost(database(multi_az=True), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 2 * (0.178 * 730 + 100 * 0.115))

    def test_unsupported_engine(self):
        line = rds_instance_cost(database(engine="oracle-ee"), REGION, pricer())
        self.assertIsNone(line.monthly)
        self.assertIn("not supported", line.note)

    def test_several_matching_products_uses_lowest(self):
        self.assertEqual(pricer().rds_instance_hourly(REGION, "db.t3.medium", "MySQL", False), 0.068)


class EksAndNetworkTest(unittest.TestCase):
    def test_cluster_standard_support(self):
        line = eks_cluster_cost(cluster("1.34"), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.10 * 730)  # $73.00
        self.assertEqual(line.note, "")

    def test_cluster_extended_support_costs_six_times_more(self):
        line = eks_cluster_cost(cluster("1.29"), REGION, pricer())
        self.assertAlmostEqual(line.monthly, (0.10 + 0.50) * 730)  # $438.00: base fee + surcharge
        self.assertIn("past standard support", line.note)

    def test_cluster_unknown_version_assumes_standard(self):
        line = eks_cluster_cost(cluster("9.99"), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.10 * 730)
        self.assertIn("unknown", line.note)

    def test_node_group_multiplies_by_desired_size(self):
        line = eks_node_group_cost(node_group(), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 2 * (0.0832 * 730 + 20 * 0.08))  # $124.67
        self.assertEqual(line.details, "2 × t3.large (max 3) · 20 GB gp3 each")
        self.assertEqual(line.note, "up to $187.01 at 3 nodes")  # 3 × $62.336

    def test_node_group_spot_note(self):
        line = eks_node_group_cost(node_group(capacity_type="SPOT", maximum=2), REGION, pricer())
        self.assertEqual(line.note, "Spot nodes: on-demand price shown as upper bound")

    def test_nat_gateway_uses_hourly_not_per_gb(self):
        line = nat_gateway_cost(change("aws_nat_gateway.main", "aws_nat_gateway", {}), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.045 * 730)  # $32.85

    def test_eip(self):
        line = eip_cost(change("aws_eip.nat", "aws_eip", {"domain": "vpc"}), REGION, pricer())
        self.assertAlmostEqual(line.monthly, 0.005 * 730)  # $3.65


class SectionTest(unittest.TestCase):
    def test_full_demo_plan(self):
        disk = {"volume_size": 30, "volume_type": "gp3"}
        changes = [instance("bastion", "t3.micro", disk), instance("worker", "m5.2xlarge", disk)]
        changes += [instance(f"app-{i}", "t3.medium", disk) for i in (1, 2, 3)]
        changes += [database(), cluster(), node_group(),
                    change("aws_nat_gateway.main", "aws_nat_gateway", {}),
                    change("aws_eip.nat", "aws_eip", {"domain": "vpc"}),
                    change("aws_vpc.main", "aws_vpc", {})]
        client = FakePricingClient()
        text = cost_section({"variables": {"aws_region": {"value": REGION}}}, changes,
                            Pricer(client, FakeEksClient()))
        print("\n" + text)
        # $391.02 EC2 + $141.44 RDS + $73.00 EKS + $124.67 nodes + $32.85 NAT + $3.65 IP
        self.assertIn("**Estimated monthly cost: $766.63**", text)
        self.assertNotIn("Not priced yet", text)
        self.assertNotIn("aws_vpc", text)
        # 4 instance types + 1 disk type + 2 RDS + EKS + NAT + IP; repeats come from the cache.
        self.assertEqual(client.calls, 10)


if __name__ == "__main__":
    unittest.main()
