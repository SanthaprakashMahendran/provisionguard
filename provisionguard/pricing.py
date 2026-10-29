"""Look up AWS on-demand list prices with the Pricing API, caching each answer."""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, Tuple

HOURS_PER_MONTH = 730

# Services spell the same unit differently: EC2/RDS/VPC use "Hrs", EKS uses "Hours" or "hours".
UNIT_ALIASES = {"hrs": {"hrs", "hours", "hour"}}


class Pricer:
    def __init__(self, client: Any = None, eks_client: Any = None):
        if client is None:
            import boto3

            # The Pricing API only has endpoints in a few regions; us-east-1 answers for every region.
            client = boto3.client("pricing", region_name="us-east-1")
        self._client = client
        self._eks_client = eks_client
        self._cache: Dict[Tuple, Optional[float]] = {}

    def ec2_instance_hourly(self, region: str, instance_type: str) -> Optional[float]:
        """USD per hour for a Linux, shared-tenancy, on-demand instance."""
        return self._lookup(
            "AmazonEC2",
            "Hrs",
            regionCode=region,
            instanceType=instance_type,
            operatingSystem="Linux",
            tenancy="Shared",
            preInstalledSw="NA",
            capacitystatus="Used",
            licenseModel="No License required",
        )

    def ebs_gb_month(self, region: str, volume_type: str) -> Optional[float]:
        """USD per GB-month of EBS storage (gp3, gp2, io1, ...)."""
        return self._lookup(
            "AmazonEC2",
            "GB-Mo",
            regionCode=region,
            productFamily="Storage",
            volumeApiName=volume_type,
        )

    def rds_instance_hourly(self, region: str, instance_class: str, engine: str, multi_az: bool) -> Optional[float]:
        """USD per hour for an RDS instance. `engine` uses Pricing API names, e.g. "PostgreSQL"."""
        return self._lookup(
            "AmazonRDS",
            "Hrs",
            regionCode=region,
            locationType="AWS Region",
            productFamily="Database Instance",
            instanceType=instance_class,
            databaseEngine=engine,
            deploymentOption="Multi-AZ" if multi_az else "Single-AZ",
        )

    def rds_storage_gb_month(self, region: str, volume_type: str, multi_az: bool) -> Optional[float]:
        """USD per GB-month of RDS storage. `volume_type` uses Pricing API names, e.g. "General Purpose-GP3"."""
        return self._lookup(
            "AmazonRDS",
            "GB-Mo",
            regionCode=region,
            locationType="AWS Region",
            productFamily="Database Storage",
            volumeType=volume_type,
            deploymentOption="Multi-AZ" if multi_az else "Single-AZ",
        )

    def nat_gateway_hourly(self, region: str) -> Optional[float]:
        """USD per hour a NAT gateway exists (data processed is billed separately, per GB)."""
        return self._lookup(
            "AmazonEC2", "Hrs", regionCode=region, locationType="AWS Region", productFamily="NAT Gateway"
        )

    def public_ipv4_hourly(self, region: str) -> Optional[float]:
        """USD per hour for a public IPv4 address that is attached to something."""
        return self._lookup(
            "AmazonVPC", "Hrs", contains={"usagetype": "PublicIPv4:InUseAddress"}, regionCode=region
        )

    def eks_cluster_hourly(self, region: str, extended_support: bool) -> Optional[float]:
        """USD per hour for an EKS control plane; versions past standard support cost more."""
        standard = self._lookup(
            "AmazonEKS", "Hrs", contains={"usagetype": "AmazonEKS-Hours:perCluster"}, regionCode=region
        )
        if not extended_support or standard is None:
            return standard
        # Extended support is billed as a surcharge on top of the standard cluster fee.
        surcharge = self._lookup(
            "AmazonEKS", "Hrs", contains={"usagetype": "AmazonEKS-Hours:extendedSupport"}, regionCode=region
        )
        return None if surcharge is None else standard + surcharge

    def eks_version_status(self, region: str, version: str) -> Optional[str]:
        """"STANDARD_SUPPORT", "EXTENDED_SUPPORT" or "UNSUPPORTED" for a Kubernetes version, None if unknown."""
        try:
            if self._eks_client is None:
                import boto3

                self._eks_client = boto3.client("eks", region_name=region)
            versions = self._eks_client.describe_cluster_versions(clusterVersions=[version])["clusterVersions"]
        except Exception as exc:
            print(f"::warning::Could not look up EKS {version} support status: {exc!r}", file=sys.stderr)
            return None
        if not versions:
            return None
        status = versions[0].get("versionStatus") or versions[0].get("status") or ""
        return status.upper().replace("-", "_") or None

    def _lookup(
        self, service: str, unit: str, contains: Optional[Dict[str, str]] = None, **attributes: str
    ) -> Optional[float]:
        contains = contains or {}
        key = (service, unit, tuple(sorted(attributes.items())), tuple(sorted(contains.items())))
        if key not in self._cache:
            self._cache[key] = self._fetch(service, unit, attributes, contains)
        return self._cache[key]

    def _fetch(
        self, service: str, unit: str, attributes: Dict[str, str], contains: Dict[str, str]
    ) -> Optional[float]:
        filters = [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in attributes.items()]
        filters += [{"Type": "CONTAINS", "Field": k, "Value": v} for k, v in contains.items()]
        response = self._client.get_products(
            ServiceCode=service, Filters=filters, FormatVersion="aws_v1", MaxResults=100
        )
        prices = set()
        units_seen = set()
        for item in response["PriceList"]:
            product = json.loads(item) if isinstance(item, str) else item
            for term in product.get("terms", {}).get("OnDemand", {}).values():
                for dimension in term["priceDimensions"].values():
                    price = float(dimension["pricePerUnit"].get("USD", 0))
                    units_seen.add(dimension["unit"])
                    if dimension["unit"].lower() in UNIT_ALIASES.get(unit.lower(), {unit.lower()}) and price > 0:
                        prices.add(price)
        if not prices:
            reason = f"products matched but in units {sorted(units_seen)}" if units_seen else "no products matched"
            print(f"::warning::No {unit} price for {service} {attributes} {contains}: {reason}", file=sys.stderr)
        if len(prices) > 1:
            # The filters matched several products; they need tightening to pick one.
            print(f"::warning::{service} {attributes} {contains} matched {len(prices)} prices {sorted(prices)}; using the lowest",
                  file=sys.stderr)
        return min(prices) if prices else None


_shared: Optional[Pricer] = None


def default_pricer() -> Pricer:
    """One Pricer per run, so every section shares the same price cache."""
    global _shared
    if _shared is None:
        _shared = Pricer()
    return _shared
