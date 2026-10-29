"""Shared helpers for the read-only AWS calls the checks make."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class AwsClients:
    """Creates boto3 clients on first use, so tests can pass fakes and local runs don't need boto3."""

    def __init__(self, region: str, clients: Optional[Dict[str, Any]] = None):
        self.region = region
        self._clients = dict(clients or {})

    def __getitem__(self, service: str) -> Any:
        if service not in self._clients:
            import boto3

            self._clients[service] = boto3.client(service, region_name=self.region)
        return self._clients[service]


def error_code(exc: Exception) -> str:
    """The AWS error code of a botocore ClientError, e.g. "NoSuchEntity"; "" for anything else."""
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def pages(client: Any, operation: str, key: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """All items of a paginated AWS list/describe call."""
    items: List[Dict[str, Any]] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items += page.get(key, [])
    return items
