"""Shared data models."""

from dataclasses import dataclass


@dataclass
class DNSRecord:
    """A parsed DNS record."""

    name: str
    ttl: int
    type: str
    data: str
