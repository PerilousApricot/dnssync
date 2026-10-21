"""BIND zone file parser using dnspython."""

import dns.zone
import dns.rdatatype
from typing import List

from .models import DNSRecord


def parse_zone_file(filepath: str, zone_name: str = "") -> List[DNSRecord]:
    """Parse a BIND zone file and return a list of DNS records."""
    zone = dns.zone.from_file(filepath, zone_name)

    records = []
    for name, ttl, rdata in zone.iterate_rdatas():
        # Convert relative name to absolute
        if not name.is_absolute():
            name = name.concatenate(zone.origin)
        records.append(
            DNSRecord(
                name=str(name),
                ttl=ttl,
                type=dns.rdatatype.to_text(rdata.rdtype),
                data=str(rdata),
            )
        )

    return records
