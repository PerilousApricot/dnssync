"""BIND zone file parser using dnspython."""

import dns.zone
import dns.rdatatype
from typing import List

from .models import DNSRecord


def parse_zone_file(filepath: str, zone_name: str = "") -> List[DNSRecord]:
    """Parse a BIND zone file and return a list of DNS records.

    Names and rdata (e.g. the target of an NS record) are returned
    ABSOLUTE. We pass ``relativize=False`` so dnspython does not strip the
    zone origin from rdata: a real BIND server always returns fully-qualified
    names via AXFR, so the zone-file side must use the same form or the
    reconciliation would see a phantom diff (NS 'ns1' vs 'ns1.<zone>').
    """
    zone = dns.zone.from_file(filepath, zone_name, relativize=False)

    records = []
    for name, ttl, rdata in zone.iterate_rdatas():
        # Names are already absolute (relativize=False); keep the guard for
        # safety in case a caller passes an origin that yields relative names.
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
