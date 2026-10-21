"""RFC 2136 DNS dynamic update sender with full zone reconciliation."""

import socket
from collections import defaultdict
import dns.update
import dns.tsig
import dns.rdatatype
import dns.rcode
import dns.query
import dns.message
from typing import Dict, List, Set, Tuple

from .models import DNSRecord


def get_server_records(server: str, port: int, zone: str) -> List[DNSRecord]:
    """Query the server for all current records in the zone via AXFR."""
    try:
        response = dns.query.xfr(server, zone, port=port)
        records = []
        for rdataset in response:
            for rdata in rdataset:
                records.append(
                    DNSRecord(
                        name=str(rdataset.name),
                        type=dns.rdatatype.to_text(rdataset.rdtype),
                        data=str(rdata),
                        ttl=rdataset.ttl,
                    )
                )
        return records
    except Exception:
        return []


def build_update(zone: str, records: List[DNSRecord]) -> dns.update.Update:
    """Build an RFC 2136 update message without sending it.

    Groups records by (name, type) so that replace() sends the complete set.
    Records removed from the zone file will be deleted from the server.

    Used for dry-run mode to preview changes.
    """
    update = dns.update.Update(zone)

    # Group records by (name, type) so we can replace all at once
    groups = defaultdict(list)
    for record in records:
        if record.type == "SOA":
            continue
        rtype = dns.rdatatype.from_text(record.type)
        groups[(record.name, rtype)].append(record)

    for (name, rtype), group in groups.items():
        # Delete all existing records of this type for this name
        update.delete(name, rtype)
        # Add the new complete set
        for record in group:
            update.add(name, record.ttl, rtype, record.data)

    return update


def reconcile_zone(
    server: str,
    port: int,
    zone: str,
    zone_records: List[DNSRecord],
    tsig_key: str = "",
    tsig_secret: str = "",
) -> Dict[str, object]:
    """Reconcile the server zone with the zone file.

    Full reconciliation: queries the server for all current records,
    compares with the zone file, and sends updates to make them match.
    """
    # Get current server state
    server_records = get_server_records(server, port, zone)
    print(f"    Server has {len(server_records)} records")

    # Build sets for comparison
    def record_key(r):
        return (r.name, r.type, r.data)

    zone_set = {record_key(r) for r in zone_records if r.type != "SOA"}
    server_set = {record_key(r) for r in server_records}

    to_add = zone_set - server_set
    to_delete = server_set - zone_set

    if not to_add and not to_delete:
        print("    Zone is already in sync")
        return {"added": 0, "removed": 0, "errors": 0}

    print(f"    Will add {len(to_add)} record(s), delete {len(to_delete)} record(s)")

    # Build update
    update = dns.update.Update(zone)

    # Delete stale records
    for name, rtype, data in to_delete:
        update.delete(name, rtype)

    # Add/update zone file records
    groups = defaultdict(list)
    for record in zone_records:
        if record.type == "SOA":
            continue
        rtype = dns.rdatatype.from_text(record.type)
        groups[(record.name, rtype)].append(record)

    for (name, rtype), group in groups.items():
        update.delete(name, rtype)
        for record in group:
            update.add(name, record.ttl, rtype, record.data)

    # Add TSIG auth
    if tsig_key:
        key = dns.tsig.Key(tsig_key, tsig_secret, dns.tsig.HMAC_SHA256)
        update.use_tsig(key, keyring={key.name: key})

    # Send update
    try:
        wire = update.to_wire()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(wire, (server, port))
        sock.settimeout(5)
        response_wire, _ = sock.recvfrom(4096)
        sock.close()

        response = dns.message.from_wire(response_wire)
        if response.rcode() == dns.rcode.NOERROR:
            return {"added": len(to_add), "removed": len(to_delete), "errors": 0}
        else:
            return {
                "added": 0,
                "removed": 0,
                "errors": 1,
                "message": f"Server returned rcode {response.rcode()}",
            }
    except Exception as e:
        return {"added": 0, "removed": 0, "errors": 1, "message": str(e)}


def apply_updates(
    server: str,
    port: int,
    zone: str,
    records: List[DNSRecord],
    tsig_key: str = "",
    tsig_secret: str = "",
) -> Dict[str, object]:
    """Apply all updates for records to the DNS server.

    Full zone reconciliation: records in the zone file are added/updated,
    and records on the server that are not in the zone file are deleted.
    """
    return reconcile_zone(server, port, zone, records, tsig_key, tsig_secret)
