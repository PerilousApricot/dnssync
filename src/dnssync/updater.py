"""RFC 2136 DNS dynamic update sender with full zone reconciliation."""

import socket
import time
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
    """Query the server for all current records in the zone via AXFR.

    Falls back to returning empty list if AXFR is not available.
    """
    try:
        # relativize=False so returned names are absolute, matching the
        # absolute names the zone-file parser produces (otherwise the
        # reconciliation name sets never line up and stale records are missed).
        response = dns.query.xfr(server, zone, port=port, timeout=5, relativize=False)
        records = []
        # dns.query.xfr yields Message objects; the transferred RRsets are in
        # each message's answer section (SOA at first and last).
        for message in response:
            for rdataset in message.answer:
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
    except dns.exception.Timeout:
        print(f"    Warning: AXFR timed out, assuming empty zone")
        return []
    except Exception as e:
        print(f"    Warning: AXFR failed ({e}), assuming empty zone")
        return []


def build_update(
    zone: str, records: List[DNSRecord], mark_managed: bool = True, owner_id: str = ""
) -> dns.update.Update:
    """Build an RFC 2136 update message without sending it.

    Groups records by (name, type) so that replace() sends the complete set.
    Records removed from the zone file will be deleted from the server.

    Args:
        zone: Zone name
        records: List of DNS records to add
        mark_managed: If True, add heritage TXT records to track managed records
        owner_id: Owner ID for the heritage record (external-dns compatible format)

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
        if mark_managed:
            # Add external-dns compatible heritage record
            owner = owner_id if owner_id else "default"
            heritage = f"heritage=external-dns,external-dns/owner={owner}"
            update.add(name, 3600, dns.rdatatype.TXT, heritage)

    return update


def reconcile_zone(
    server: str,
    port: int,
    zone: str,
    zone_records: List[DNSRecord],
    tsig_key: str = "",
    tsig_secret: str = "",
    mark_managed: bool = True,
    owner_id: str = "",
) -> Dict[str, object]:
    """Reconcile the server zone with the zone file.

    Full reconciliation: queries the server for all current records,
    compares with the zone file, and sends updates to make them match.

    Args:
        server: DNS server address
        port: DNS server port
        zone: Zone name
        zone_records: Records from the zone file
        tsig_key: TSIG key name for authentication
        tsig_secret: TSIG key secret
        mark_managed: If True, add heritage TXT records to track managed records
        owner_id: Owner ID for the heritage record (external-dns compatible format)
    """
    # Get current server state
    server_records = get_server_records(server, port, zone)
    print(f"    Server has {len(server_records)} records")

    # Build sets for comparison
    def record_key(r):
        return (r.name, r.type, r.data)

    zone_set = {record_key(r) for r in zone_records if r.type != "SOA"}
    # The server set must be built consistently with zone_set: exclude SOA
    # (dnssync does not manage the SOA -- deleting it would break subsequent
    # AXFR transfers, which require a leading SOA RRset) and exclude our own
    # heritage TXT markers. TXT rdata serializes with surrounding quotes, so
    # strip them before the heritage prefix check.
    server_set = set()
    for r in server_records:
        if r.type == "SOA":
            continue
        if r.type == "TXT" and r.data.strip('"').startswith("heritage=external-dns"):
            continue
        server_set.add(record_key(r))

    to_add = zone_set - server_set
    to_delete = server_set - zone_set

    # Names present on the server but entirely absent from the zone file must
    # be wiped for ALL types (including their heritage TXT marker), otherwise
    # an orphaned TXT record is left behind when its parent record is removed.
    zone_names = {r.name for r in zone_records if r.type != "SOA"}
    fully_stale_names = {
        r.name for r in server_records if r.name not in zone_names
    }

    if not to_add and not to_delete and not fully_stale_names:
        print("    Zone is already in sync")
        return {"added": 0, "removed": 0, "errors": 0}

    print(f"    Will add {len(to_add)} record(s), delete {len(to_delete)} record(s)")

    # Build update
    update = dns.update.Update(zone)

    # Wipe names that are no longer in the zone file at all (all types)
    for name in fully_stale_names:
        update.delete(name)

    # Delete stale records for names that are still in the zone file
    for name, rtype, data in to_delete:
        if name not in fully_stale_names:
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
        if mark_managed:
            # Add external-dns compatible heritage record
            owner = owner_id if owner_id else "default"
            heritage = f"heritage=external-dns,external-dns/owner={owner}"
            update.add(name, 3600, dns.rdatatype.TXT, heritage)

    # Add TSIG auth
    if tsig_key:
        import base64

        # Ensure secret is base64-encoded
        try:
            base64.b64decode(tsig_secret)
        except Exception:
            tsig_secret = base64.b64encode(tsig_secret.encode()).decode()
        key = dns.tsig.Key(tsig_key, tsig_secret, dns.tsig.HMAC_SHA256)
        update.use_tsig(key)

    # Send update via RFC 2136
    try:
        response = dns.query.udp(update, server, port=port, timeout=5)
        if response.rcode() == dns.rcode.NOERROR:
            return {"added": len(to_add), "removed": len(to_delete), "errors": 0}
        else:
            return {
                "added": 0,
                "removed": 0,
                "errors": 1,
                "message": f"Server returned rcode {dns.rcode.to_text(response.rcode())}",
            }
    except dns.exception.Timeout:
        return {"added": 0, "removed": 0, "errors": 1, "message": "Update timed out"}
    except Exception as e:
        return {"added": 0, "removed": 0, "errors": 1, "message": str(e)}


def apply_updates(
    server: str,
    port: int,
    zone: str,
    records: List[DNSRecord],
    tsig_key: str = "",
    tsig_secret: str = "",
    mark_managed: bool = True,
    owner_id: str = "",
) -> Dict[str, object]:
    """Apply all updates for records to the DNS server.

    Full zone reconciliation: records in the zone file are added/updated,
    and records on the server that are not in the zone file are deleted.

    Args:
        server: DNS server address
        port: DNS server port
        zone: Zone name
        records: Records from the zone file
        tsig_key: TSIG key name for authentication
        tsig_secret: TSIG key secret
        mark_managed: If True, add heritage TXT records to track managed records
        owner_id: Owner ID for the heritage record (external-dns compatible format)
    """
    return reconcile_zone(
        server, port, zone, records, tsig_key, tsig_secret, mark_managed, owner_id
    )
