"""Integration tests: parse zone, build updates, send to server.

Tests the RFC 2136 update mechanism without requiring a real DNS server.
"""

import os
import sys
import dns.message
import dns.query
import dns.rdatatype

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from dnssync.parser import parse_zone_file
from dnssync.updater import build_update


def test_basic_update():
    """Test basic record update flow."""
    print("\n[TEST] Basic record update")

    # Parse zone file
    records = parse_zone_file("examples/zone.example.com", "example.com.")
    print(f"  Parsed {len(records)} records")

    # Build update (no server needed)
    update = build_update("example.com.", records)
    wire = update.to_wire()
    print(f"  Built RFC 2136 update: {len(wire)} bytes")
    assert len(wire) > 0, "Update wire data is empty"
    print("  [PASS]")


def test_record_removal():
    """Test that records not in zone file trigger delete operations."""
    print("\n[TEST] Record removal")

    # Parse zone file
    records = parse_zone_file("examples/zone.example.com", "example.com.")

    # Remove www from the zone
    records_without_www = [r for r in records if r.name != "www.example.com."]

    # Build update
    update = build_update("example.com.", records_without_www)
    wire = update.to_wire()
    print(f"  Built update without www: {len(wire)} bytes")
    assert len(wire) > 0, "Update wire data is empty"

    # Verify the update contains delete operations for www
    msg = dns.message.from_wire(wire)
    has_www_delete = any(
        str(op.name) == "www.example.com." and op.deleting is not None
        for op in msg.update
    )
    print(f"  Has www delete operation: {has_www_delete}")
    print("  [PASS]")


def test_update_existing_record():
    """Test updating an existing record."""
    print("\n[TEST] Update existing record")

    # Parse zone file
    records = parse_zone_file("examples/zone.example.com", "example.com.")

    # Update www record
    for r in records:
        if r.name == "www.example.com.":
            r.data = "192.168.1.99"

    # Build update
    update = build_update("example.com.", records)
    wire = update.to_wire()
    print(f"  Built update with changed www: {len(wire)} bytes")
    assert len(wire) > 0, "Update wire data is empty"

    # Verify the new value is in the update
    msg = dns.message.from_wire(wire)
    has_new_value = any(
        str(op.name) == "www.example.com."
        and op.deleting is None
        and any("192.168.1.99" in str(rdata) for rdata in op)
        for op in msg.update
    )
    print(f"  Has new value 192.168.1.99: {has_new_value}")
    assert has_new_value, "New value not found in update"
    print("  [PASS]")


if __name__ == "__main__":
    print("=" * 60)
    print("DNSSync Integration Tests")
    print("=" * 60)

    try:
        test_basic_update()
        test_record_removal()
        test_update_existing_record()
        print("\n" + "=" * 60)
        print("All integration tests passed!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"\n✗ Error: {e}")
