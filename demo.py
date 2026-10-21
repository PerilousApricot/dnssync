"""
DNSSync Prototype - Zone Parse and Update Build Demo
Shows the full pipeline: parse BIND zone file → build RFC 2136 update message.

Usage:
    python demo.py <zonefile> [--zone ZONE_NAME] [--dry-run]
"""

import argparse
import dns.zone
import dns.update
import dns.rdatatype
import dns.name


from dnssync.parser import parse_zone_file
from dnssync.updater import build_update


def main():
    parser = argparse.ArgumentParser(description="DNSSync Prototype Demo")
    parser.add_argument("zonefile", help="Path to BIND zone file")
    parser.add_argument(
        "--zone", default=None, help="Zone name (auto-detected if not specified)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show planned changes without sending"
    )
    args = parser.parse_args()

    # Auto-detect zone name from filename if not specified
    zone_name = args.zone
    if not zone_name:
        # Try to detect from filename
        base = args.zonefile.split("/")[-1]
        zone_name = base.replace(".zone", "").replace("zone.", "") + "."

    print("=" * 60)
    print("DNSSync Prototype - End-to-End Demo")
    print("=" * 60)

    # Step 1: Parse zone file
    print(f"\n[1] Parsing zone file: {args.zonefile}")
    records = parse_zone_file(args.zonefile, zone_name)
    print(f"    Parsed {len(records)} records:")
    for r in records:
        print(f"      {r.name:40s} {r.type:5s} {r.data}")

    # Step 2: Build RFC 2136 update message
    print("\n[2] Building RFC 2136 update message")
    update = build_update(zone_name, records)

    # Show planned changes
    print("\n[3] Planned changes (dry run):")
    print("    " + "-" * 56)
    for line in update.to_text().split("\n"):
        if (
            line.strip()
            and not line.startswith("id ")
            and not line.startswith("opcode ")
            and not line.startswith("rcode ")
            and not line.startswith("flags ")
            and not line.startswith(";ZONE")
            and not line.startswith(";PREREQ")
            and not line.startswith(";UPDATE")
            and not line.startswith(";ADDITIONAL")
        ):
            print(f"    {line}")
    print("    " + "-" * 56)

    if args.dry_run:
        print("\nDry run complete. No changes sent to server.")
    else:
        print("\nTo send this update to a real BIND server:")
        print("  update.send('server.example.com', 53)")
        print("  or with TSIG auth:")
        print("  update.send('server.example.com', 53, key=key)")

    print("\n" + "=" * 60)
    print("Prototype complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
