"""Command-line interface for DNSSync."""

import argparse
import sys

from dnssync.models import DNSRecord
from dnssync.parser import parse_zone_file
from dnssync.updater import apply_updates


def main():
    parser = argparse.ArgumentParser(
        prog="dnssync",
        description="Sync DNS records from BIND zone files using RFC 2136 dynamic updates.",
    )
    parser.add_argument(
        "zonefile",
        help="Path to BIND zone file to parse",
    )
    parser.add_argument(
        "-s",
        "--server",
        default="127.0.0.1",
        help="DNS server address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="DNS server port (default: 53)",
    )
    parser.add_argument(
        "-z",
        "--zone",
        default="",
        help="Zone name (inferred from zonefile if not specified)",
    )
    parser.add_argument(
        "-k",
        "--key",
        default="",
        help="TSIG key name for authentication",
    )
    parser.add_argument(
        "--key-secret",
        default="",
        help="TSIG key secret",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show updates without sending them",
    )
    parser.add_argument(
        "--mark-managed",
        action="store_true",
        default=True,
        help="Add 'heritage=external-dns' TXT records to mark managed records (default: True)",
    )
    parser.add_argument(
        "--no-mark-managed",
        action="store_true",
        help="Disable marking managed records with TXT records",
    )
    parser.add_argument(
        "--owner-id",
        default="",
        help="Owner ID for managed records (used in external-dns compatible TXT format)",
    )

    args = parser.parse_args()

    # Resolve mark_managed flag
    if args.no_mark_managed:
        args.mark_managed = False

    if not args.zone:
        # Infer zone name from zonefile filename
        import os

        args.zone = os.path.basename(args.zonefile).rstrip(".")

    print(f"Parsing zone file: {args.zonefile}")
    print(f"Zone: {args.zone}")

    try:
        records = parse_zone_file(args.zonefile, args.zone)
        print(f"Parsed {len(records)} records")

        for record in records:
            print(f"  {record.name:40s} {record.type:5s} {record.data}")

        if args.dry_run:
            print("\nDry run complete. No updates sent.")
            return 0

        print(f"\nSending updates to {args.server}:{args.port}...")
        result = apply_updates(
            args.server,
            args.port,
            args.zone,
            records,
            args.key,
            args.key_secret,
            args.mark_managed,
            args.owner_id,
        )

        print(
            f"Updates completed: {result['added']} added, {result['removed']} removed, "
            f"{result['errors']} errors"
        )

        if result["errors"] > 0:
            return 1
        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
