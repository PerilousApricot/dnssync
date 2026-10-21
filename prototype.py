#!/usr/bin/env python3
"""
DNSSync Prototype Demo
======================
Shows the full pipeline: parse BIND zone file → build RFC 2136 updates.

To test against a real BIND server, configure:
  - Server must allow RFC 2136 updates (update-policy in named.conf)
  - TSIG key for authentication

Example BIND update-policy:
  update-policy {
    grant dnssync.example.com. name any any;
  };

Generate TSIG key:
  tsig-keygen -a HMAC-SHA256 dnssync-key > dnssync-key.key
"""

import argparse
import dns.zone
import dns.update
import dns.rdatatype
import dns.name
import dns.tsig

def parse_zone_file(filepath, zone_name):
    """Parse a BIND zone file using dnspython."""
    zone = dns.zone.from_file(filepath, zone_name)
    records = []
    for (name, ttl, rdata) in zone.iterate_rdatas():
        records.append({
            'name': str(name),
            'ttl': ttl,
            'type': dns.rdatatype.to_text(rdata.rdtype),
            'data': str(rdata),
        })
    return records

def build_update(zone_name, records):
    """Build an RFC 2136 update message from parsed records."""
    update = dns.update.Update(zone_name)
    for record in records:
        if record['type'] == 'SOA':
            continue
        rtype = dns.rdatatype.from_text(record['type'])
        if record['type'] in ('A', 'AAAA'):
            # Delete old, add new
            update.delete(name=record['name'], rdtype=rtype)
            update.add(name=record['name'], ttl=record['ttl'], rdtype=rtype, rdata=record['data'])
        else:
            update.replace(record['name'], record['ttl'], rtype, record['data'])
    return update

def send_update(server, port, update, key_name=None, key_secret=None):
    """Send the update to the DNS server."""
    if key_name and key_secret:
        key = dns.tsig.Key(key_name, key_secret, dns.tsig.HMAC_SHA256)
        response = update.send(server, port, key=key)
    else:
        response = update.send(server, port)
    return response

def main():
    parser = argparse.ArgumentParser(description='DNSSync Prototype Demo')
    parser.add_argument('zonefile', help='Path to BIND zone file')
    parser.add_argument('-s', '--server', default='127.0.0.1', help='DNS server')
    parser.add_argument('-p', '--port', type=int, default=53, help='DNS port')
    parser.add_argument('-z', '--zone', help='Zone name')
    parser.add_argument('-k', '--key', help='TSIG key name')
    parser.add_argument('--key-secret', help='TSIG key secret')
    parser.add_argument('--dry-run', action='store_true', help='Show updates without sending')
    args = parser.parse_args()

    if not args.zone:
        args.zone = args.zonefile.split('.')[0] + '.'

    print(f"Zone: {args.zone}")
    print(f"Parsing: {args.zonefile}")
    records = parse_zone_file(args.zonefile, args.zone)
    print(f"Parsed {len(records)} records:")
    for r in records:
        print(f"  {r['name']:40} {r['type']:5} {r['data']}")

    update = build_update(args.zone, records)
    print(f"\nBuilt RFC 2136 update message with {len(update.deletions)} deletions, {len(update.additions)} additions")

    if args.dry_run:
        print("Dry run complete (not sending)")
        return

    print(f"Sending to {args.server}:{args.port}...")
    try:
        response = send_update(args.server, args.port, update, args.key, args.key_secret)
        print(f"Response: {response}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()