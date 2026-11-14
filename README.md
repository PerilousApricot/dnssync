# DNSSync

Parse BIND zone files and sync DNS records via RFC 2136 dynamic updates.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Dry run
dnssync zone.example.com -s 127.0.0.1 --dry-run

# Live update with TSIG authentication
dnssync zone.example.com -s ns1.example.com -k update-key --key-secret "secret..."

# Custom port
dnssync zone.example.com -s 127.0.0.1 -p 5353
```

## Configuration

- Zone file: Path to BIND-format zone file to parse
- `-s, --server`: DNS server to send updates to (default: 127.0.0.1)
- `-p, --port`: Server port (default: 53)
- `-k, --key`: TSIG key name for authentication
- `--key-secret`: TSIG key secret (or use DNS_TSIG_SECRET env var)
- `--dry-run`: Show what updates would be made without sending them
- `--mark-managed`: Add external-dns compatible heritage TXT records to mark managed records (default: True)
- `--no-mark-managed`: Disable marking managed records with TXT records
- `--owner-id`: Owner ID for managed records (used in external-dns compatible TXT format, default: "default")

## How It Works

1. Parses a BIND zone file to extract DNS records
2. Compares with existing records on the server (via AXFR or individual lookups)
3. Generates RFC 2136 update messages to add/remove/change records
4. Sends updates to the specified DNS server

## Development

```bash
pip install -e ".[dev]"
pytest
black src/ tests/
```