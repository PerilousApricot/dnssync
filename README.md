# DNSSync

Parse BIND zone files and sync their DNS records to a running BIND server using
RFC 2136 dynamic updates (TSIG-authenticated), with **full-zone reconciliation**.

DNSSync treats the zone file you point it at as the source of truth. On every
run it reads the current state of the zone from the server, diffs it against
the zone file, and sends a single RFC 2136 update that adds what's missing,
updates what changed, and deletes what's no longer in the zone file.

## How it works

1. **Parse** a BIND-format zone file with dnspython (`dns.zone.from_file`).
2. **Read** the current zone from the server via an **AXFR** zone transfer.
3. **Reconcile** — compute the set difference between the zone file and the
   server (excluding the SOA and DNSSync's own heritage markers).
4. **Update** — build one RFC 2136 `UPDATE` message (TSIG-signed) that deletes
   stale records and replaces each managed `(name, type)` set, then send it.

If the zone is already in sync, nothing is sent.

### Reconciliation rules

- The **SOA is never managed**. DNSSync excludes the SOA from both sides of
  the diff — the server owns the serial number, and deleting the SOA would
  break subsequent AXFR transfers (a zone transfer must start with a SOA
  RRset).
- **Full replacement per `(name, type)`**: for every record group in the zone
  file, DNSSync deletes the existing RRset and adds the complete new set, so
  the server matches the file exactly.
- **Stale deletion**: any name that is on the server but entirely absent from
  the zone file is wiped for *all* types (including its heritage TXT marker),
  so no orphaned records are left behind.
- **Idempotent**: a second run with no changes reports `Zone is already in
  sync` and sends nothing.

## Installation

Requires Python 3.8+.

```bash
pip install -e .
```

This installs the `dnssync` console script. You can also run it as a module:
`python -m dnssync`.

## Quick start

```bash
# Parse the zone file and print its records without contacting the server
dnssync /etc/bind/db.example.com -s ns1.example.com -z example.com --dry-run

# Live sync with TSIG authentication
dnssync /etc/bind/db.example.com \
    -s ns1.example.com -p 53 \
    -z example.com \
    -k dnssync-key. --key-secret "BASE64SECRET=="
```

If `-z/--zone` is omitted, the zone name is inferred from the zone file's
filename (e.g. `db.example.com` → `example.com`), but passing it explicitly is
strongly recommended to avoid surprises.

## CLI reference

```
dnssync ZONEFILE [-s SERVER] [-p PORT] [-z ZONE] [-k KEY] [--key-secret SECRET]
                 [--dry-run] [--no-mark-managed] [--owner-id OWNER]
```

| Flag | Default | Description |
|------|---------|-------------|
| `ZONEFILE` (positional) | — | Path to the BIND zone file to parse. |
| `-s, --server` | `127.0.0.1` | DNS server address to send updates to. |
| `-p, --port` | `53` | DNS server port. |
| `-z, --zone` | inferred from filename | Zone (origin) name, e.g. `example.com`. |
| `-k, --key` | *(none)* | TSIG key name. Omit for an unsigned update (only useful if the server allows unsigned updates). |
| `--key-secret` | *(none)* | TSIG key secret — base64-encoded, or plaintext (auto-encoded if not already valid base64). |
| `--dry-run` | off | Parse and show the parsed records, then stop without contacting the server. |
| `--no-mark-managed` | off | Disable the heritage TXT markers (on by default). |
| `--owner-id` | `default` | Owner ID written into the heritage TXT marker (external-dns compatible format). |

**Exit codes:** `0` on success (including a no-op "already in sync"), `1` on
any error (parse failure, rejected update, timeout, or a non-NOERROR response
rcode).

## Zone file format

Standard BIND master-file syntax, parsed by dnspython:

```
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. admin.example.com. (
                    2024102101  ; serial
                    3600        ; refresh
                    900         ; retry
                    604800      ; expire
                    300 )       ; minimum
@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.
@       IN  A   93.184.216.34
www     IN  A   93.184.216.34
ns1     IN  A   198.51.100.10
ns2     IN  A   198.51.100.11
```

- The **SOA must be present** for dnspython to parse the zone, but it is
  ignored during reconciliation (see rules above).
- **In-zone NS targets need glue.** If an `NS` record points at a name inside
  the zone (e.g. `ns1.example.com.`), BIND requires a matching `A`/`AAAA`
  record for the zone to load. Keep the glue records in your zone file so
  DNSSync treats them as managed rather than deleting them as stale.
- All rdata names are normalized to fully-qualified form, so relative and
  absolute names in the file reconcile correctly against the server.

## Sysadmin / BIND server configuration

DNSSync is a plain RFC 2136 client. For it to work, the BIND server must be
configured to (a) accept TSIG-signed dynamic updates for the zone, and (b)
allow the AXFR zone transfer DNSSync uses to read current state.

### 1. Generate a TSIG key

```bash
# 128-bit HMAC-SHA256 key named "dnssync-key."
dnssec-keygen -a HMAC-SHA256 -b 128 -n HOST dnssync-key
```

This creates `Kdnssync-key.+157+<id>.key` (for BIND) and
`Kdnssync-key.+157+<id>.private`. Extract the base64 `Secret` line from the
`.private` file:

```
DNSKEY ...
Algorithm ...
Key ...
Secret "BASE64SECRET==";     # <-- this is the value for --key-secret
```

### 2. Configure the zone in `named.conf`

```
key dnssync-key. {
    algorithm hmac-sha256;
    secret "BASE64SECRET==";
};

zone "example.com" IN {
    type master;
    file "/etc/bind/db.example.com";
    allow-update  { key dnssync-key.; };   # TSIG-gated dynamic updates
    allow-transfer { 203.0.113.50; };       # AXFR from DNSSync's client IP
};
```

Key points:

- **`type master`** — the zone must be authoritative.
- **`allow-update { key dnssync-key.; }`** — restricts dynamic updates to
  clients presenting the TSIG key. This is the security boundary for writes.
  Use `key <name>;` (TSIG-gated), not a bare IP, so an unauthenticated client
  cannot push records.
- **`allow-transfer { ...; }`** — DNSSync reads current state with an
  **unsigned AXFR** (it does not sign the transfer), so this must permit the
  transfer by **client IP**, not by `key`. Restrict it to the IP the DNSSync
  client runs from (as shown), not `any;`, to avoid exposing the full zone to
  the internet.
- The **key name must match exactly** between `named.conf` and the
  `--key` flag, including the trailing dot (`dnssync-key.`).
- After editing, check and reload:

  ```bash
  named-checkconf && named-checkzone example.com /etc/bind/db.example.com
  systemctl reload bind9      # or rndc reload
  ```

### 3. Network / firewall

DNSSync talks to the server on the configured port (default `53`) using:

- **UDP** — the RFC 2136 `UPDATE` message is sent over UDP.
- **TCP** — the AXFR zone transfer uses TCP.

Open both UDP and TCP on that port to the DNSSync client.

### 4. Security notes

- **Keep the TSIG secret out of the zone file and version control** in real
  deployments. Pass it via `--key-secret` or, better, a secret store /
  environment-injected argument in your automation. (The repo's `k8s/` test
  fixtures contain a throwaway test key — do not reuse it in production.)
- **Prefer `--key-secret` over `--key`-only.** Without a key, DNSSync sends an
  unsigned update, which a correctly configured server will reject.
- **Large zones / updates.** The update is sent as a single UDP message. For
  very large changesets this can approach UDP message-size limits; if you
  sync a huge zone in one file and see timeouts, consider chunking the zone
  file across multiple runs.

## Heritage / managed-record markers

By default DNSSync adds an external-dns-compatible TXT marker to every
`(name, type)` it manages:

```
heritage=external-dns,external-dns/owner=default
```

Use `--owner-id <id>` to label records with a specific owner, or
`--no-mark-managed` to disable markers entirely. DNSSync always filters these
markers out of the reconciliation diff, so they never trigger spurious
add/delete churn on subsequent runs.

## Exit behavior and scripting

- `--dry-run` is safe to run anywhere: it parses and prints the records, then
  exits `0` without touching the network.
- A successful live sync (including a no-op) exits `0`.
- Any failure exits `1` and prints the error, which makes it easy to gate CI
  or cron jobs on:

  ```bash
  dnssync "$ZONEFILE" -s "$NS" -z "$ZONE" -k "$KEY" --key-secret "$SECRET" || \
      alert "dnssync failed for $ZONE"
  ```

## Testing

The test suite runs in three layers (fast → slow):

```bash
pip install -e ".[dev]"

# Full suite (in-process E2E + integration + container + K8s + parser)
pytest

# Just the in-process E2E suite (no external services, ~10s)
pytest tests/test_e2e.py
```

- **`tests/test_e2e.py`** — runs the real CLI (subprocess) against an
  in-process dnspython server that implements RFC 2136 UPDATE + TSIG + AXFR.
  No external dependencies.
- **`tests/test_integration_k8s.py`** — runs the real CLI **in a Kubernetes
  cluster** against a **real BIND 9** server (deployed by the test if missing),
  over UDP/TCP with TSIG. Skips automatically if there's no `kubectl` cluster.
  See below for the standalone test server.

### K8s test BIND server

A standalone, real BIND 9 server is provided under `k8s/` for local-cluster
testing. It uses the public `internetsystemsconsortium/bind9:9.18` image, which
the node pulls from Docker Hub (no local image build):

```bash
cd k8s
./deploy.sh          # deploys (image pulled from Docker Hub), restarts for a clean baseline
./deploy.sh down     # tears down the dnssync-test namespace
```

This deploys into the `dnssync-test` namespace: a `bind` Deployment (named 9
with a TSIG-gated, AXFR-enabled `testsync.accre.vu` zone) and a ClusterIP
`bind` service on 53/UDP+TCP. The integration test reuses this running server,
restarts the pod for a clean baseline each run, and leaves it running after the
test for reuse.

## Development

```bash
pip install -e ".[dev]"
pytest
black src/ tests/
```

Project layout:

```
src/dnssync/
  __main__.py    # python -m dnssync entrypoint
  cli.py         # argparse CLI
  models.py      # DNSRecord dataclass
  parser.py      # BIND zone file parser (dnspython)
  updater.py     # AXFR read + RFC 2136 reconciliation/sender
tests/
  test_e2e.py            # in-process server E2E (8 scenarios)
  server.py              # in-process TSIG/AXFR test server
  test_integration_k8s.py# real-BIND-on-K8s integration test
  k8s/runner.py          # in-cluster scenario runner
  k8s/zone-k8s.zone      # K8s zone fixture
k8s/                   # standalone real-BIND test server (k8s manifests)
```
