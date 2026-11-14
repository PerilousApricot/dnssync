"""End-to-end tests for DNSSync.

These exercise the *real* CLI entry point (``python -m dnssync``) in a
subprocess, talking to an in-process DNS server (``FullDNSServer``) over real
UDP/TCP sockets with TSIG. Results are verified with *independent* dnspython
queries -- never by poking the server's internal store -- so the tests reflect
what actually lands on the wire.

The scenarios:
  1. first sync            -- every zone-file record appears on the server
  2. heritage markers      -- each managed name gets a heritage TXT
  3. idempotency           -- a second run is a no-op, state is stable
  4. change detection      -- editing the zone file adds/updates records
  5. stale deletion        -- removing a name deletes its records AND its TXT
  6. dry-run               -- --dry-run reports but does not change the server
  7. auth failure          -- a wrong TSIG secret is rejected, nothing applied
  8. unreachable server    -- a dead port yields a clean non-zero exit
"""

import os
import socket
import subprocess
import sys

import dns.message
import dns.query
import pytest

# Make the in-process server importable regardless of pytest's rootdir.
sys.path.insert(0, os.path.dirname(__file__))
from server import FullDNSServer  # noqa: E402

ZONE = "testsync.accre.vu."
TSIG_KEY = "dnssync-e2e-key."
TSIG_SECRET = "s3cr3tKeyValue123"

ZONE_TEXT = """$ORIGIN {zone}
$TTL 300
@       IN  SOA ns1.{zone} admin.{zone} (
                    2024102101  ; serial
                    3600       ; refresh
                    900        ; retry
                    604800     ; expire
                    300 )      ; minimum
@       IN  NS  ns1.{zone}
@       IN  NS  ns2.{zone}
@       IN  A   10.0.0.1
www     IN  A   10.0.0.1
api     IN  A   10.0.0.2
mail    IN  A   10.0.0.3
""".format(zone=ZONE)

# Names we expect DNSSync to manage (everything except the SOA).
MANAGED_NAMES = [
    ZONE,
    "www." + ZONE,
    "api." + ZONE,
    "mail." + ZONE,
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _q(server, port, name, rdtype, timeout=5):
    """Independent query; returns the list of answer rdata (as objects)."""
    ans = dns.query.udp(
        dns.message.make_query(name, rdtype), server, port=port, timeout=timeout
    )
    return list(ans.answer)


def q_a(server, port, name):
    """Return the set of A-record IP strings for *name* (empty set if none)."""
    rrs = _q(server, port, name, "A")
    out = set()
    for rr in rrs:
        for rdata in rr:
            out.add(str(rdata))
    return out


def q_txt(server, port, name):
    """Return the list of TXT string values for *name*."""
    rrs = _q(server, port, name, "TXT")
    out = []
    for rr in rrs:
        for rdata in rr:
            out.append(str(rdata))
    return out


def q_ns(server, port, name):
    rrs = _q(server, port, name, "NS")
    out = set()
    for rr in rrs:
        for rdata in rr:
            out.add(str(rdata))
    return out


def run_cli(env, *extra):
    """Invoke the real CLI in a subprocess and return the CompletedProcess."""
    cmd = [
        sys.executable,
        "-m",
        "dnssync",
        str(env.zonefile),
        "-s",
        "127.0.0.1",
        "-p",
        str(env.port),
        "-z",
        ZONE,
    ]
    if env.use_tsig:
        cmd += ["-k", TSIG_KEY, "--key-secret", TSIG_SECRET]
    cmd += list(extra)
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=90, cwd=env.project_root
    )


def write_zone(path, text):
    path.write_text(text)
    return path


# --------------------------------------------------------------------------- #
# fixture
# --------------------------------------------------------------------------- #

class Env:
    pass


@pytest.fixture
def env(tmp_path):
    server = FullDNSServer(
        zone_name=ZONE,
        tsig_keyname=TSIG_KEY,
        tsig_secret=TSIG_SECRET,
    )
    e = Env()
    e.server = server
    e.port = server.port
    e.use_tsig = True
    e.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    e.zonefile = write_zone(tmp_path / "zone.zone", ZONE_TEXT)
    yield e
    server.stop()


# --------------------------------------------------------------------------- #
# 1. first sync
# --------------------------------------------------------------------------- #

def test_first_sync(env):
    r = run_cli(env)
    assert r.returncode == 0, f"CLI failed: {r.stdout}\n{r.stderr}"

    # A records
    assert q_a(env.server.host, env.port, ZONE) == {"10.0.0.1"}
    assert q_a(env.server.host, env.port, "www." + ZONE) == {"10.0.0.1"}
    assert q_a(env.server.host, env.port, "api." + ZONE) == {"10.0.0.2"}
    assert q_a(env.server.host, env.port, "mail." + ZONE) == {"10.0.0.3"}

    # NS records (both present)
    ns = q_ns(env.server.host, env.port, ZONE)
    assert "ns1." + ZONE in ns
    assert "ns2." + ZONE in ns


# --------------------------------------------------------------------------- #
# 2. heritage markers
# --------------------------------------------------------------------------- #

def test_heritage_markers(env):
    r = run_cli(env)
    assert r.returncode == 0, f"CLI failed: {r.stdout}\n{r.stderr}"

    for name in MANAGED_NAMES:
        txts = q_txt(env.server.host, env.port, name)
        assert any("heritage=external-dns" in t for t in txts), (
            f"no heritage TXT for {name}: {txts}"
        )


# --------------------------------------------------------------------------- #
# 3. idempotency
# --------------------------------------------------------------------------- #

def test_idempotency(env):
    r1 = run_cli(env)
    assert r1.returncode == 0, f"first run failed: {r1.stdout}\n{r1.stderr}"
    before = q_a(env.server.host, env.port, "www." + ZONE)

    r2 = run_cli(env)
    assert r2.returncode == 0, f"second run failed: {r2.stdout}\n{r2.stderr}"
    after = q_a(env.server.host, env.port, "www." + ZONE)

    assert before == after == {"10.0.0.1"}


# --------------------------------------------------------------------------- #
# 4. change detection
# --------------------------------------------------------------------------- #

def test_change_detection(env):
    run_cli(env)  # initial sync
    assert q_a(env.server.host, env.port, "www." + ZONE) == {"10.0.0.1"}

    # Change www's IP and add a new host "shop".
    modified = ZONE_TEXT.replace(
        "www     IN  A   10.0.0.1", "www     IN  A   10.9.9.9"
    ) + "shop    IN  A   10.0.0.4\n"
    env.zonefile = write_zone(env.zonefile, modified)

    r = run_cli(env)
    assert r.returncode == 0, f"re-sync failed: {r.stdout}\n{r.stderr}"

    # www now points to the new IP (old one gone)
    assert q_a(env.server.host, env.port, "www." + ZONE) == {"10.9.9.9"}
    # new host appears
    assert q_a(env.server.host, env.port, "shop." + ZONE) == {"10.0.0.4"}
    # untouched record is stable
    assert q_a(env.server.host, env.port, "mail." + ZONE) == {"10.0.0.3"}


# --------------------------------------------------------------------------- #
# 5. stale deletion (records AND their heritage TXT)
# --------------------------------------------------------------------------- #

def test_stale_deletion(env):
    run_cli(env)  # initial sync
    assert q_a(env.server.host, env.port, "api." + ZONE) == {"10.0.0.2"}

    # Remove the api host entirely from the zone file.
    modified = "\n".join(
        line for line in ZONE_TEXT.splitlines() if not line.startswith("api")
    ) + "\n"
    env.zonefile = write_zone(env.zonefile, modified)

    r = run_cli(env)
    assert r.returncode == 0, f"re-sync failed: {r.stdout}\n{r.stderr}"

    # The A record is gone...
    assert q_a(env.server.host, env.port, "api." + ZONE) == set()
    # ...and its heritage TXT is cleaned up too (no orphaned marker).
    assert q_txt(env.server.host, env.port, "api." + ZONE) == []
    # Other records unaffected.
    assert q_a(env.server.host, env.port, "mail." + ZONE) == {"10.0.0.3"}


# --------------------------------------------------------------------------- #
# 6. dry-run does not mutate the server
# --------------------------------------------------------------------------- #

def test_dry_run(env):
    run_cli(env)  # populate server with the original records
    assert q_a(env.server.host, env.port, "www." + ZONE) == {"10.0.0.1"}

    # Modify the zone file, but run with --dry-run.
    modified = ZONE_TEXT.replace("www     IN  A   10.0.0.1", "www     IN  A   99.99.99.99")
    env.zonefile = write_zone(env.zonefile, modified)

    r = run_cli(env, "--dry-run")
    assert r.returncode == 0, f"dry-run failed: {r.stdout}\n{r.stderr}"
    assert "Dry run complete" in r.stdout

    # Server must be unchanged: www still has the original IP.
    assert q_a(env.server.host, env.port, "www." + ZONE) == {"10.0.0.1"}


# --------------------------------------------------------------------------- #
# 7. auth failure (wrong TSIG secret)
# --------------------------------------------------------------------------- #

def test_auth_failure(env):
    # Confirm the server starts empty of managed A records.
    assert q_a(env.server.host, env.port, "www." + ZONE) == set()

    # Point the CLI at the server but with the WRONG secret.
    cmd = [
        sys.executable, "-m", "dnssync", str(env.zonefile),
        "-s", "127.0.0.1", "-p", str(env.port), "-z", ZONE,
        "-k", TSIG_KEY, "--key-secret", "definitelyWrongSecret",
    ]
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=90, cwd=env.project_root
    )

    # The update must be rejected (non-zero exit) and nothing applied.
    assert r.returncode != 0, f"expected failure, got: {r.stdout}"
    assert q_a(env.server.host, env.port, "www." + ZONE) == set()


# --------------------------------------------------------------------------- #
# 8. unreachable server
# --------------------------------------------------------------------------- #

def test_unreachable_server(env, tmp_path):
    # Grab a port with no listener.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()

    zonefile = write_zone(tmp_path / "zone.zone", ZONE_TEXT)
    cmd = [
        sys.executable, "-m", "dnssync", str(zonefile),
        "-s", "127.0.0.1", "-p", str(dead_port), "-z", ZONE,
    ]
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=90, cwd=env.project_root
    )
    assert r.returncode != 0, f"expected failure, got: {r.stdout}"
    # Should surface an error, not crash with a traceback.
    assert "Traceback" not in r.stderr, f"unexpected traceback: {r.stderr}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
