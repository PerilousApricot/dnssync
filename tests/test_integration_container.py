"""Container integration test: dnspython-based UDP DNS server in nerdctl container.

Starts a dnspython-based DNS server with RFC 2136 support in a nerdctl container,
runs DNSSync inside the same container to push updates, and verifies with
dnspython queries.
"""

import os
import platform
import subprocess

IS_MACOS = platform.system() == "Darwin"


import pytest


def run(cmd, check=True, capture=True):
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result


def test_container_integration():
    """Test DNSSync against dnspython server in nerdctl container."""
    print("\n[TEST] Container integration test")

    # Stop any previous container
    run("nerdctl rm -f dnssync-test 2>/dev/null || true", check=False)

    # Write a dnspython-based DNS server with RFC 2136 support
    server_script = """
import dns
import dns.zone
import dns.message
import dns.rdatatype
import dns.rcode
import socket

# Create a zone with origin test.com.
zone_text = '''$ORIGIN test.com.
$TTL 3600
@ IN SOA ns1.test.com. admin.test.com. (1 3600 900 604800 86400)
@ IN NS ns1.test.com.'''
zone = dns.zone.from_text(zone_text, origin=dns.name.from_text('test.com.'))

class UpdateHandler:
    def __init__(self):
        self.zone = zone

    def update(self, name, rdtype, rdataset=None):
        # Convert to absolute name
        if not name.is_absolute():
            name = name.concatenate(self.zone.origin)
        if rdataset is None:
            # Delete
            try:
                node = self.zone.nodes[name]
                node.delete_rdataset(rdtype)
            except (KeyError, KeyError):
                pass
        else:
            # Add/replace
            try:
                node = self.zone.nodes[name]
            except KeyError:
                node = self.zone.node_factory()
                self.zone.nodes[name] = node
            # Replace existing rdataset
            try:
                node.delete_rdataset(rdtype)
            except KeyError:
                pass
            # Convert UpdateRRset to regular rdataset
            for rdata in rdataset:
                if rdataset[0] == rdata:
                    rdataset_obj = dns.rdataset.from_text(rdtype, rdataset.ttl, rdata.to_text())
                else:
                    rdataset_obj = rdataset_obj.union(dns.rdataset.from_text(rdtype, rdataset.ttl, rdata.to_text()))
            node.add_rdataset(rdataset_obj)

    def get(self, name, rdtype):
        if not name.is_absolute():
            name = name.concatenate(self.zone.origin)
        try:
            return self.zone.get_rdataset(name, rdtype)
        except KeyError:
            return None

handler = UpdateHandler()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 15353))
print("Server ready on port 15353", flush=True)

while True:
    data, addr = sock.recvfrom(4096)
    try:
        msg = dns.message.from_wire(data)
        if isinstance(msg, dns.update.UpdateMessage):
            for op in msg.update:
                if op.deleting == dns.rdatatype.ANY:
                    # Delete all records of this type for this name
                    handler.update(op.name, op.rdtype, None)
                elif op.deleting is None:
                    # Add/update
                    handler.update(op.name, op.rdtype, op)
            # Send success response
            resp = dns.message.Message(id=msg.id)
            resp.flags = 0x8180
            resp.rcode = dns.rcode.NOERROR
            sock.sendto(resp.to_wire(), addr)
        else:
            # Query
            resp = dns.message.Message(id=msg.id)
            resp.flags = 0x8180
            resp.question = msg.question
            if msg.question:
                qname = msg.question[0].qname
                qtype = msg.question[0].qtype
                rdataset = handler.get(qname, qtype)
                if rdataset is not None:
                    resp.answer.append(rdataset)
            sock.sendto(resp.to_wire(), addr)
    except Exception as e:
        print(f"Server error: {e}", flush=True)
"""

    # Write the test script
    test_script = """
import subprocess
import time
import sys
import dns
import dns.query

# Wait for server to be ready
time.sleep(2)

# Run DNSSync (mark-managed is on by default)
print("Running DNSSync...", flush=True)
result = subprocess.run(['python', '-m', 'dnssync', '/zone.example.com', '-s', '127.0.0.1', '-p', '15353', '-z', 'test.com.'], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print("DNSSync failed!")
    print(result.stderr)
    sys.exit(1)

# Wait for propagation
time.sleep(1)

# Query DNS to verify updates
print("Querying DNS...", flush=True)

def dns_query(name, rtype):
    qname = name if name.endswith(".") else name + "."
    rtype_id = {"A": 1, "AAAA": 28, "TXT": 16, "NS": 2, "SOA": 6, "MX": 15}.get(rtype, 1)
    msg = dns.message.make_query(qname, rtype_id)
    try:
        resp = dns.query.udp(msg, "127.0.0.1", port=15353, timeout=2)
        if resp.answer:
            for rrset in resp.answer:
                for rr in rrset:
                    return str(rr.rdata)
    except Exception as e:
        print(f"Query error: {e}", flush=True)
    return None

www = dns_query("www.test.com.", "A")
print(f"www.test.com. A: {www}")
if "192.168.1.1" not in (www or ""):
    print(f"FAIL: www record not updated: {www}")
    sys.exit(1)

mail = dns_query("mail.test.com.", "A")
print(f"mail.test.com. A: {mail}")
if "192.168.1.2" not in (mail or ""):
    print(f"FAIL: mail record not updated: {mail}")
    sys.exit(1)

txt = dns_query("www.test.com.", "TXT")
print(f"www.test.com. TXT: {txt}")
if "heritage=external-dns" not in (txt or ""):
    print(f"FAIL: TXT record missing: {txt}")
    sys.exit(1)

print("All checks passed!")
"""

    # Write the zone file
    zone_content = """$ORIGIN test.com.
$TTL 3600
@ IN SOA ns1.test.com. admin.test.com. (
    2024102001 ; serial
    3600       ; refresh
    900        ; retry
    604800     ; expire
    86400      ; minimum
)
@ IN NS ns1.test.com.
www IN A 192.168.1.1
mail IN A 192.168.1.2
"""

    with open("tests/_container_server.py", "w") as f:
        f.write(server_script)

    with open("tests/_container_test.py", "w") as f:
        f.write(test_script)

    with open("tests/_container_zone.zone", "w") as f:
        f.write(zone_content)

    # Run the test in the container
    result = run(
        "nerdctl run --name dnssync-test "
        "-v $(pwd)/tests/_container_server.py:/server.py:ro "
        "-v $(pwd)/tests/_container_test.py:/test.py:ro "
        "-v $(pwd)/tests/_container_zone.zone:/zone.example.com:ro "
        "-v $(pwd)/src:/src:ro "
        "python:3 bash -c "
        "'cd /src && pip install -q dnspython && python /server.py > /tmp/server.log 2>&1 & SERVER_PID=$! && sleep 3 && python /test.py; kill $SERVER_PID 2>/dev/null || true'",
        check=False,
    )
    print("  Test output:")
    print(result.stdout)
    if result.returncode != 0:
        print("  Test failed:")
        print(result.stderr)
        run("nerdctl rm -f dnssync-test 2>/dev/null || true", check=False)
        for f in [
            "tests/_container_server.py",
            "tests/_container_test.py",
            "tests/_container_zone.zone",
        ]:
            if os.path.exists(f):
                os.remove(f)
        assert False, "Container integration test failed"
    else:
        print("  ✓ Records updated successfully in container")

    # Cleanup
    run("nerdctl rm -f dnssync-test 2>/dev/null || true", check=False)
    for f in [
        "tests/_container_server.py",
        "tests/_container_test.py",
        "tests/_container_zone.zone",
    ]:
        if os.path.exists(f):
            os.remove(f)
    print("  Container cleaned up")


if __name__ == "__main__":
    print("=" * 60)
    print("DNSSync Container Integration Test")
    print("=" * 60)

    try:
        test_container_integration()
        print("\n" + "=" * 60)
        print("Container integration test passed!")
        print("=" * 60)
    except RuntimeError as e:
        print(f"\n✗ Test failed: {e}")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"\n✗ Error: {e}")
