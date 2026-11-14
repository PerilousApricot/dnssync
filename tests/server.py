import socket
import threading
import dns.zone
import dns.update
import dns.rdatatype
import dns.name
import dns.message
import dns.rcode
import dns.rrset
import sys
import dns.rdataclass


class TestDNSServer:
    """Simple in-memory DNS test server for integration testing."""

    def __init__(self, host="127.0.0.1", port=15353, zone_name="example.com."):
        self.host = host
        self.port = port
        self.zone_name = zone_name

        # Create an empty zone
        zone_text = f"$ORIGIN {zone_name}\n$TTL 3600\n@ IN SOA ns1 admin 1 3600 900 604800 300\n@ IN NS ns1"
        self.zone = dns.zone.from_text(zone_text, origin=dns.name.from_text(zone_name))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        print(f"DNS server listening on {host}:{port}")

    def handle_update(self, msg):
        """Process RFC 2136 update operations."""
        for op in msg.update:
            print(f"  [server] Operation: {op.name} {op.rdtype} deleting={op.deleting}")
            if op.deleting == dns.rdatatype.ANY:
                # Delete all records of this type for this name
                try:
                    node = self.zone.nodes[op.name]
                    rdatasets = [r for r in node.rdatasets() if r.rdtype == op.rdtype]
                    for r in rdatasets:
                        node.remove_rdataset(r)
                    print(f"  [server] Deleted all {op.rdtype} for {op.name}")
                except KeyError:
                    print(f"  [server] No node for {op.name}")
            elif op.deleting is not None:
                # Delete specific records
                try:
                    node = self.zone.nodes[op.name]
                    rdataset = node.get_rdataset(dns.rdataclass.IN, op.rdtype)
                    if rdataset is not None:
                        for rdata in op:
                            rdataset.discard(rdata)
                        print(f"  [server] Deleted specific {op.rdtype} for {op.name}")
                except KeyError:
                    print(f"  [server] No rdataset for {op.name} {op.rdtype}")
            else:
                # Add records
                try:
                    node = self.zone.nodes[op.name]
                except KeyError:
                    node = self.zone.node_factory()
                    self.zone.nodes[op.name] = node
                    print(f"  [server] Created node for {op.name}")
                try:
                    rdataset = node.get_rdataset(dns.rdataclass.IN, op.rdtype)
                    if rdataset is None:
                        rdataset = dns.rrset.RRset(
                            op.name, dns.rdataclass.IN, op.rdtype
                        )
                        rdataset.ttl = op.ttl
                        node.add_rdataset(rdataset)
                        print(f"  [server] Created rdataset for {op.name} {op.rdtype}")
                    for rdata in op:
                        rdataset.add(rdata)
                    print(f"  [server] Added records for {op.name} {op.rdtype}")
                except Exception as e:
                    print(f"  [server] Error adding: {e}")

    def handle_request(self, data, addr):
        try:
            msg = dns.message.from_wire(data)
            if msg.opcode() == dns.opcode.UPDATE:
                print(f"  [server] Update from {addr}")
                self.handle_update(msg)
                resp = dns.message.make_response(msg)
                resp.rcode = dns.rcode.NOERROR
                return resp.to_wire()
            else:
                print(f"  [server] Query from {addr}: {msg.question}")
                resp = dns.message.make_response(msg)
                if msg.question:
                    qname = msg.question[0].qname
                    qtype = msg.question[0].qtype
                    try:
                        node = self.zone.nodes[qname]
                        for rdataset in node.rdatasets():
                            if rdataset.rdtype == qtype:
                                resp.answer.append(rdataset)
                                print(f"  [server] Found {qname} {qtype}")
                    except KeyError:
                        print(f"  [server] No node for {qname}")
                return resp.to_wire()
        except Exception as e:
            print(f"  [server] Error: {e}", file=sys.stderr)
            try:
                resp = dns.message.make_response(dns.message.from_wire(data))
                resp.rcode = dns.rcode.SERVFAIL
                return resp.to_wire()
            except Exception:
                return None

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                resp = self.handle_request(data, addr)
                if resp:
                    self.sock.sendto(resp, addr)
            except Exception as e:
                print(f"  [server] Error: {e}", file=sys.stderr)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.sock.close()
