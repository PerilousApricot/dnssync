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

PORT = 15353
ZONE_NAME = "example.com."

# Create zone from zone file
with open("/etc/bind/db.example.com", "r") as f:
    zone_text = f.read()

zone = dns.zone.from_text(zone_text, origin=dns.name.from_text(ZONE_NAME))
print(f"Zone loaded with {len(list(zone.iterate_rdatas()))} records")


def handle_request(sock, data, addr):
    try:
        msg = dns.message.from_wire(data)
        if isinstance(msg, dns.update.Update):
            # RFC 2136 update
            zone.apply(msg.update)
            resp = msg.response()
            resp.rcode = dns.rcode.NOERROR
            return resp.to_wire()
        else:
            # Standard query
            resp = msg.response()
            if msg.question:
                qname = msg.question[0].qname
                qtype = msg.question[0].qtype
                try:
                    rdataset = zone.get_rdataset(qname, qtype)
                    for rdata in rdataset:
                        rr = dns.rr.RR(qname, qtype, 0, rdataset.ttl, rdata)
                        resp.answer.append(rr)
                except (dns.zone.NoRRset, KeyError):
                    pass
            return resp.to_wire()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        try:
            # Send a basic error response
            resp = dns.message.make_response(msg)
            resp.rcode = dns.rcode.SERVFAIL
            return resp.to_wire()
        except:
            return None


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", PORT))
print(f"DNS server listening on 0.0.0.0:{PORT}")

while True:
    try:
        data, addr = sock.recvfrom(4096)
        resp = handle_request(sock, data, addr)
        if resp:
            sock.sendto(resp, addr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
