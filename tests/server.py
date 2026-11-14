"""In-process DNS test server for DNSSync integration/E2E testing.

Implements, over real UDP and TCP sockets, just enough of DNS to exercise the
full DNSSync code path end-to-end:

  * RFC 2136 dynamic UPDATE (UDP)  -- what DNSSync sends
  * AXFR zone transfer (TCP)       -- what DNSSync's get_server_records() uses
  * normal A/AAAA/MX/NS/TXT/SOA queries (UDP) -- for independent verification
  * TSIG authentication (optional) -- HMAC-SHA256, matching DNSSync's updater

The zone is stored in a plain dict ``(absolute_name, rdtype) -> {"ttl", "rdatas"}``
rather than a ``dns.zone`` object, which avoids dnspython's version-sensitive
Node/rdataset API and keeps the update application logic trivially correct.

The server starts with only an SOA and an NS record for the zone origin; every
other record arrives via RFC 2136 updates, exactly like a freshly delegated zone.
"""

import base64
import os
import socket
import struct
import threading

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.rdataclass
import dns.tsig
import dns.rcode
import dns.update  # noqa: F401  (kept for clarity; update ops arrive as msg.update)

_RRTYPE_ANY = 255
_RRTYPE_NONE = 254  # deleting-specific-rdata marker


def _free_port(host="127.0.0.1"):
    """Return a currently-free UDP/TCP port on the loopback interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FullDNSServer:
    """In-memory DNS server supporting UPDATE, AXFR, queries, and TSIG."""

    def __init__(
        self,
        zone_name: str,
        host: str = "127.0.0.1",
        port: int = None,
        tsig_keyname: str = None,
        tsig_secret: str = None,
        ns_name: str = None,
    ):
        self.zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        self.zone_origin = dns.name.from_text(self.zone_name)
        self.host = host
        self.port = port if port is not None else _free_port(host)
        self.ns_name = ns_name or f"ns1.{self.zone_name}"

        # (absolute_name, rdtype) -> {"ttl": int, "rdatas": [Rdata, ...]}
        self.store = {}
        self._lock = threading.Lock()

        # TSIG (optional)
        self.tsig_key = None
        self.tsig_keyname = None
        self._keyring = None
        if tsig_keyname and tsig_secret:
            self.tsig_keyname = tsig_keyname
            # The updater base64-encodes a plaintext secret before handing it to
            # dns.tsig.Key; mirror that here so both sides agree on the raw key.
            b64_secret = self._effective_b64_secret(tsig_secret)
            self.tsig_key = dns.tsig.Key(
                self.tsig_keyname, b64_secret, dns.tsig.HMAC_SHA256
            )
            # Keyring must be keyed by dns.name.Name (not str) for verification.
            self._keyring = {dns.name.from_text(self.tsig_keyname): self.tsig_key}

        # Bootstrap the zone with SOA + NS (everything else arrives via UPDATE)
        self._seed_zone()

        # Sockets: UDP for updates/queries, TCP for AXFR
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((host, self.port))

        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((host, self.port))
        self._tcp.listen(5)

        self._running = True
        self._udp_thread = threading.Thread(target=self._udp_loop, daemon=True)
        self._tcp_thread = threading.Thread(target=self._tcp_loop, daemon=True)
        self._udp_thread.start()
        self._tcp_thread.start()

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _effective_b64_secret(plaintext: str) -> str:
        """Mirror the updater's base64 handling of a TSIG secret."""
        try:
            base64.b64decode(plaintext)
            return plaintext
        except Exception:
            return base64.b64encode(plaintext.encode()).decode()

    def _seed_zone(self):
        zone = self.zone_name
        soa = dns.rrset.from_text(
            zone, 3600, "IN", "SOA",
            f"{self.ns_name} admin.{zone} 1 3600 900 604800 300",
        )
        self._add(self.zone_origin, dns.rdatatype.SOA, 3600, list(soa))
        ns = dns.rrset.from_text(zone, 3600, "IN", "NS", self.ns_name)
        self._add(self.zone_origin, dns.rdatatype.NS, 3600, list(ns))

    def _make_rrset(self, name, rdtype, entry):
        return dns.rrset.from_rdata(name, entry["ttl"], *entry["rdatas"])

    def _add(self, name, rdtype, ttl, rdatas):
        key = (name, rdtype)
        if key in self.store:
            existing = self.store[key]["rdatas"]
            for rd in rdatas:
                if rd not in existing:
                    existing.append(rd)
            self.store[key]["ttl"] = ttl
        else:
            self.store[key] = {"ttl": ttl, "rdatas": list(rdatas)}

    def _delete_type(self, name, rdtype):
        self.store.pop((name, rdtype), None)

    def _delete_all(self, name):
        for key in [k for k in self.store if k[0] == name]:
            del self.store[key]

    def _delete_specific(self, name, rdtype, rdatas):
        key = (name, rdtype)
        if key in self.store:
            keep = [rd for rd in self.store[key]["rdatas"] if rd not in rdatas]
            if keep:
                self.store[key]["rdatas"] = keep
            else:
                del self.store[key]

    # -- update (RFC 2136) ----------------------------------------------

    def _apply_update(self, msg):
        for op in msg.update:
            name = op.name
            rdtype = op.rdtype
            rdatas = list(op)
            deleting = None if op.deleting is None else int(op.deleting)
            if os.environ.get("DNSSYNC_DEBUG"):
                kind = "ADD" if deleting is None else ("DEL-ALL" if int(rdtype)==_RRTYPE_ANY else ("DEL-ONE" if deleting==_RRTYPE_NONE else "DEL-TYPE"))
                print(f"[SRV] {kind:8s} {name} rtype={int(rdtype):3d} rdata={rdatas}", flush=True)

            if deleting is None:
                # ADD
                self._add(name, rdtype, op.ttl, rdatas)
            elif int(rdtype) == _RRTYPE_ANY:
                # Delete every type for this name (covers orphaned heritage TXT)
                self._delete_all(name)
            elif deleting == _RRTYPE_NONE and rdatas:
                # Delete these specific rdatas
                self._delete_specific(name, rdtype, rdatas)
            else:
                # Delete all records of this type for this name
                self._delete_type(name, rdtype)

    # -- request handling ------------------------------------------------

    def _handle_udp(self, data, addr):
        if self._keyring is not None:
            try:
                msg = dns.message.from_wire(data, keyring=self._keyring)
            except dns.tsig.BadSignature:
                return self._error_wire(data, dns.rcode.BADKEY)
            except Exception:
                return self._error_wire(data, dns.rcode.SERVFAIL)
        else:
            msg = dns.message.from_wire(data)

        with self._lock:
            if msg.opcode() == dns.opcode.UPDATE:
                if self.tsig_key is not None and not msg.had_tsig:
                    return self._tsig_error(msg, dns.rcode.REFUSED)
                self._apply_update(msg)
                return self._update_response(msg)
            else:
                return self._query_response(msg)

    def _handle_tcp(self, data):
        # AXFR arrives over TCP. Note: an AXFR *request* has opcode=0 (QUERY)
        # with qtype=AXFR(252) in the question -- so detect by qtype, not opcode.
        msg = dns.message.from_wire(data)
        is_axfr = False
        if msg.question:
            is_axfr = int(msg.question[0].rdtype) == int(dns.rdatatype.AXFR)
        if is_axfr:
            with self._lock:
                return self._axfr_response(msg)
        # Fallback: treat as a normal query
        with self._lock:
            return self._query_response(msg)

    def _update_response(self, msg):
        # make_response echoes the request id, sets QR, and preserves the
        # UPDATE opcode -- all required for the client's is_response() check.
        resp = dns.message.make_response(msg)
        resp.rcode = dns.rcode.NOERROR
        if self.tsig_key is not None:
            # The response MAC must incorporate the request's MAC for the
            # client's TSIG verification to succeed.
            resp.request_mac = msg.mac
            resp.use_tsig(self.tsig_key, fudge=300)
        return resp.to_wire()

    def _tsig_error(self, msg, rcode):
        resp = dns.message.make_response(msg)
        resp.rcode = rcode
        if self.tsig_key is not None:
            # A non-zero tsig_error short-circuits MAC verification on the
            # client (it raises the matching Peer* exception), so the MAC need
            # not be valid -- but a TSIG record must be present.
            if getattr(msg, "mac", None) is not None:
                resp.request_mac = msg.mac
            resp.use_tsig(self.tsig_key, fudge=300, tsig_error=rcode)
        return resp.to_wire()

    def _error_wire(self, data, rcode):
        try:
            msg = dns.message.from_wire(data)
            return self._tsig_error(msg, rcode)
        except Exception:
            return None

    def _query_response(self, msg):
        resp = dns.message.make_response(msg)
        if msg.question:
            q = msg.question[0]
            if int(q.rdtype) == _RRTYPE_ANY:
                for (name, rdtype) in list(self.store.keys()):
                    if name == q.name:
                        resp.answer.append(self._make_rrset(name, rdtype, self.store[(name, rdtype)]))
            else:
                key = (q.name, q.rdtype)
                if key in self.store:
                    resp.answer.append(self._make_rrset(q.name, q.rdtype, self.store[key]))
        return resp.to_wire()

    def _axfr_response(self, msg):
        resp = dns.message.Message()
        resp.id = msg.id
        resp.opcode = dns.opcode.QUERY  # AXFR responses carry opcode=QUERY
        resp.flags = 0x8400
        resp.rcode = dns.rcode.NOERROR
        soa_key = (self.zone_origin, dns.rdatatype.SOA)
        if soa_key in self.store:
            resp.answer.append(self._make_rrset(self.zone_origin, dns.rdatatype.SOA, self.store[soa_key]))
        for (name, rdtype), entry in self.store.items():
            if rdtype != dns.rdatatype.SOA:
                resp.answer.append(self._make_rrset(name, rdtype, entry))
        if soa_key in self.store:
            resp.answer.append(self._make_rrset(self.zone_origin, dns.rdatatype.SOA, self.store[soa_key]))
        return resp.to_wire()

    # -- sockets ---------------------------------------------------------

    def _udp_loop(self):
        while self._running:
            try:
                data, addr = self._udp.recvfrom(65535)
                out = self._handle_udp(data, addr)
                if out:
                    self._udp.sendto(out, addr)
            except OSError:
                break
            except Exception:
                continue

    def _readall(self, conn, n):
        b = b""
        while len(b) < n:
            c = conn.recv(n - len(b))
            if not c:
                break
            b += c
        return b

    def _tcp_loop(self):
        while self._running:
            try:
                conn, _ = self._tcp.accept()
            except OSError:
                break
            try:
                hdr = self._readall(conn, 2)
                if len(hdr) < 2:
                    conn.close()
                    continue
                (length,) = struct.unpack("!H", hdr)
                data = self._readall(conn, length)
                out = self._handle_tcp(data)
                if out:
                    conn.sendall(struct.pack("!H", len(out)) + out)
            except Exception:
                pass
            finally:
                conn.close()

    # -- test helpers ----------------------------------------------------

    def snapshot(self):
        """Return a read-only view of the store as {(name, type): [rdata,...]}."""
        with self._lock:
            return {
                (n.to_text(), dns.rdatatype.to_text(t)): [str(r) for r in e["rdatas"]]
                for (n, t), e in self.store.items()
            }

    def start(self):
        """Already started in __init__; kept for API symmetry."""
        return self

    def stop(self):
        self._running = False
        try:
            self._udp.close()
        except OSError:
            pass
        try:
            self._tcp.close()
        except OSError:
            pass
