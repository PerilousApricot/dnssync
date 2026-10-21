"""Test zone file parsing."""

import pytest
from dnssync.parser import parse_zone_file


def test_parse_zone_file(tmp_path):
    zone = tmp_path / "test.zone"
    zone.write_text("""$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
                    2024102001  ; serial
                    3600       ; refresh
                    900        ; retry
                    604800     ; expire
                    86400 )    ; minimum
@   IN  NS  ns1.example.com.
@   IN  A   192.168.1.1
www IN  A   192.168.1.2
mail IN A 192.168.1.3
""")

    records = parse_zone_file(str(zone), "example.com.")

    # Expect 3 A records, 1 NS, 1 SOA
    a_records = [r for r in records if r.type == "A"]
    assert len(a_records) == 3

    names = {r.name: r.data for r in a_records}
    assert names.get("example.com.") == "192.168.1.1"
    assert names.get("www.example.com.") == "192.168.1.2"
    assert names.get("mail.example.com.") == "192.168.1.3"
