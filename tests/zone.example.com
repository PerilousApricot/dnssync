$TTL 3600
@   IN  SOA ns1.test.com. admin.test.com. (
                2024102001
                3600
                900
                604800
                86400 )
@   IN  NS  ns1.test.com.
www IN  A   192.168.1.1
mail IN A 192.168.1.2