$ORIGIN example.com.
$TTL 3600
@       IN  SOA ns1.example.com. admin.example.com. (
                    2024102001  ; serial
                    3600       ; refresh
                    900        ; retry
                    604800     ; expire
                    86400 )    ; minimum
@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.
@       IN  A   192.168.1.1
www     IN  A   192.168.1.1
mail    IN  A   192.168.1.2
@       IN      MX      10 mail.example.com.