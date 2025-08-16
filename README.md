## A DOH DNS forwarder

# 支持参数和默认值

```
"listen", ":8053", "UDP listen address for DNS (e.g. :53, 127.0.0.1:8053)"
"u", "", "DoH URL, e.g. https://example.com/dns-query"
"host", "", "override Host header & TLS SNI (e.g. doh.example.com)"
"connect", "", "connect to this addr (host:port, still use -u for scheme/path"
"http1", false, "force HTTP/1.1 (disable h2, conservative mode)"
"ua", "mosdns-x/4.6.0", "User-Agent to send"
"insecure", false, "skip TLS certificate verification (NOT recommended)"
"ecs4", "", "ECS IPv4 CIDR, e.g. 203.0.113.0/24 (overrides client)"
"ecs6", "", "ECS IPv6 CIDR, e.g. 2001:db8::/56 (overrides client)"
"ecs-auto", false, "derive ECS from client source IP (/24 for v4, /56 for v6; tunable via -ecs4mask/-ecs6mask)"
"ecs4mask", 24, "mask to use when -ecs-auto and client is IPv4"
"ecs6mask", 56, "mask to use when -ecs-auto and client is IPv6"
"respect-client-ecs", true, "if client sent ECS, keep it (true or override with our ECS (false))"
"do", false, "set DO (DNSSEC OK bit when adding EDNS (does not remove client DO if present)"
"pad", 0, "EDNS padding target block size (0=disable)"
"cookie", "", "EDNS cookie (hex, 8+ bytes; client cookie uses first 8 bytes"
"edns-size", 1232, "EDNS0 UDP payload size upper bound (default 1232)"
"t", 6*time.Second, "per-query DoH timeout"
"udp-buf", 4096, "UDP read buffer size"
"logq", false, "log queries and upstream results"
```
