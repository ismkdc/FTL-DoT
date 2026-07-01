# FTL-DoT

Fork of [pi-hole/FTL](https://github.com/pi-hole/FTL) with native **DNS-over-TLS** (RFC 7858) support.

Not affiliated with or endorsed by the official Pi-hole project. "Pi-hole" is a trademark of Pi-hole LLC.

mbedTLS is already compiled into FTL for the web server, this fork reuses it to add a synchronous TCP+TLS upstream path directly inside the DNS forwarder (`dnsmasq/forward.c`). No extra process, no sidecar, no unbound.

## Usage

Set `FTLCONF_dns_upstreams` with `tls://ip#port#tls-hostname`:

```
tls://8.8.8.8#853#dns.google;tls://8.8.4.4#853#dns.google
```

Multiple upstreams semicolon-separated. Any RFC 7858 compliant server works, see [ismkdc/docker-pihole-dot](https://github.com/ismkdc/docker-pihole-dot) for the ready-to-use Docker image.

## Building

```bash
# Alpine 3.24
apk add build-base cmake mbedtls-dev mbedtls-static libcap-dev nettle-dev \
        lua5.4-dev sqlite-dev libevent-dev libidn2-dev libunistring-dev readline-dev

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSTATIC=false
make -j$(nproc) pihole-FTL
```

## Key implementation detail

TLS 1.3 servers send a `NewSessionTicket` message immediately after the handshake, before the first DNS response. mbedTLS 4.x returns `MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET` (-0x7B00) from `mbedtls_ssl_read()` for this event. Without handling it, every first query after a fresh TLS connection fails silently. Fixed in `src/dnsmasq/tls.c` by treating this as a retry signal.

## Releases

Pre-built binaries for all 5 architectures on the [Releases](https://github.com/ismkdc/FTL-DoT/releases) page, auto-downloaded by the Docker image.

| Binary | Architecture |
|---|---|
| `pihole-FTL-amd64` | x86-64 |
| `pihole-FTL-arm64` | ARM 64-bit |
| `pihole-FTL-armv7` | ARM 32-bit v7 |
| `pihole-FTL-armv6` | ARM 32-bit v6 |
| `pihole-FTL-riscv64` | RISC-V 64-bit |
