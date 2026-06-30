# FTL-DoT

Fork of [pi-hole/FTL](https://github.com/pi-hole/FTL) with native **DNS-over-TLS** (RFC 7858) support.

mbedTLS is already compiled into FTL for the web server — this fork reuses it to add a synchronous TCP+TLS upstream path directly inside the DNS forwarder (`dnsmasq/forward.c`). No extra process, no sidecar, no unbound.

## Usage

Set `FTLCONF_dns_upstreams` with `tls://ip#port#tls-hostname`:

```
tls://8.8.8.8#853#dns.google;tls://8.8.4.4#853#dns.google
```

Multiple upstreams semicolon-separated. Any RFC 7858 compliant server works — see [ismkdc/docker-pihole-dot](https://github.com/ismkdc/docker-pihole-dot) for the ready-to-use Docker image.

## Benchmark

Native DoT vs unbound+pihole forwarding to the same provider. 60 uncached queries each.

| Resolver | avg | p50 | p95 | p99 |
|---|---|---|---|---|
| **★ Native DoT → Google** | 11.7ms | 11.5ms | 16.8ms | **17.4ms** |
| Unbound+Pihole → Google DoT | 11.1ms | 9.4ms | 17.5ms | 51.8ms |
| **★ Native DoT → Cloudflare** | 14.7ms | 14.5ms | 19.0ms | **22.6ms** |
| Unbound+Pihole → Cloudflare DoT | 12.2ms | 10.8ms | 22.4ms | 54.7ms |
| **★ Native DoT → Quad9** | 15.4ms | 15.0ms | 19.2ms | **24.8ms** |
| Unbound+Pihole → Quad9 DoT | 12.1ms | 11.5ms | 16.3ms | 40.3ms |

p99 tail latency is 2–3× better with native DoT. The pihole→unbound IPC hop causes spikes (40–55ms at p99) that native DoT avoids.

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

TLS 1.3 servers send a `NewSessionTicket` message immediately after the handshake — before the first DNS response. mbedTLS 4.x returns `MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET` (-0x7B00) from `mbedtls_ssl_read()` for this event. Without handling it, every first query after a fresh TLS connection fails silently. Fixed in `src/dnsmasq/tls.c` by treating this as a retry signal.

## Releases

Pre-built binaries for all 5 architectures on the [Releases](https://github.com/ismkdc/FTL-DoT/releases) page, auto-downloaded by the Docker image.

| Binary | Architecture |
|---|---|
| `pihole-FTL-amd64` | x86-64 |
| `pihole-FTL-arm64` | ARM 64-bit |
| `pihole-FTL-armv7` | ARM 32-bit v7 |
| `pihole-FTL-armv6` | ARM 32-bit v6 |
| `pihole-FTL-riscv64` | RISC-V 64-bit |
