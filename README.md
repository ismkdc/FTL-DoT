# FTL-DoT

Fork of [pi-hole/FTL](https://github.com/pi-hole/FTL) adding native **DNS-over-TLS** (RFC 7858) support.

## What's different

- `tls://ip#port#hostname` format in `FTLCONF_dns_upstreams`
- Synchronous TCP+TLS forwarding in `src/dnsmasq/forward.c`
- mbedTLS 4.x with ALPN "dot", TLS 1.2+, cert verification
- TLS session persistence (one handshake per upstream, reused across queries)
- All 5 platforms: amd64, arm64, armv7, armv6, riscv64

## Key bug fixed during development

TLS 1.3 servers send `NewSessionTicket` post-handshake. mbedTLS 4.x returns
`MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET` (-0x7B00) from `mbedtls_ssl_read()` —
not an error. Without handling this, every first DNS query after a fresh TLS
connection failed. Fixed in `src/dnsmasq/tls.c`.

## Usage

See [ismkdc/docker-pihole-dot](https://github.com/ismkdc/docker-pihole-dot) for the Docker image.

```yaml
# docker-compose.yml
environment:
  FTLCONF_dns_upstreams: 'tls://8.8.8.8#853#dns.google;tls://8.8.4.4#853#dns.google'
```

## Building

```bash
# Alpine 3.24+
apk add build-base cmake mbedtls-dev mbedtls-static libcap-dev nettle-dev \
        lua5.4-dev sqlite-dev libevent-dev libidn2-dev libunistring-dev readline-dev

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSTATIC=false
make -j$(nproc) pihole-FTL
```

## Releases

Pre-built binaries for all 5 architectures are published on the
[Releases](https://github.com/ismkdc/FTL-DoT/releases) page and downloaded
automatically by the Docker image.

---

<!-- upstream pi-hole/FTL README below -->
<p align="center">
  <a href="https://pi-hole.net/">
    <img src="https://raw.githubusercontent.com/pi-hole/graphics/refs/heads/master/Vortex/vortex_with_text.svg" alt="Pi-hole logo" width="80" height="128">
  </a>
  <br>
  <strong>Network-wide ad blocking via your own Linux hardware</strong>
  <br>
  <br>
  <a href="https://pi-hole.net/">
    <img src="https://raw.githubusercontent.com/pi-hole/graphics/refs/heads/master/FTLDNS/FTLDNS.svg" alt="FTLDNS logo" width="500" height="128">
  </a>
</p>

FTLDNS (`pihole-FTL`) provides an interactive API and also generates statistics for Pi-hole[®](https://pi-hole.net/trademark-rules-and-brand-guidelines/)'s Web interface.

- **Fast**: stats are read directly from memory by coupling our codebase closely with `dnsmasq`
- **Versatile**: upstream changes to `dnsmasq` can quickly be merged in without much conflict
- **Lightweight**: runs smoothly with [minimal hardware and software requirements](https://discourse.pi-hole.net/t/hardware-software-requirements/273) such as Raspberry Pi Zero
- **Interactive**: our API can be used to interface with your projects
- **Insightful**: stats normally reserved inside of `dnsmasq` are made available so you can see what's really happening on your network

## Official documentation

The official *FTL*DNS documentation can be found [here](https://docs.pi-hole.net/ftldns/).

## Installation

FTLDNS (`pihole-FTL`) is automatically installed when installing Pi-hole.

### IMPORTANT

>FTLDNS will *disable* any existing installations of `dnsmasq`. This is because FTLDNS *is* `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.
