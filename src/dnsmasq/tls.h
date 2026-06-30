/* Pi-hole FTL-DoT: native DNS-over-TLS upstream support
 * SPDX-License-Identifier: GPL-2.0-only */

#ifndef TLS_H
#define TLS_H

#ifdef HAVE_MBEDTLS

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

/* mbedTLS 4.x replaced entropy/ctr_drbg with PSA Crypto. */
#if MBEDTLS_VERSION_MAJOR >= 4
#  include <psa/crypto.h>
#else
#  include <mbedtls/entropy.h>
#  include <mbedtls/ctr_drbg.h>
#endif

/* Attached to each struct server that uses DoT.
 * Allocated once on first connect, freed when server is removed. */
struct tls_server_ctx {
  mbedtls_ssl_config   conf;       /* per-server TLS config (CA chain, ALPN, ...) */
  mbedtls_x509_crt     cacert;     /* loaded CA bundle */
  mbedtls_ssl_context  ssl;        /* per-connection SSL context */
  mbedtls_ssl_session  session;    /* saved TLS session for resumption */
  mbedtls_net_context  net;        /* wraps tcpfd for mbedTLS BIO */
  int                  sess_saved; /* 1 if session is valid for resumption */
};

/* Call once from FTL_fork_and_bind_sockets() before dnsmasq starts. */
void dot_global_init(void);

/* Call when a struct server with tls_hostname is first created.
 * Allocates and configures tls_server_ctx; returns -1 on error. */
int dot_server_init(struct server *serv);

/* Synchronous blocking handshake (kept for reference; async path preferred). */
int dot_handshake(struct server *serv);

/* Synchronous blocking send/recv (kept for reference). */
int dot_send(struct server *serv, struct iovec *sendio);
int dot_recv_length(struct server *serv, unsigned char *lenbuf);
int dot_recv_payload(struct server *serv, unsigned char *buf, size_t len);

/* Close TLS session gracefully (does NOT close serv->tcpfd). */
void dot_close(struct server *serv);

/* Free all TLS resources for this server (called on server removal). */
void dot_server_free(struct server *serv);

/* Log a mbedTLS error code with a message prefix. */
void dot_log_error(const char *prefix, int ret);

/* ── Async non-blocking DoT state machine ── */

/* Start an async DoT query for forward frec.
 * Sets serv->dot_state and registers the connection in the poll loop.
 * Returns 0 on success (state machine started), -1 on immediate failure. */
int dot_start(struct server *serv, struct frec *forward,
              const struct dns_header *header, size_t plen);

/* Enqueue a query while the server is in-flight (one slot per server).
 * Copies the DNS packet; frec->sentto must be set by caller on success.
 * Returns 0 on success, -1 if the slot is already taken or malloc fails. */
int dot_enqueue(struct server *serv, struct frec *forward,
                const struct dns_header *header, size_t plen);

/* Advance the state machine when serv->tcpfd is ready.
 * Called from check_dns_listeners() when poll fires for the DoT fd.
 * On completion calls return_reply(); on error cleans up. */
void dot_advance(time_t now, struct server *serv);

/* Abort the async op without delivering a reply (e.g. frec timed out). */
void dot_abort(struct server *serv);

/* Return the poll events to watch for the given dot_state (POLLIN/POLLOUT). */
int dot_poll_events(int state);

#endif /* HAVE_MBEDTLS */
#endif /* TLS_H */
