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
 * Allocated once on first connect, freed when server is removed.
 * Used only by the synchronous blocking path below (TCP-fallback for
 * truncated UDP replies); the async pooled-connection path uses
 * struct dot_shared_ctx / struct dot_async_ctx instead. */
struct tls_server_ctx {
  mbedtls_ssl_config   conf;       /* per-server TLS config (CA chain, ALPN, ...) */
  mbedtls_x509_crt     cacert;     /* loaded CA bundle */
  mbedtls_ssl_context  ssl;        /* per-connection SSL context */
  mbedtls_ssl_session  session;    /* saved TLS session for resumption */
  mbedtls_net_context  net;        /* wraps tcpfd for mbedTLS BIO */
  int                  sess_saved; /* 1 if session is valid for resumption */
};

/* Per-server TLS config shared by every pooled async connection
 * (struct server.dot_conn[]): CA chain, ALPN, and the most recently saved
 * session ticket for resumption. Allocated once on first use, freed when
 * the server is removed. */
struct dot_shared_ctx {
  mbedtls_ssl_config   conf;
  mbedtls_x509_crt     cacert;
  mbedtls_ssl_session  session;
  int                  sess_saved;
};

/* Per-pooled-connection mbedTLS state (struct server.dot_conn[i].actx).
 * One TCP socket = one of these; reset and reused across reconnects. */
struct dot_async_ctx {
  mbedtls_ssl_context  ssl;
  mbedtls_net_context  net;
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

/* Close TLS session gracefully (does NOT close serv->tcpfd). Used only by
 * the synchronous TCP-fallback path (dot_handshake/dot_send/dot_recv_*);
 * the async pool closes its own pooled connections internally in tls.c. */
void dot_close(struct server *serv);

/* Free all TLS resources for this server (called on server removal):
 * the synchronous tls_ctx, the shared async config, and every pooled
 * connection's per-connection context. */
void dot_server_free(struct server *serv);

/* Log a mbedTLS error code with a message prefix. */
void dot_log_error(const char *prefix, int ret);

/* ── Async non-blocking DoT state machine (pipelined connection pool) ─────
 *
 * Each upstream DoT server keeps a small pool of DOT_CONN_MAX concurrent
 * TCP+TLS connections (struct server.dot_conn[]). Once a connection is
 * established, it pipelines up to DOT_JOB_MAX queries at once (RFC 7766)
 * instead of serializing every query behind its own send-then-receive
 * round trip — replies are demultiplexed off the stream by the 16-bit DNS
 * transaction ID, the same mechanism dnsmasq already uses to correlate
 * multiple outstanding plain-UDP queries. Queries that find every pooled
 * connection's pipeline full fall into a shared per-server overflow queue
 * (struct server.dot_pending[]) and are drained as job slots free up. */

/* Start an async DoT query for forward frec: reuses an existing connected
 * pipeline with room, or starts a new pooled connection if needed. Returns
 * 0 on success, -1 if every connection's pipeline is full — the caller
 * should fall back to dot_enqueue(). */
int dot_start(struct server *serv, struct frec *forward,
              const struct dns_header *header, size_t plen);

/* Enqueue a query when every pooled connection's pipeline is full. Copies
 * the DNS packet; frec->sentto must be set by caller on success. Returns 0
 * on success, -1 if the overflow queue is also full or malloc fails. */
int dot_enqueue(struct server *serv, struct frec *forward,
                const struct dns_header *header, size_t plen);

/* Advance connection dot_conn[conn_idx]'s state machine when its tcpfd is
 * ready: flushes any queued-but-unsent jobs, then drains every complete
 * response already available (looping internally, not just one per call)
 * delivering each via return_reply(). On a connection-level error, fails
 * and either requeues (unsent) or drops (already sent) every job it held. */
void dot_advance(time_t now, struct server *serv, int conn_idx);

/* Remove any job or overflow-queue entry belonging to frec f, on any DoT
 * server, without disturbing other jobs on the same connection. Called
 * from forward.c's free_frec() when a frec expires (e.g. client gave up
 * waiting) so a later reply for it is safely discarded instead of
 * dereferencing a freed frec. */
void dot_gc_frec(struct frec *f);

/* Return the poll events to watch for dot_conn[conn_idx] (POLLIN/POLLOUT). */
int dot_poll_events(struct server *serv, int conn_idx);

#endif /* HAVE_MBEDTLS */
#endif /* TLS_H */
