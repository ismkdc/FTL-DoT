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
#  include <mbedtls/psa_util.h>
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

/* After TCP connect() succeeds on serv->tcpfd, perform TLS handshake.
 * Returns 0 on success, -1 on failure (caller should close tcpfd). */
int dot_handshake(struct server *serv);

/* Write exactly len bytes of DNS message (2-byte length prefix + payload).
 * sendio[0] = {&length_be, 2}, sendio[1] = {payload, n}
 * Returns 1 on success, 0 on failure. */
int dot_send(struct server *serv, struct iovec *sendio);

/* Read 2-byte length prefix, then read that many bytes into buf.
 * Returns number of bytes read (>0), 0 on EOF, -1 on error. */
int dot_recv_length(struct server *serv, unsigned char *lenbuf);
int dot_recv_payload(struct server *serv, unsigned char *buf, size_t len);

/* Close TLS session gracefully; saves session for resumption.
 * Does NOT close serv->tcpfd (caller does that). */
void dot_close(struct server *serv);

/* Free all TLS resources for this server (called on server removal). */
void dot_server_free(struct server *serv);

/* Log a mbedTLS error code with a message prefix. */
void dot_log_error(const char *prefix, int ret);

#endif /* HAVE_MBEDTLS */
#endif /* TLS_H */
