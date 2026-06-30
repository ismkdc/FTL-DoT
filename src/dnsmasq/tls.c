/* Pi-hole FTL-DoT: native DNS-over-TLS upstream support (RFC 7858)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Design:
 *  - mbedTLS is already linked into FTL for the web server; we reuse it.
 *  - mbedTLS 3.x: global entropy + CTR-DRBG RNG (thread-safe via mutex).
 *  - mbedTLS 4.x: PSA Crypto replaces entropy/drbg; thread-safe natively.
 *  - Per-server: tls_server_ctx holds ssl_config (CA chain, ALPN, TLS ver)
 *    and ssl_session for resumption.  These persist as long as the server exists.
 *  - Per-connection: ssl_context and net_context are reset on each new TCP
 *    connection but reuse the per-server config.  Session resumption avoids the
 *    full handshake RTT on reconnect.
 *  - I/O is non-blocking: TCP socket is O_NONBLOCK; mbedTLS WANT_READ/WANT_WRITE
 *    are handled by returning to the poll loop (dot_advance is re-entered when
 *    the fd is ready).  This keeps the dnsmasq event loop responsive.
 */

#ifdef HAVE_MBEDTLS

#include "dnsmasq.h"
#include "tls.h"
#include "dnsmasq_interface.h"

#include <fcntl.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <string.h>
#include <errno.h>

#if MBEDTLS_VERSION_MAJOR >= 4
#  include <psa/crypto.h>
#else
#  include <mbedtls/entropy.h>
#  include <mbedtls/ctr_drbg.h>
#  include <pthread.h>
#endif

/* System CA bundle path (Alpine / Debian / OpenWrt all ship this). */
#ifndef DOT_CA_BUNDLE
#  define DOT_CA_BUNDLE "/etc/ssl/cert.pem"
#endif
#ifndef DOT_CA_BUNDLE2
#  define DOT_CA_BUNDLE2 "/etc/ssl/certs/ca-certificates.crt"
#endif

/* Maximum retries on WANT_READ / WANT_WRITE before declaring I/O failure. */
#define DOT_IO_RETRIES 5

/* ALPN token required by RFC 7858 §4. */
static const char *dot_alpn[] = { "dot", NULL };

/* ── Global state ──────────────────────────────────────────────────────── */

static int g_initialized = 0;

#if MBEDTLS_VERSION_MAJOR < 4
static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static pthread_mutex_t          g_rng_lock = PTHREAD_MUTEX_INITIALIZER;

static int dot_rng(void *p_rng, unsigned char *output, size_t len)
{
  (void)p_rng;
  int ret;
  pthread_mutex_lock(&g_rng_lock);
  ret = mbedtls_ctr_drbg_random(&g_ctr_drbg, output, len);
  pthread_mutex_unlock(&g_rng_lock);
  return ret;
}
#endif

void dot_global_init(void)
{
  if (g_initialized)
    return;

#if MBEDTLS_VERSION_MAJOR >= 4
  psa_status_t psa_ret = psa_crypto_init();
  if (psa_ret != PSA_SUCCESS)
    {
      my_syslog(LOG_ERR, "DoT: psa_crypto_init() failed (%d)", (int)psa_ret);
      return;
    }
#else
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_ctr_drbg);

  const unsigned char seed[] = "pihole-ftl-dot";
  int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
                                   &g_entropy, seed, sizeof(seed) - 1);
  if (ret != 0)
    {
      dot_log_error("DoT: RNG seed failed", ret);
      return;
    }
#endif

  g_initialized = 1;
  my_syslog(LOG_INFO, "DoT: global TLS context initialized (mbedTLS %d.%d)",
            MBEDTLS_VERSION_MAJOR, MBEDTLS_VERSION_MINOR);
}

/* ── Per-server init ───────────────────────────────────────────────────── */

int dot_server_init(struct server *serv)
{
  if (!g_initialized)
    {
      my_syslog(LOG_ERR, "DoT: dot_global_init() not called");
      return -1;
    }

  struct tls_server_ctx *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      my_syslog(LOG_ERR, "DoT: out of memory");
      return -1;
    }

  mbedtls_ssl_config_init(&ctx->conf);
  mbedtls_x509_crt_init(&ctx->cacert);
  mbedtls_ssl_init(&ctx->ssl);
  mbedtls_net_init(&ctx->net);
  ctx->sess_saved = 0;

  /* Load CA bundle. */
  int ret = mbedtls_x509_crt_parse_file(&ctx->cacert, DOT_CA_BUNDLE);
  if (ret != 0)
    {
      ret = mbedtls_x509_crt_parse_file(&ctx->cacert, DOT_CA_BUNDLE2);
      if (ret != 0)
        {
          dot_log_error("DoT: failed to load CA bundle", ret);
          goto fail;
        }
    }

  /* TLS client defaults. */
  ret = mbedtls_ssl_config_defaults(&ctx->conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0)
    {
      dot_log_error("DoT: ssl_config_defaults failed", ret);
      goto fail;
    }

  /* Require valid certificate (RFC 7858 §4). */
  mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, NULL);

  /* RNG: mbedTLS 4.x uses PSA internally — no explicit conf needed.
   * mbedTLS 3.x requires an explicit callback. */
#if MBEDTLS_VERSION_MAJOR < 4
  mbedtls_ssl_conf_rng(&ctx->conf, dot_rng, NULL);
#endif

  /* Minimum TLS 1.2; constant was renamed in mbedTLS 4.x. */
#if MBEDTLS_VERSION_MAJOR >= 4
  mbedtls_ssl_conf_min_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
  mbedtls_ssl_conf_min_tls_version(&ctx->conf, MBEDTLS_TLS_VERSION_1_2);
#endif

  /* ALPN "dot" as required by RFC 7858. */
  ret = mbedtls_ssl_conf_alpn_protocols(&ctx->conf, dot_alpn);
  if (ret != 0)
    {
      dot_log_error("DoT: ALPN setup failed", ret);
      goto fail;
    }

  serv->tls_ctx = ctx;
  my_syslog(LOG_DEBUG|MS_DEBUG, "DoT: server %s TLS context ready",
            serv->tls_hostname);
  return 0;

fail:
  mbedtls_ssl_free(&ctx->ssl);
  mbedtls_x509_crt_free(&ctx->cacert);
  mbedtls_ssl_config_free(&ctx->conf);
  mbedtls_net_free(&ctx->net);
  free(ctx);
  return -1;
}

/* ── Per-connection: handshake ─────────────────────────────────────────── */

int dot_handshake(struct server *serv)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (!ctx)
    {
      if (dot_server_init(serv) != 0)
        return -1;
      ctx = serv->tls_ctx;
    }

  mbedtls_ssl_free(&ctx->ssl);
  mbedtls_ssl_init(&ctx->ssl);

  int ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
  if (ret != 0)
    {
      dot_log_error("DoT: ssl_setup failed", ret);
      return -1;
    }

  ret = mbedtls_ssl_set_hostname(&ctx->ssl, serv->tls_hostname);
  if (ret != 0)
    {
      dot_log_error("DoT: set_hostname failed", ret);
      return -1;
    }

  ctx->net.fd = serv->tcpfd;
  mbedtls_ssl_set_bio(&ctx->ssl, &ctx->net,
                      mbedtls_net_send, mbedtls_net_recv, NULL);

  if (ctx->sess_saved)
    mbedtls_ssl_set_session(&ctx->ssl, &ctx->session);

  int tries = 0;
  while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0)
    {
      if ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE) && ++tries < DOT_IO_RETRIES)
        continue;
      dot_log_error("DoT: handshake failed", ret);
      return -1;
    }

  if (!ctx->sess_saved)
    mbedtls_ssl_session_init(&ctx->session);
  ret = mbedtls_ssl_get_session(&ctx->ssl, &ctx->session);
  ctx->sess_saved = (ret == 0) ? 1 : 0;

  /* RFC 7858 §4: server MUST negotiate ALPN "dot". */
  const char *alpn = mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
  if (!alpn || strcmp(alpn, "dot") != 0)
    {
      my_syslog(LOG_ERR, "DoT: server %s did not negotiate ALPN 'dot' (got: %s) — aborting",
                serv->tls_hostname, alpn ? alpn : "none");
      return -1;
    }
  my_syslog(LOG_DEBUG|MS_DEBUG,
            "DoT: TLS handshake OK with %s (resumed=%d, ALPN=dot)",
            serv->tls_hostname, ctx->sess_saved);
  return 0;
}

/* ── Per-connection: I/O ───────────────────────────────────────────────── */

int dot_send(struct server *serv, struct iovec *sendio)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;

  size_t total = sendio[0].iov_len + sendio[1].iov_len;
  unsigned char *buf = malloc(total);
  if (!buf)
    return 0;
  memcpy(buf, sendio[0].iov_base, sendio[0].iov_len);
  memcpy(buf + sendio[0].iov_len, sendio[1].iov_base, sendio[1].iov_len);

  size_t sent = 0;
  int ok = 1;
  while (sent < total)
    {
      int tries = 0;
      int ret;
      while ((ret = mbedtls_ssl_write(&ctx->ssl, buf + sent, total - sent)) <= 0)
        {
          if ((ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
               ret == MBEDTLS_ERR_SSL_WANT_READ) && ++tries < DOT_IO_RETRIES)
            continue;
          dot_log_error("DoT: ssl_write failed", ret);
          ok = 0;
          goto done;
        }
      sent += (size_t)ret;
    }

done:
  free(buf);
  return ok;
}

int dot_recv_length(struct server *serv, unsigned char *lenbuf)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  size_t got = 0;
  while (got < 2)
    {
      int tries = 0;
      int ret;
      while ((ret = mbedtls_ssl_read(&ctx->ssl, lenbuf + got, 2 - got)) <= 0)
        {
          if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
            return 0;
          /* TLS 1.3: server may send NewSessionTicket before the DNS reply;
           * mbedTLS surfaces this as RECEIVED_NEW_SESSION_TICKET — not an
           * error, but count it against retries to avoid an infinite loop if
           * a server sends tickets back-to-back indefinitely. */
          if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET && ++tries < DOT_IO_RETRIES)
            continue;
          if ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE) && ++tries < DOT_IO_RETRIES)
            continue;
          dot_log_error("DoT: recv length failed", ret);
          return -1;
        }
      got += (size_t)ret;
    }
  return 2;
}

int dot_recv_payload(struct server *serv, unsigned char *buf, size_t len)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  size_t got = 0;
  while (got < len)
    {
      int tries = 0;
      int ret;
      while ((ret = mbedtls_ssl_read(&ctx->ssl, buf + got, len - got)) <= 0)
        {
          if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
            return (int)got;
          if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET && ++tries < DOT_IO_RETRIES)
            continue;
          if ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE) && ++tries < DOT_IO_RETRIES)
            continue;
          dot_log_error("DoT: recv payload failed", ret);
          return -1;
        }
      got += (size_t)ret;
    }
  return (int)got;
}

/* ── Async non-blocking DoT state machine ──────────────────────────────── */

/* Prepare the mbedTLS ssl context for a new connection on serv->tcpfd.
 * Allocates tls_ctx if needed.  Called once after TCP connect() completes. */
static int dot_nb_handshake_setup(struct server *serv)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (!ctx)
    {
      if (dot_server_init(serv) != 0) return -1;
      ctx = serv->tls_ctx;
    }

  mbedtls_ssl_free(&ctx->ssl);
  mbedtls_ssl_init(&ctx->ssl);

  int ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
  if (ret != 0) { dot_log_error("DoT: ssl_setup", ret); return -1; }

  ret = mbedtls_ssl_set_hostname(&ctx->ssl, serv->tls_hostname);
  if (ret != 0) { dot_log_error("DoT: set_hostname", ret); return -1; }

  ctx->net.fd = serv->tcpfd;
  mbedtls_ssl_set_bio(&ctx->ssl, &ctx->net,
                      mbedtls_net_send, mbedtls_net_recv, NULL);

  if (ctx->sess_saved)
    mbedtls_ssl_set_session(&ctx->ssl, &ctx->session);

  return 0;
}

int dot_poll_events(int state)
{
  (void)state;
  return POLLIN | POLLOUT; /* TLS may flip direction at any time */
}

int dot_start(struct server *serv, struct frec *forward,
              const struct dns_header *header, size_t plen)
{
  /* Allocate send buffer: 2-byte TCP-DNS length prefix + DNS query payload. */
  size_t sndlen = 2 + plen;
  unsigned char *sndbuf = malloc(sndlen);
  if (!sndbuf) return -1;

  u16 tcp_len = htons((u16)plen);
  memcpy(sndbuf,     &tcp_len, 2);
  memcpy(sndbuf + 2, header,  plen);

  serv->dot_sndbuf   = sndbuf;
  serv->dot_sndlen   = sndlen;
  serv->dot_sndoff   = 0;
  serv->dot_lenbytes = 0;
  serv->dot_rsplen   = 0;
  serv->dot_rspoff   = 0;
  serv->dot_frec     = forward;

  /* Lazy-allocate the response buffer (same capacity as daemon->packet). */
  if (!serv->dot_rspbuf)
    {
      serv->dot_rspbuf = malloc(daemon->packet_buff_sz);
      if (!serv->dot_rspbuf)
        { free(sndbuf); serv->dot_sndbuf = NULL; return -1; }
    }

  /* Re-use the existing TLS session if the connection is still alive. */
  if (serv->tcpfd != -1 && (serv->flags & SERV_GOT_TCP))
    {
      serv->dot_state = DOT_STATE_SENDING;
      return 0;
    }

  /* Close any stale half-open connection. */
  if (serv->tcpfd != -1)
    {
      dot_close(serv);
      close(serv->tcpfd);
      serv->tcpfd = -1;
      serv->flags &= ~SERV_GOT_TCP;
    }

  /* Open a non-blocking TCP socket. */
  serv->tcpfd = socket(serv->addr.sa.sa_family, SOCK_STREAM, 0);
  if (serv->tcpfd == -1)
    { free(sndbuf); serv->dot_sndbuf = NULL; return -1; }

  int fl = fcntl(serv->tcpfd, F_GETFL, 0);
  if (fl == -1 || fcntl(serv->tcpfd, F_SETFL, fl | O_NONBLOCK) == -1)
    {
      close(serv->tcpfd); serv->tcpfd = -1;
      free(sndbuf); serv->dot_sndbuf = NULL; return -1;
    }

  if (!local_bind(serv->tcpfd, &serv->source_addr, serv->interface, 0, 1))
    {
      close(serv->tcpfd); serv->tcpfd = -1;
      free(sndbuf); serv->dot_sndbuf = NULL; return -1;
    }

  int ret = connect(serv->tcpfd, &serv->addr.sa, sa_len(&serv->addr));
  if (ret == 0)
    {
      /* Immediate connect (loopback).  Start handshake right away. */
      if (dot_nb_handshake_setup(serv) != 0)
        {
          close(serv->tcpfd); serv->tcpfd = -1;
          free(sndbuf); serv->dot_sndbuf = NULL; return -1;
        }
      serv->dot_state = DOT_STATE_HANDSHAKING;
    }
  else if (errno == EINPROGRESS)
    {
      serv->dot_state = DOT_STATE_CONNECTING;
    }
  else
    {
      my_syslog(LOG_ERR, "DoT: connect to %s failed: %s",
                serv->tls_hostname, strerror(errno));
      close(serv->tcpfd); serv->tcpfd = -1;
      free(sndbuf); serv->dot_sndbuf = NULL; return -1;
    }

  return 0;
}

static void dot_fail(struct server *serv)
{
  FTL_connection_error("DoT async query failed", &serv->addr, -1);
  serv->failed_queries++;

  if (serv->tls_ctx && serv->tcpfd != -1)
    dot_close(serv);
  if (serv->tcpfd != -1)
    {
      close(serv->tcpfd);
      serv->tcpfd = -1;
    }
  serv->flags    &= ~SERV_GOT_TCP;
  free(serv->dot_sndbuf);
  serv->dot_sndbuf = NULL;
  serv->dot_frec   = NULL;
  serv->dot_state  = DOT_STATE_IDLE;
}

void dot_abort(struct server *serv)
{
  if (serv->tls_ctx && serv->tcpfd != -1)
    dot_close(serv);
  if (serv->tcpfd != -1)
    {
      close(serv->tcpfd);
      serv->tcpfd = -1;
    }
  serv->flags    &= ~SERV_GOT_TCP;
  free(serv->dot_sndbuf);
  serv->dot_sndbuf = NULL;
  serv->dot_frec   = NULL;
  serv->dot_state  = DOT_STATE_IDLE;
}

void dot_advance(time_t now, struct server *serv)
{
  struct frec *fwd = serv->dot_frec;

  /* Bail if the frec was already freed/recycled (query timed out). */
  if (!fwd || fwd->sentto != serv)
    { dot_abort(serv); return; }

  switch (serv->dot_state)
    {
    case DOT_STATE_CONNECTING:
      {
        /* Check whether the non-blocking connect() completed. */
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(serv->tcpfd, SOL_SOCKET, SO_ERROR, &err, &elen) == -1 || err != 0)
          {
            my_syslog(LOG_ERR, "DoT: connect to %s failed: %s",
                      serv->tls_hostname, strerror(err ? err : errno));
            dot_fail(serv); return;
          }
        if (dot_nb_handshake_setup(serv) != 0) { dot_fail(serv); return; }
        serv->dot_state = DOT_STATE_HANDSHAKING;
      }
      /* FALLTHROUGH — attempt handshake immediately; may already have data */

    case DOT_STATE_HANDSHAKING:
      {
        struct tls_server_ctx *ctx = serv->tls_ctx;
        int ret = mbedtls_ssl_handshake(&ctx->ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          return; /* wait for next poll event */
        if (ret != 0)
          { dot_log_error("DoT: handshake failed", ret); dot_fail(serv); return; }

        /* Save session for resumption. */
        if (!ctx->sess_saved) mbedtls_ssl_session_init(&ctx->session);
        if (mbedtls_ssl_get_session(&ctx->ssl, &ctx->session) == 0) ctx->sess_saved = 1;

        /* RFC 7858 §4: verify ALPN "dot". */
        const char *alpn = mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
        if (!alpn || strcmp(alpn, "dot") != 0)
          {
            my_syslog(LOG_ERR, "DoT: %s did not negotiate ALPN 'dot' (got: %s)",
                      serv->tls_hostname, alpn ? alpn : "none");
            dot_fail(serv); return;
          }
        my_syslog(LOG_DEBUG|MS_DEBUG, "DoT: handshake OK with %s (resumed=%d)",
                  serv->tls_hostname, ctx->sess_saved);
        serv->dot_state = DOT_STATE_SENDING;
      }
      /* FALLTHROUGH */

    case DOT_STATE_SENDING:
      {
        struct tls_server_ctx *ctx = serv->tls_ctx;
        while (serv->dot_sndoff < serv->dot_sndlen)
          {
            int ret = mbedtls_ssl_write(&ctx->ssl,
                                        serv->dot_sndbuf + serv->dot_sndoff,
                                        serv->dot_sndlen  - serv->dot_sndoff);
            if (ret > 0) { serv->dot_sndoff += (size_t)ret; continue; }
            if (ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                ret == MBEDTLS_ERR_SSL_WANT_READ)  return;
            dot_log_error("DoT: ssl_write failed", ret);
            dot_fail(serv); return;
          }
        free(serv->dot_sndbuf); serv->dot_sndbuf = NULL;
        serv->dot_lenbytes = 0;
        serv->dot_state    = DOT_STATE_RECV_LEN;
      }
      /* FALLTHROUGH */

    case DOT_STATE_RECV_LEN:
      {
        struct tls_server_ctx *ctx = serv->tls_ctx;
        while (serv->dot_lenbytes < 2)
          {
            int ret = mbedtls_ssl_read(&ctx->ssl,
                                       serv->dot_lenbuf + serv->dot_lenbytes,
                                       2 - serv->dot_lenbytes);
            if (ret > 0)  { serv->dot_lenbytes += (size_t)ret; continue; }
            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) return;
            if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
              { dot_fail(serv); return; }
            dot_log_error("DoT: recv len failed", ret);
            dot_fail(serv); return;
          }
        size_t rsplen = ((size_t)serv->dot_lenbuf[0] << 8) | serv->dot_lenbuf[1];
        if (rsplen == 0 || rsplen > daemon->packet_buff_sz)
          {
            my_syslog(LOG_ERR, "DoT: response length %zu out of range", rsplen);
            dot_fail(serv); return;
          }
        serv->dot_rsplen = rsplen;
        serv->dot_rspoff = 0;
        serv->dot_state  = DOT_STATE_RECV_PAYLOAD;
      }
      /* FALLTHROUGH */

    case DOT_STATE_RECV_PAYLOAD:
      {
        struct tls_server_ctx *ctx = serv->tls_ctx;
        while (serv->dot_rspoff < serv->dot_rsplen)
          {
            int ret = mbedtls_ssl_read(&ctx->ssl,
                                       serv->dot_rspbuf + serv->dot_rspoff,
                                       serv->dot_rsplen  - serv->dot_rspoff);
            if (ret > 0)  { serv->dot_rspoff += (size_t)ret; continue; }
            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) return;
            if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
              { dot_fail(serv); return; }
            dot_log_error("DoT: recv payload failed", ret);
            dot_fail(serv); return;
          }

        /* Full response received — deliver it. */
        {
          ssize_t rsize = (ssize_t)serv->dot_rsplen;
          struct dns_header *resp = (struct dns_header *)serv->dot_rspbuf;

          /* Mark connection live for reuse; reset state BEFORE return_reply
           * since that may trigger new queries on this server. */
          serv->flags    |= SERV_GOT_TCP;
          serv->dot_state = DOT_STATE_IDLE;
          serv->dot_frec  = NULL;

          /* Un-flip query-name case scrambling in the echoed question. */
          extract_name(resp, (size_t)rsize, NULL,
                       (char *)&fwd->frec_src.encode_bitmap,
                       EXTR_NAME_FLIP, 1);

          return_reply(now, fwd, resp, rsize, STAT_OK);
        }
        break;
      }

    default:
      break;
    }
}

/* ── Session / cleanup ─────────────────────────────────────────────────── */

void dot_close(struct server *serv)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (!ctx)
    return;

  int ret, tries = 0;
  do {
    ret = mbedtls_ssl_close_notify(&ctx->ssl);
  } while ((ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_WANT_READ) && ++tries < 10);

  ctx->net.fd = -1;
}

void dot_server_free(struct server *serv)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (!ctx)
    return;

  mbedtls_ssl_free(&ctx->ssl);
  if (ctx->sess_saved)
    mbedtls_ssl_session_free(&ctx->session);
  mbedtls_ssl_config_free(&ctx->conf);
  mbedtls_x509_crt_free(&ctx->cacert);
  mbedtls_net_free(&ctx->net);
  free(ctx);
  serv->tls_ctx = NULL;

  /* Free async state machine buffers. */
  free(serv->dot_sndbuf); serv->dot_sndbuf = NULL;
  free(serv->dot_rspbuf); serv->dot_rspbuf = NULL;
  serv->dot_state = DOT_STATE_IDLE;
  serv->dot_frec  = NULL;
}

/* ── Utility ───────────────────────────────────────────────────────────── */

void dot_log_error(const char *prefix, int ret)
{
  char errbuf[256];
  mbedtls_strerror(ret, errbuf, sizeof(errbuf));
  my_syslog(LOG_ERR, "%s: -0x%04X (%s)", prefix, (unsigned int)(-ret), errbuf);
}

#endif /* HAVE_MBEDTLS */
