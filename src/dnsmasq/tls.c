/* Pi-hole FTL-DoT: native DNS-over-TLS upstream support (RFC 7858)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Design:
 *  - mbedTLS is already linked into FTL for the web server; we reuse it.
 *  - mbedTLS 3.x: global entropy + CTR-DRBG RNG (thread-safe via mutex).
 *  - mbedTLS 4.x: PSA Crypto replaces entropy/drbg; thread-safe natively.
 *  - Per-server: dot_shared_ctx holds ssl_config (CA chain, ALPN, TLS ver)
 *    and ssl_session for resumption.  These persist as long as the server exists.
 *  - Per-connection: a small pool (DOT_CONN_MAX) of dot_async_ctx, each with
 *    its own ssl_context and net_context, reusing the per-server shared
 *    config. Once a connection is up, it pipelines up to DOT_JOB_MAX
 *    queries at once (RFC 7766) instead of dedicating the whole connection
 *    to one query's send-then-receive lifecycle, replies are demultiplexed
 *    by the 16-bit DNS transaction ID already used to correlate plain-UDP
 *    forwarding. Session resumption (shared across the pool) avoids the
 *    full handshake RTT on each new pooled connection.
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

/* ── Per-server init (synchronous TCP-fallback path) ─────────────────────── */

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

  /* RNG: mbedTLS 4.x uses PSA internally, no explicit conf needed.
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

/* ── Per-connection: handshake (synchronous TCP-fallback path) ───────────── */

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

  if (ctx->sess_saved)
    mbedtls_ssl_session_free(&ctx->session);
  mbedtls_ssl_session_init(&ctx->session);
  ret = mbedtls_ssl_get_session(&ctx->ssl, &ctx->session);
  ctx->sess_saved = (ret == 0) ? 1 : 0;

  /* RFC 7858 §4: verify ALPN.  Reject wrong ALPN; allow absent ALPN
   * (many real-world DoT servers including Google 8.8.8.8 omit it). */
  const char *alpn = mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
  if (alpn != NULL && strcmp(alpn, "dot") != 0)
    {
      my_syslog(LOG_ERR, "DoT: server %s returned wrong ALPN '%s' (expected 'dot')",
                serv->tls_hostname, alpn);
      return -1;
    }
  my_syslog(LOG_DEBUG|MS_DEBUG,
            "DoT: TLS handshake OK with %s (resumed=%d, ALPN=%s)",
            serv->tls_hostname, ctx->sess_saved, alpn ? alpn : "none");
  return 0;
}

/* ── Per-connection: I/O (synchronous TCP-fallback path) ──────────────────── */

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
           * mbedTLS surfaces this as RECEIVED_NEW_SESSION_TICKET, not an
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

/* ── Async non-blocking DoT state machine (pipelined connection pool) ────── */

static void dot_conn_close(struct server *serv, int i);
static void dot_fail(struct server *serv, int i);
static void dot_start_pending(struct server *serv, int i);

/* Allocate and configure the per-server shared TLS config (CA chain, ALPN,
 * min version). Called once, the first time any pooled connection is
 * needed for this server. */
static int dot_shared_init(struct server *serv)
{
  if (!g_initialized)
    {
      my_syslog(LOG_ERR, "DoT: dot_global_init() not called");
      return -1;
    }

  struct dot_shared_ctx *sh = calloc(1, sizeof(*sh));
  if (!sh)
    {
      my_syslog(LOG_ERR, "DoT: out of memory");
      return -1;
    }

  mbedtls_ssl_config_init(&sh->conf);
  mbedtls_x509_crt_init(&sh->cacert);
  sh->sess_saved = 0;

  int ret = mbedtls_x509_crt_parse_file(&sh->cacert, DOT_CA_BUNDLE);
  if (ret != 0)
    {
      ret = mbedtls_x509_crt_parse_file(&sh->cacert, DOT_CA_BUNDLE2);
      if (ret != 0)
        {
          dot_log_error("DoT: failed to load CA bundle", ret);
          goto fail;
        }
    }

  ret = mbedtls_ssl_config_defaults(&sh->conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0)
    {
      dot_log_error("DoT: ssl_config_defaults failed", ret);
      goto fail;
    }

  mbedtls_ssl_conf_authmode(&sh->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&sh->conf, &sh->cacert, NULL);

#if MBEDTLS_VERSION_MAJOR < 4
  mbedtls_ssl_conf_rng(&sh->conf, dot_rng, NULL);
#endif

#if MBEDTLS_VERSION_MAJOR >= 4
  mbedtls_ssl_conf_min_tls_version(&sh->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
  mbedtls_ssl_conf_min_tls_version(&sh->conf, MBEDTLS_TLS_VERSION_1_2);
#endif

  ret = mbedtls_ssl_conf_alpn_protocols(&sh->conf, dot_alpn);
  if (ret != 0)
    {
      dot_log_error("DoT: ALPN setup failed", ret);
      goto fail;
    }

  serv->dot_shared_ctx = sh;
  return 0;

fail:
  mbedtls_x509_crt_free(&sh->cacert);
  mbedtls_ssl_config_free(&sh->conf);
  free(sh);
  return -1;
}

/* Prepare the mbedTLS ssl context for a new connection on dot_conn[i].tcpfd.
 * Allocates dot_shared_ctx/dot_conn[i].actx as needed. Called once after TCP
 * connect() completes for that pooled connection. */
static int dot_conn_setup(struct server *serv, int i)
{
  if (!serv->dot_shared_ctx && dot_shared_init(serv) != 0)
    return -1;
  struct dot_shared_ctx *sh = serv->dot_shared_ctx;

  struct dot_async_ctx *actx = serv->dot_conn[i].actx;
  if (!actx)
    {
      actx = calloc(1, sizeof(*actx));
      if (!actx)
        return -1;
      mbedtls_ssl_init(&actx->ssl);
      mbedtls_net_init(&actx->net);
      serv->dot_conn[i].actx = actx;
    }
  else
    {
      mbedtls_ssl_free(&actx->ssl);
      mbedtls_ssl_init(&actx->ssl);
    }

  int ret = mbedtls_ssl_setup(&actx->ssl, &sh->conf);
  if (ret != 0) { dot_log_error("DoT: ssl_setup", ret); return -1; }

  ret = mbedtls_ssl_set_hostname(&actx->ssl, serv->tls_hostname);
  if (ret != 0) { dot_log_error("DoT: set_hostname", ret); return -1; }

  actx->net.fd = serv->dot_conn[i].tcpfd;
  mbedtls_ssl_set_bio(&actx->ssl, &actx->net,
                      mbedtls_net_send, mbedtls_net_recv, NULL);

  if (sh->sess_saved)
    mbedtls_ssl_set_session(&actx->ssl, &sh->session);

  return 0;
}

/* Return the poll events to watch for dot_conn[i] (POLLIN/POLLOUT). */
int dot_poll_events(struct server *serv, int i)
{
  switch (serv->dot_conn[i].state)
    {
    case DOT_STATE_CONNECTING:
      return POLLOUT;              /* waiting for connect() to complete */
    case DOT_STATE_HANDSHAKING:
      return POLLIN | POLLOUT;     /* TLS may flip direction mid-handshake */
    case DOT_STATE_ACTIVE:
      {
        /* Need to read whenever active (replies may arrive any time).
         * Only need to write if some job hasn't been fully sent yet. */
        int j;
        for (j = 0; j < serv->dot_conn[i].job_count; j++)
          if (serv->dot_conn[i].jobs[j].buf != NULL)
            return POLLIN | POLLOUT;
        return POLLIN;
      }
    default:
      return 0;
    }
}

/* Open a non-blocking TCP socket on dot_conn[i] and set its state to
 * CONNECTING/HANDSHAKING. Any jobs already queued on dot_conn[i].jobs[] are
 * left untouched, they'll be flushed once the connection reaches ACTIVE.
 * Returns 0 on success, -1 on error (socket cleaned up; caller must still
 * dispose of any jobs already assigned to this slot). */
static int dot_start_socket(struct server *serv, int i)
{
  /* Re-use the existing TLS connection if it's still alive. */
  if (serv->dot_conn[i].tcpfd != -1 && serv->dot_conn[i].alive)
    {
      serv->dot_conn[i].state = DOT_STATE_ACTIVE;
      return 0;
    }

  /* Close any stale half-open connection. */
  if (serv->dot_conn[i].tcpfd != -1)
    {
      dot_conn_close(serv, i);
      close(serv->dot_conn[i].tcpfd);
      serv->dot_conn[i].tcpfd = -1;
      serv->dot_conn[i].alive = 0;
    }

  serv->dot_conn[i].tcpfd = socket(serv->addr.sa.sa_family, SOCK_STREAM, 0);
  if (serv->dot_conn[i].tcpfd == -1)
    return -1;

  int fl = fcntl(serv->dot_conn[i].tcpfd, F_GETFL, 0);
  if (fl == -1 || fcntl(serv->dot_conn[i].tcpfd, F_SETFL, fl | O_NONBLOCK) == -1)
    {
      close(serv->dot_conn[i].tcpfd); serv->dot_conn[i].tcpfd = -1;
      return -1;
    }

  if (!local_bind(serv->dot_conn[i].tcpfd, &serv->source_addr, serv->interface, 0, 1))
    {
      close(serv->dot_conn[i].tcpfd); serv->dot_conn[i].tcpfd = -1;
      return -1;
    }

  int ret = connect(serv->dot_conn[i].tcpfd, &serv->addr.sa, sa_len(&serv->addr));
  if (ret == 0)
    {
      if (dot_conn_setup(serv, i) != 0)
        {
          close(serv->dot_conn[i].tcpfd); serv->dot_conn[i].tcpfd = -1;
          return -1;
        }
      serv->dot_conn[i].state = DOT_STATE_HANDSHAKING;
    }
  else if (errno == EINPROGRESS || errno == EAGAIN)
    {
      serv->dot_conn[i].state = DOT_STATE_CONNECTING;
    }
  else
    {
      my_syslog(LOG_ERR, "DoT: connect to %s failed: %s",
                serv->tls_hostname, strerror(errno));
      close(serv->dot_conn[i].tcpfd); serv->dot_conn[i].tcpfd = -1;
      return -1;
    }

  return 0;
}

/* Append one job (frec + wire packet) to dot_conn[i].jobs[]. Caller must
 * have already checked job_count < DOT_JOB_MAX. wire_id is the DNS
 * transaction ID already written into header->id (forward->new_id),
 * used later to match this job against its reply. */
static void dot_conn_add_job(struct server *serv, int i, struct frec *forward,
                             unsigned char *buf, size_t len, u16 wire_id)
{
  int j = serv->dot_conn[i].job_count++;
  serv->dot_conn[i].jobs[j].frec    = forward;
  serv->dot_conn[i].jobs[j].buf     = buf;
  serv->dot_conn[i].jobs[j].len     = len;
  serv->dot_conn[i].jobs[j].off     = 0;
  serv->dot_conn[i].jobs[j].wire_id = wire_id;
}

/* Find a connection that can accept one more pipelined job right now:
 * prefer an already-ACTIVE connection with room (query goes out immediately
 * on the next write), then a CONNECTING/HANDSHAKING one with room (query
 * waits for the handshake to finish), then a completely IDLE slot (starts a
 * brand new connection). Returns -1 if every connection's pipeline is full. */
static int dot_find_conn_for_job(struct server *serv)
{
  int i;
  for (i = 0; i < DOT_CONN_MAX; i++)
    if (serv->dot_conn[i].state == DOT_STATE_ACTIVE &&
        serv->dot_conn[i].job_count < DOT_JOB_MAX)
      return i;
  for (i = 0; i < DOT_CONN_MAX; i++)
    if ((serv->dot_conn[i].state == DOT_STATE_CONNECTING ||
         serv->dot_conn[i].state == DOT_STATE_HANDSHAKING) &&
        serv->dot_conn[i].job_count < DOT_JOB_MAX)
      return i;
  for (i = 0; i < DOT_CONN_MAX; i++)
    if (serv->dot_conn[i].state == DOT_STATE_IDLE)
      return i;
  return -1;
}

/* Try to write out every not-yet-sent job on dot_conn[i], in order, until
 * one blocks on WANT_READ/WANT_WRITE, fails, or all are sent. Safe to call
 * whenever a connection is ACTIVE and may have unsent jobs. */
static void dot_conn_flush_writes(struct server *serv, int i)
{
  struct dot_async_ctx *actx = serv->dot_conn[i].actx;
  int j;

  for (j = 0; j < serv->dot_conn[i].job_count; j++)
    {
      if (serv->dot_conn[i].jobs[j].buf == NULL)
        continue; /* already sent, awaiting reply */

      while (serv->dot_conn[i].jobs[j].off < serv->dot_conn[i].jobs[j].len)
        {
          int ret = mbedtls_ssl_write(&actx->ssl,
                       serv->dot_conn[i].jobs[j].buf + serv->dot_conn[i].jobs[j].off,
                       serv->dot_conn[i].jobs[j].len  - serv->dot_conn[i].jobs[j].off);
          if (ret > 0) { serv->dot_conn[i].jobs[j].off += (size_t)ret; continue; }
          if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ)
            return; /* socket buffer full or needs a read first; try again next poll */
          dot_log_error("DoT: ssl_write failed", ret);
          dot_fail(serv, i);
          return;
        }
      free(serv->dot_conn[i].jobs[j].buf);
      serv->dot_conn[i].jobs[j].buf = NULL; /* now sent, awaiting reply */
    }
}

int dot_start(struct server *serv, struct frec *forward,
              const struct dns_header *header, size_t plen)
{
  int i = dot_find_conn_for_job(serv);
  if (i == -1)
    return -1; /* every connection's pipeline is full; caller should dot_enqueue() */

  size_t sndlen = 2 + plen;
  unsigned char *sndbuf = malloc(sndlen);
  if (!sndbuf) return -1;

  u16 tcp_len = htons((u16)plen);
  memcpy(sndbuf,     &tcp_len, 2);
  memcpy(sndbuf + 2, header,  plen);

  int was_idle = (serv->dot_conn[i].state == DOT_STATE_IDLE);

  dot_conn_add_job(serv, i, forward, sndbuf, sndlen, ntohs(header->id));

  if (!serv->dot_conn[i].rspbuf)
    {
      serv->dot_conn[i].rspbuf = malloc(daemon->packet_buff_sz);
      if (!serv->dot_conn[i].rspbuf)
        { serv->dot_conn[i].job_count--; free(sndbuf); return -1; }
    }

  if (was_idle)
    {
      if (dot_start_socket(serv, i) != 0)
        { serv->dot_conn[i].job_count--; free(sndbuf); return -1; }
    }
  else if (serv->dot_conn[i].state == DOT_STATE_ACTIVE)
    {
      /* Connection already up, try to send this job immediately instead
       * of waiting for the next poll() cycle, to keep latency low. */
      dot_conn_flush_writes(serv, i);
    }
  /* else CONNECTING/HANDSHAKING: job waits in the queue, flushed once ACTIVE. */

  return 0;
}

int dot_enqueue(struct server *serv, struct frec *forward,
                const struct dns_header *header, size_t plen)
{
  if (serv->dot_pending_count >= DOT_PENDING_MAX)
    return -1; /* overflow queue full */

  size_t sndlen = 2 + plen;
  unsigned char *buf = malloc(sndlen);
  if (!buf) return -1;

  u16 tcp_len = htons((u16)plen);
  memcpy(buf,     &tcp_len, 2);
  memcpy(buf + 2, header,  plen);

  int i = serv->dot_pending_count++;
  serv->dot_pending[i].buf  = buf;
  serv->dot_pending[i].len  = sndlen;
  serv->dot_pending[i].frec = forward;
  return 0;
}

/* Called whenever dot_conn[i] might have spare pipeline capacity (after
 * connecting, or after a reply frees a job slot); moves queries from the
 * shared overflow queue onto it until the queue is empty or the pipeline
 * is full. Entries whose frec was recycled while queued (timed out) are
 * skipped and freed. */
static void dot_start_pending(struct server *serv, int i)
{
  if (serv->dot_conn[i].state != DOT_STATE_ACTIVE &&
      serv->dot_conn[i].state != DOT_STATE_IDLE)
    return; /* still connecting/handshaking; will be called again once ready */

  while (serv->dot_pending_count > 0 && serv->dot_conn[i].job_count < DOT_JOB_MAX)
    {
      unsigned char *buf    = serv->dot_pending[0].buf;
      size_t         buflen = serv->dot_pending[0].len;
      struct frec   *frec   = serv->dot_pending[0].frec;

      serv->dot_pending_count--;
      memmove(&serv->dot_pending[0], &serv->dot_pending[1],
              (size_t)serv->dot_pending_count * sizeof(serv->dot_pending[0]));

      /* Detect frec recycled while it was waiting. */
      if (frec->sentto != serv) { free(buf); continue; }

      /* wire_id lives in the first two bytes of the DNS message, after the
       * 2-byte TCP length prefix. */
      u16 wire_id = ((u16)buf[2] << 8) | buf[3];
      int was_idle = (serv->dot_conn[i].state == DOT_STATE_IDLE);
      dot_conn_add_job(serv, i, frec, buf, buflen, wire_id);

      if (!serv->dot_conn[i].rspbuf)
        {
          serv->dot_conn[i].rspbuf = malloc(daemon->packet_buff_sz);
          if (!serv->dot_conn[i].rspbuf)
            { serv->dot_conn[i].job_count--; free(buf); frec_free(frec); continue; }
        }

      if (was_idle && dot_start_socket(serv, i) != 0)
        {
          serv->dot_conn[i].job_count--;
          free(buf);
          frec_free(frec);
          return; /* socket-level failure; give up on this slot for now */
        }
    }

  if (serv->dot_conn[i].state == DOT_STATE_ACTIVE)
    dot_conn_flush_writes(serv, i);
}

/* Fail dot_conn[i]: close the connection and dispose of every job it held.
 * Jobs not yet sent still have their packet bytes (buf != NULL) and are
 * moved to the shared overflow queue to retry on whatever connection frees
 * up next. Jobs already sent (buf == NULL) cannot be retried without a copy
 * of the original packet, those are dropped (frec_free), same as a plain
 * network timeout looks to the original client. */
static void dot_fail(struct server *serv, int i)
{
  FTL_connection_error("DoT async query failed", &serv->addr, -1);
  serv->failed_queries++;

  if (serv->dot_conn[i].actx && serv->dot_conn[i].tcpfd != -1)
    dot_conn_close(serv, i);
  if (serv->dot_conn[i].tcpfd != -1)
    {
      close(serv->dot_conn[i].tcpfd);
      serv->dot_conn[i].tcpfd = -1;
    }
  serv->dot_conn[i].alive = 0;

  /* Snapshot the jobs locally and empty dot_conn[i].jobs[] *before* touching
   * any frec: frec_free() below re-enters dot_gc_frec(), which searches
   * every server's dot_conn[]/dot_pending[] for the freed frec and, if
   * found, mutates that array (memmove) to remove it. If dot_conn[i].jobs[]
   * still held live entries at that point, a frec_free() for job k could
   * shift/free entries out from under this very loop, a reentrant
   * heap-corrupting self-modification (observed as a crash inside malloc). */
  int job_count = serv->dot_conn[i].job_count;
  struct { struct frec *frec; unsigned char *buf; size_t len; } snap[DOT_JOB_MAX];
  int j;
  for (j = 0; j < job_count; j++)
    {
      snap[j].frec = serv->dot_conn[i].jobs[j].frec;
      snap[j].buf  = serv->dot_conn[i].jobs[j].buf;
      snap[j].len  = serv->dot_conn[i].jobs[j].len;
    }
  serv->dot_conn[i].job_count = 0;
  serv->dot_conn[i].state     = DOT_STATE_IDLE;
  serv->dot_conn[i].lenbytes  = 0;
  serv->dot_conn[i].rspoff    = 0;

  for (j = 0; j < job_count; j++)
    {
      if (snap[j].buf && snap[j].frec->sentto == serv && serv->dot_pending_count < DOT_PENDING_MAX)
        {
          int p = serv->dot_pending_count++;
          serv->dot_pending[p].buf  = snap[j].buf;
          serv->dot_pending[p].len  = snap[j].len;
          serv->dot_pending[p].frec = snap[j].frec;
        }
      else
        {
          free(snap[j].buf);
          if (snap[j].frec->sentto == serv)
            frec_free(snap[j].frec);
        }
    }

  /* This connection is now idle, try to start something queued on it. */
  dot_start_pending(serv, i);
}

/* Drain as many complete replies as are already available on dot_conn[i]
 * without needing a new poll() event, demultiplexing each by DNS
 * transaction ID against the jobs it holds. */
static void dot_conn_service_reads(time_t now, struct server *serv, int i)
{
  struct dot_async_ctx *actx = serv->dot_conn[i].actx;

  for (;;)
    {
      while (serv->dot_conn[i].lenbytes < 2)
        {
          int ret = mbedtls_ssl_read(&actx->ssl,
                       serv->dot_conn[i].lenbuf + serv->dot_conn[i].lenbytes,
                       2 - serv->dot_conn[i].lenbytes);
          if (ret > 0) { serv->dot_conn[i].lenbytes += (size_t)ret; continue; }
          if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return; /* nothing more available right now */
          if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
          if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
            { dot_fail(serv, i); return; }
          dot_log_error("DoT: recv len failed", ret);
          dot_fail(serv, i); return;
        }

      size_t rsplen = ((size_t)serv->dot_conn[i].lenbuf[0] << 8) | serv->dot_conn[i].lenbuf[1];
      if (rsplen == 0 || rsplen > daemon->packet_buff_sz)
        {
          my_syslog(LOG_ERR, "DoT: response length %zu out of range", rsplen);
          dot_fail(serv, i); return;
        }
      serv->dot_conn[i].rsplen = rsplen;

      while (serv->dot_conn[i].rspoff < serv->dot_conn[i].rsplen)
        {
          int ret = mbedtls_ssl_read(&actx->ssl,
                       serv->dot_conn[i].rspbuf + serv->dot_conn[i].rspoff,
                       serv->dot_conn[i].rsplen  - serv->dot_conn[i].rspoff);
          if (ret > 0) { serv->dot_conn[i].rspoff += (size_t)ret; continue; }
          if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return;
          if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
          if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
            { dot_fail(serv, i); return; }
          dot_log_error("DoT: recv payload failed", ret);
          dot_fail(serv, i); return;
        }

      /* Full response received, find which job it answers. */
      u16 rid = ((u16)serv->dot_conn[i].rspbuf[0] << 8) | serv->dot_conn[i].rspbuf[1];
      int idx = -1, j;
      for (j = 0; j < serv->dot_conn[i].job_count; j++)
        if (serv->dot_conn[i].jobs[j].buf == NULL &&
            serv->dot_conn[i].jobs[j].wire_id == rid)
          { idx = j; break; }

      if (idx == -1)
        my_syslog(LOG_DEBUG|MS_DEBUG,
                  "DoT: unmatched reply id %u from %s, discarding",
                  rid, serv->tls_hostname);
      else
        {
          struct frec *fwd = serv->dot_conn[i].jobs[idx].frec;
          size_t rsize = serv->dot_conn[i].rsplen;

          /* Remove the job before delivering, return_reply()/free_frec()
           * must not find a stale entry if they re-enter this server. */
          serv->dot_conn[i].job_count--;
          memmove(&serv->dot_conn[i].jobs[idx], &serv->dot_conn[i].jobs[idx + 1],
                  (size_t)(serv->dot_conn[i].job_count - idx) * sizeof(serv->dot_conn[i].jobs[0]));

          if (fwd->sentto == serv) /* still valid; not recycled by GC meanwhile */
            {
              /* return_reply()/process_reply() validate and rewrite the
               * header we hand them, but the actual wire send (send_from(),
               * forward.c) always transmits daemon->packet, regardless of
               * which buffer pointer was passed in. Our per-connection
               * rspbuf is a different buffer, so without this copy
               * send_from() would transmit whatever stale bytes happened to
               * already be in daemon->packet, wrong transaction ID,
               * wrong/no answer, while logging (which does read rspbuf)
               * looked correct. */
              memcpy(daemon->packet, serv->dot_conn[i].rspbuf, rsize);
              struct dns_header *resp = (struct dns_header *)daemon->packet;

              extract_name(resp, rsize, NULL,
                           (char *)&fwd->frec_src.encode_bitmap,
                           EXTR_NAME_FLIP, 1);

              serv->dot_conn[i].alive = 1;
              return_reply(now, fwd, resp, (ssize_t)rsize, STAT_OK);
            }
        }

      /* Reset to read the next response, if any is already buffered. */
      serv->dot_conn[i].lenbytes = 0;
      serv->dot_conn[i].rspoff   = 0;
    }
}

void dot_advance(time_t now, struct server *serv, int i)
{
  /* Oldest-job staleness check: jobs are always appended at the end, so
   * jobs[0], if present, is the longest-waiting survivor. If the server
   * hasn't answered it in 2×TIMEOUT despite poll() repeatedly firing for
   * this connection, treat the whole connection as stuck (a healthy
   * pipelined connection should not let any one reply lag this far behind;
   * unresponsive connections that never fire a poll event at all are
   * handled separately by the free_frec() sweep in forward.c). */
  if (serv->dot_conn[i].job_count > 0)
    {
      struct frec *oldest = serv->dot_conn[i].jobs[0].frec;
      if (oldest->sentto == serv && difftime(now, oldest->time) > 2 * TIMEOUT)
        {
          my_syslog(LOG_WARNING, "DoT: connection to %s stalled for %ds, resetting",
                    serv->tls_hostname, 2 * TIMEOUT);
          dot_fail(serv, i);
          return;
        }
    }

  switch (serv->dot_conn[i].state)
    {
    case DOT_STATE_CONNECTING:
      {
        /* Check whether the non-blocking connect() completed. */
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(serv->dot_conn[i].tcpfd, SOL_SOCKET, SO_ERROR, &err, &elen) == -1)
          { dot_fail(serv, i); return; }
        /* EAGAIN/EINPROGRESS: connection still in progress (spurious POLLOUT on
         * some kernels / Docker networking stacks).  Stay in CONNECTING state. */
        if (err == EAGAIN || err == EINPROGRESS)
          return;
        if (err != 0)
          {
            my_syslog(LOG_ERR, "DoT: connect to %s failed: %s",
                      serv->tls_hostname, strerror(err));
            dot_fail(serv, i); return;
          }
        if (dot_conn_setup(serv, i) != 0) { dot_fail(serv, i); return; }
        serv->dot_conn[i].state = DOT_STATE_HANDSHAKING;
      }
      /* FALLTHROUGH, attempt handshake immediately; may already have data */

    case DOT_STATE_HANDSHAKING:
      {
        struct dot_shared_ctx *sh = serv->dot_shared_ctx;
        struct dot_async_ctx  *actx = serv->dot_conn[i].actx;
        int ret = mbedtls_ssl_handshake(&actx->ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          return; /* wait for next poll event */
        if (ret != 0)
          { dot_log_error("DoT: handshake failed", ret); dot_fail(serv, i); return; }

        /* Save session for resumption (shared across the connection pool).
         * Free old data first to avoid leak (get_session does a deep copy
         * with heap allocations). */
        if (sh->sess_saved) mbedtls_ssl_session_free(&sh->session);
        mbedtls_ssl_session_init(&sh->session);
        if (mbedtls_ssl_get_session(&actx->ssl, &sh->session) == 0) sh->sess_saved = 1;

        /* RFC 7858 §4: verify ALPN.
         * If server returns a different ALPN value, refuse (wrong protocol).
         * If server sends no ALPN at all (common with Google 8.8.8.8:853),
         * log a warning and continue, the TLS tunnel is still intact. */
        const char *alpn = mbedtls_ssl_get_alpn_protocol(&actx->ssl);
        if (alpn != NULL && strcmp(alpn, "dot") != 0)
          {
            my_syslog(LOG_ERR, "DoT: %s returned wrong ALPN '%s' (expected 'dot')",
                      serv->tls_hostname, alpn);
            dot_fail(serv, i); return;
          }
        my_syslog(LOG_DEBUG|MS_DEBUG, "DoT: handshake OK with %s (resumed=%d, ALPN=%s)",
                  serv->tls_hostname, sh->sess_saved, alpn ? alpn : "none");
        serv->dot_conn[i].state = DOT_STATE_ACTIVE;
        /* Any jobs queued while CONNECTING/HANDSHAKING are still sitting in
         * dot_conn[i].jobs[] with buf != NULL, fall through to send them. */
      }
      /* FALLTHROUGH */

    case DOT_STATE_ACTIVE:
      dot_conn_flush_writes(serv, i);
      if (serv->dot_conn[i].state == DOT_STATE_ACTIVE) /* flush may have dot_fail()'d us */
        {
          dot_conn_service_reads(now, serv, i);
          if (serv->dot_conn[i].state == DOT_STATE_ACTIVE)
            dot_start_pending(serv, i); /* pull in overflow queue if there's now room */
        }
      break;

    default:
      break;
    }
}

void dot_gc_frec(struct frec *f)
{
  struct server *_s;
  for (_s = daemon->servers; _s; _s = _s->next)
    {
      if (!_s->tls_hostname)
        continue;

      int _k;
      for (_k = 0; _k < DOT_CONN_MAX; _k++)
        {
          int _j;
          for (_j = 0; _j < _s->dot_conn[_k].job_count; _j++)
            if (_s->dot_conn[_k].jobs[_j].frec == f)
              {
                /* Removing one job never disturbs the connection or its
                 * other jobs: unsent bytes are simply freed; if it was
                 * already sent, any late reply for its wire_id will find no
                 * matching job and be discarded harmlessly. */
                free(_s->dot_conn[_k].jobs[_j].buf);
                _s->dot_conn[_k].job_count--;
                memmove(&_s->dot_conn[_k].jobs[_j], &_s->dot_conn[_k].jobs[_j + 1],
                        (size_t)(_s->dot_conn[_k].job_count - _j) * sizeof(_s->dot_conn[_k].jobs[0]));
                return;
              }
        }

      {
        int _j;
        for (_j = 0; _j < _s->dot_pending_count; _j++)
          if (_s->dot_pending[_j].frec == f)
            {
              free(_s->dot_pending[_j].buf);
              _s->dot_pending_count--;
              memmove(&_s->dot_pending[_j], &_s->dot_pending[_j + 1],
                      (size_t)(_s->dot_pending_count - _j) * sizeof(_s->dot_pending[0]));
              return;
            }
      }
    }
}

/* ── Session / cleanup ─────────────────────────────────────────────────── */

/* Used only by the synchronous TCP-fallback path (operates on serv->tls_ctx,
 * NOT the async connection pool). */
void dot_close(struct server *serv)
{
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (!ctx)
    return;

  mbedtls_ssl_close_notify(&ctx->ssl);
  ctx->net.fd = -1;
}

/* Best-effort TLS close_notify for one pooled async connection.  On a
 * non-blocking socket WANT_READ/WANT_WRITE means "retry later", but
 * retrying immediately in a spin loop never helps; the TCP RST from
 * close() signals EOF to the peer either way. */
static void dot_conn_close(struct server *serv, int i)
{
  struct dot_async_ctx *actx = serv->dot_conn[i].actx;
  if (!actx)
    return;

  mbedtls_ssl_close_notify(&actx->ssl);

  actx->net.fd = -1;
}

void dot_server_free(struct server *serv)
{
  /* Free the synchronous TCP-fallback context, if ever used. */
  struct tls_server_ctx *ctx = serv->tls_ctx;
  if (ctx)
    {
      if (serv->tcpfd != -1)
        {
          if (ctx->net.fd == serv->tcpfd)
            ctx->net.fd = -1; /* prevent double-close inside mbedtls_net_free */
          close(serv->tcpfd);
          serv->tcpfd = -1;
        }
      mbedtls_ssl_free(&ctx->ssl);
      if (ctx->sess_saved)
        mbedtls_ssl_session_free(&ctx->session);
      mbedtls_ssl_config_free(&ctx->conf);
      mbedtls_x509_crt_free(&ctx->cacert);
      mbedtls_net_free(&ctx->net);
      free(ctx);
      serv->tls_ctx = NULL;
    }

  /* Free every pooled async connection and any jobs it still held.
   *
   * mbedtls_net_free() closes actx->net.fd, but in DOT_STATE_CONNECTING
   * dot_conn_setup() has not been called yet so actx->net.fd == -1
   * while dot_conn[i].tcpfd is a live open socket, causing an FD leak on
   * SIGHUP. By always closing dot_conn[i].tcpfd here (and zeroing
   * actx->net.fd to prevent a double-close inside mbedtls_net_free), the
   * leak is eliminated in all states regardless of whether a handshake was
   * ever initiated. */
  {
    int i;
    for (i = 0; i < DOT_CONN_MAX; i++)
      {
        struct dot_async_ctx *actx = serv->dot_conn[i].actx;
        if (serv->dot_conn[i].tcpfd != -1)
          {
            if (actx && actx->net.fd == serv->dot_conn[i].tcpfd)
              actx->net.fd = -1;
            else if (actx && actx->net.fd != -1)
              dot_conn_close(serv, i);
            close(serv->dot_conn[i].tcpfd);
            serv->dot_conn[i].tcpfd = -1;
          }
        if (actx)
          {
            mbedtls_ssl_free(&actx->ssl);
            mbedtls_net_free(&actx->net);
            free(actx);
            serv->dot_conn[i].actx = NULL;
          }
        {
          int j;
          for (j = 0; j < serv->dot_conn[i].job_count; j++)
            free(serv->dot_conn[i].jobs[j].buf);
          serv->dot_conn[i].job_count = 0;
        }
        free(serv->dot_conn[i].rspbuf); serv->dot_conn[i].rspbuf = NULL;
        serv->dot_conn[i].state = DOT_STATE_IDLE;
        serv->dot_conn[i].alive = 0;
      }
  }

  if (serv->dot_shared_ctx)
    {
      struct dot_shared_ctx *sh = serv->dot_shared_ctx;
      if (sh->sess_saved)
        mbedtls_ssl_session_free(&sh->session);
      mbedtls_ssl_config_free(&sh->conf);
      mbedtls_x509_crt_free(&sh->cacert);
      free(sh);
      serv->dot_shared_ctx = NULL;
    }

  {
    int _i;
    for (_i = 0; _i < serv->dot_pending_count; _i++)
      free(serv->dot_pending[_i].buf);
    serv->dot_pending_count = 0;
  }
}

/* ── Utility ───────────────────────────────────────────────────────────── */

void dot_log_error(const char *prefix, int ret)
{
  char errbuf[256];
  mbedtls_strerror(ret, errbuf, sizeof(errbuf));
  my_syslog(LOG_ERR, "%s: -0x%04X (%s)", prefix, (unsigned int)(-ret), errbuf);
}

#endif /* HAVE_MBEDTLS */
