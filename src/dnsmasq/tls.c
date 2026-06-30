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
 *  - I/O is synchronous/blocking via mbedtls_net_send / mbedtls_net_recv.
 *    The existing SO_SNDTIMEO / SO_RCVTIMEO on serv->tcpfd provide timeouts;
 *    WANT_READ / WANT_WRITE are retried within dot_handshake / dot_send /
 *    dot_recv_* up to DOT_IO_RETRIES times before giving up.
 */

#ifdef HAVE_MBEDTLS

#include "dnsmasq.h"
#include "tls.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <string.h>
#include <errno.h>

#if MBEDTLS_VERSION_MAJOR >= 4
#  include <psa/crypto.h>
#  include <mbedtls/psa_util.h>
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
#define DOT_IO_RETRIES 50

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

  /* RNG: PSA on mbedTLS 4.x, classic ctr_drbg on 3.x. */
#if MBEDTLS_VERSION_MAJOR >= 4
  mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_psa_get_random,
                        MBEDTLS_PSA_RANDOM_STATE);
#else
  mbedtls_ssl_conf_rng(&ctx->conf, dot_rng, NULL);
#endif

  /* Minimum TLS 1.2; prefer TLS 1.3 when available. */
  mbedtls_ssl_conf_min_tls_version(&ctx->conf, MBEDTLS_TLS_VERSION_1_2);

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

  const char *alpn = mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
  my_syslog(LOG_DEBUG|MS_DEBUG,
            "DoT: TLS handshake OK with %s (resumed=%d, ALPN=%s)",
            serv->tls_hostname, ctx->sess_saved, alpn ? alpn : "none");
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
}

/* ── Utility ───────────────────────────────────────────────────────────── */

void dot_log_error(const char *prefix, int ret)
{
  char errbuf[256];
  mbedtls_strerror(ret, errbuf, sizeof(errbuf));
  my_syslog(LOG_ERR, "%s: -0x%04X (%s)", prefix, (unsigned int)(-ret), errbuf);
}

#endif /* HAVE_MBEDTLS */
