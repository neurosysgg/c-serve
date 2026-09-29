/* The TLS seam's mbedtls 4 side (tls.h): PSA crypto underneath, so no
 * RNG to wire up; the CA bundle parsed once per process, whichever thread
 * gets there first (ctui-mail checks its accounts in parallel). mbedtls
 * as distributions build it has no MBEDTLS_THREADING_C, so PSA's key
 * slots and RNG are unguarded: every mbedtls call runs under one lock,
 * never held across the poll() waits, so connections still overlap on
 * the network and only the crypto takes turns. */
#define _POSIX_C_SOURCE 200809L
#include "tls.h"

#include "conn.h"

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct CTUI_WM_TLS {
  int fd;
  mbedtls_ssl_context ssl;
};

/* process-wide: the config and the CAs it points at, set up once; a
 * failed setup stays failed, its reason kept for every later caller */
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static int g_ready;
static char g_err[200];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mbedtls_ssl_config g_conf;
static mbedtls_x509_crt g_ca;

/* Debian/Arch/Alpine, Fedora, the BSDs and others */
static const char *const CA_FILES[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
};

static void why(int ret, const char *what, char *err, size_t err_cap) {
  char msg[160];
  mbedtls_strerror(ret, msg, sizeof msg);
  snprintf(err, err_cap, "TLS: %s: %s", what, msg);
}

static int setup_once(char *err, size_t err_cap) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    snprintf(err, err_cap, "TLS: the crypto library didn't start");
    return -1;
  }
  mbedtls_x509_crt_init(&g_ca);
  const char *env = getenv("SSL_CERT_FILE");
  int loaded = 0;
  if (env && *env) {
    loaded = mbedtls_x509_crt_parse_file(&g_ca, env) >= 0;
  }
  for (size_t i = 0; !loaded && i < sizeof CA_FILES / sizeof *CA_FILES; i++) {
    /* > 0: that many certificates in it didn't parse, the rest did */
    loaded = access(CA_FILES[i], R_OK) == 0 &&
             mbedtls_x509_crt_parse_file(&g_ca, CA_FILES[i]) >= 0;
  }
  if (!loaded || g_ca.raw.len == 0) {
    mbedtls_x509_crt_free(&g_ca);
    snprintf(err, err_cap, "TLS: no CA certificates (set SSL_CERT_FILE)");
    return -1;
  }
  mbedtls_ssl_config_init(&g_conf);
  int ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    why(ret, "config", err, err_cap);
    mbedtls_ssl_config_free(&g_conf);
    mbedtls_x509_crt_free(&g_ca);
    return -1;
  }
  mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&g_conf, &g_ca, NULL);
  return 0;
}

static void lock(void) { pthread_mutex_lock(&g_lock); }
static void unlock(void) { pthread_mutex_unlock(&g_lock); }

static void setup_run(void) { g_ready = setup_once(g_err, sizeof g_err) == 0; }

static int setup(char *err, size_t err_cap) {
  lock();
  pthread_once(&g_once, setup_run);
  unlock();
  if (!g_ready) {
    snprintf(err, err_cap, "%s", g_err);
    return -1;
  }
  return 0;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
  ssize_t w = send(*(int *)ctx, buf, len, MSG_NOSIGNAL);
  if (w < 0) {
    return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_WRITE
                                             : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  return (int)w;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
  ssize_t r = recv(*(int *)ctx, buf, len, 0);
  if (r < 0) {
    return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_READ
                                             : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  return (int)r;
}

/* after a WANT_READ/WANT_WRITE: the socket ready before deadline (0), or
 * -1; any other ret is an error (-1, why in err) */
static int again(CTUI_WM_TLS *t, int ret, const char *what, long deadline,
                 char *err, size_t err_cap) {
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    return ctui_wm_net_wait(t->fd, POLLIN, deadline, err, err_cap);
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return ctui_wm_net_wait(t->fd, POLLOUT, deadline, err, err_cap);
  }
  why(ret, what, err, err_cap);
  return -1;
}

CTUI_WM_TLS *ctui_wm_tls_open(int fd, const char *host, long deadline,
                              char *err, size_t err_cap) {
  if (setup(err, err_cap) != 0) {
    return NULL;
  }
  CTUI_WM_TLS *t = calloc(1, sizeof *t);
  if (!t) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  t->fd = fd;
  lock();
  mbedtls_ssl_init(&t->ssl);
  int ret = mbedtls_ssl_setup(&t->ssl, &g_conf);
  if (ret == 0) {
    ret = mbedtls_ssl_set_hostname(&t->ssl, host);
  }
  mbedtls_ssl_set_bio(&t->ssl, &t->fd, bio_send, bio_recv, NULL);
  unlock();
  if (ret != 0) {
    why(ret, "setup", err, err_cap);
    goto fail;
  }
  for (;;) {
    lock();
    ret = mbedtls_ssl_handshake(&t->ssl);
    uint32_t verify = mbedtls_ssl_get_verify_result(&t->ssl);
    unlock();
    if (ret == 0) {
      break;
    }
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
      char info[256];
      mbedtls_x509_crt_verify_info(info, sizeof info, "", verify);
      info[strcspn(info, "\n")] = '\0';
      snprintf(err, err_cap, "TLS: %s's certificate: %s", host, info);
      goto fail;
    }
    if (again(t, ret, "handshake", deadline, err, err_cap) != 0) {
      goto fail;
    }
  }
  return t;
fail:
  lock();
  mbedtls_ssl_free(&t->ssl);
  unlock();
  free(t);
  return NULL;
}

int ctui_wm_tls_write(CTUI_WM_TLS *t, const char *buf, size_t n, long deadline,
                      char *err, size_t err_cap) {
  while (n > 0) {
    lock();
    int w = mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf, n);
    unlock();
    if (w > 0) {
      buf += w;
      n -= (size_t)w;
    } else if (again(t, w, "sending", deadline, err, err_cap) != 0) {
      return -1;
    }
  }
  return 0;
}

ssize_t ctui_wm_tls_read(CTUI_WM_TLS *t, char *buf, size_t n, long deadline,
                         char *err, size_t err_cap) {
  for (;;) {
    lock();
    int r = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, n);
    unlock();
    if (r >= 0) {
      return r;
    }
    /* the end: with a close_notify, or (as many servers do) without; the
     * HTTP reply's own length tells a cut-off one apart */
    if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
        r == MBEDTLS_ERR_SSL_CONN_EOF) {
      return 0;
    }
    /* TLS 1.3 hands out session tickets after the handshake */
    if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      continue;
    }
    if (again(t, r, "receiving", deadline, err, err_cap) != 0) {
      return -1;
    }
  }
}

size_t ctui_wm_tls_pending(const CTUI_WM_TLS *t) {
  lock();
  size_t n = mbedtls_ssl_get_bytes_avail(&t->ssl);
  unlock();
  return n;
}

void ctui_wm_tls_close(CTUI_WM_TLS *t) {
  if (!t) {
    return;
  }
  lock();
  mbedtls_ssl_close_notify(&t->ssl);
  mbedtls_ssl_free(&t->ssl);
  unlock();
  free(t);
}
