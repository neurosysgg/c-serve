/* The TLS seam's mbedtls 4 side (tls.h): PSA crypto underneath, so no
 * RNG to wire up; the CA bundle parsed once per process, whichever thread
 * gets there first (ctui-mail checks its accounts in parallel). mbedtls
 * as distributions build it has no MBEDTLS_THREADING_C, so PSA's key
 * slots and RNG are unguarded: every mbedtls call runs under one lock,
 * never held across the poll() waits, so connections still overlap on
 * the network and only the crypto takes turns. */
#define _GNU_SOURCE /* memmem */
#include "tls.h"

#include "conn.h"

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <errno.h>
#include <fcntl.h>
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

/* base64's value of each byte, or what else it is to a PEM body */
enum { B64_BAD = -1, B64_SPACE = -2, B64_LF = -3, B64_CR = -4, B64_PAD = -5 };
/* clang-format off */
static const signed char B64[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -3, -1, -1, -4, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -5, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
/* clang-format on */

long ctui_wm_tls_pem_next(const char *buf, size_t len, size_t *pos,
                          unsigned char *der) {
  static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
  static const char END[] = "-----END CERTIFICATE-----";
  if (*pos > len) {
    return 0;
  }
  const char *b = memmem(buf + *pos, len - *pos, BEGIN, sizeof BEGIN - 1);
  if (!b) {
    *pos = len;
    return 0;
  }
  b += sizeof BEGIN - 1;
  const char *e = memmem(b, (size_t)(buf + len - b), END, sizeof END - 1);
  if (!e) {
    *pos = len;
    return 0;
  }
  *pos = (size_t)(e - buf) + sizeof END - 1;
  /* base64 between them, by mbedtls_base64_decode()'s rules: line breaks
   * (\n, \r\n), spaces only before one or at the end, '=' only at the
   * end (at most two, the symbols a multiple of 4 with them) */
  size_t n = 0, syms = 0, pad = 0;
  unsigned acc = 0;
  int bits = 0;
  int spaces = 0;
  for (const char *c = b; c < e; c++) {
    int v = B64[(unsigned char)*c];
    if (v >= 0 && !spaces && !pad) {
      syms++;
      acc = acc << 6 | (unsigned)v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        der[n++] = (unsigned char)(acc >> bits);
      }
      continue;
    }
    if (v == B64_SPACE) {
      spaces = 1;
    } else if (v == B64_LF || (v == B64_CR && c + 1 < e && c[1] == '\n')) {
      c += v == B64_CR;
      spaces = 0;
    } else if (v == B64_PAD && !spaces && pad < 2) {
      pad++;
      syms++;
    } else {
      return -1; /* a space inside a line, a symbol after '=', ... */
    }
  }
  return syms % 4 == 0 && n > 0 ? (long)n : -1;
}

/* path's certificates into ca: >= 0 when any parsed (as
 * mbedtls_x509_crt_parse_file() counts: how many didn't), else < 0. PEM
 * decoded here and handed over as DER: mbedtls's own base64 is constant
 * time (for secret keys), ~7x slower on the system bundle (121
 * certificates 4-8 ms -> 0.6 ms; ctui-wm's notes/self-improving.md,
 * session 219) -- certificates are public. A file without PEM blocks (one
 * DER certificate) goes to mbedtls whole. */
static int parse_bundle(mbedtls_x509_crt *ca, const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  char *buf = NULL;
  size_t len = 0, cap = 0;
  int bad = 0;
  for (;;) {
    if (len == cap) {
      cap = cap ? cap * 2 : 256 * 1024;
      char *p = realloc(buf, cap);
      if (!p) {
        bad = 1;
        break;
      }
      buf = p;
    }
    ssize_t got = read(fd, buf + len, cap - len);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      bad = got < 0;
      break;
    }
    len += (size_t)got;
  }
  close(fd);
  unsigned char *der = bad ? NULL : malloc(len ? len : 1);
  int ok = 0, failed = 0, blocks = 0;
  size_t pos = 0;
  long n;
  while (der && (n = ctui_wm_tls_pem_next(buf, len, &pos, der)) != 0) {
    blocks++;
    if (n > 0 && mbedtls_x509_crt_parse_der(ca, der, (size_t)n) == 0) {
      ok++;
    } else {
      failed++;
    }
  }
  free(der);
  free(buf);
  if (bad) {
    return -1;
  }
  if (blocks == 0) {
    return mbedtls_x509_crt_parse_file(ca, path);
  }
  return ok ? failed : -1;
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
    loaded = parse_bundle(&g_ca, env) >= 0;
  }
  for (size_t i = 0; !loaded && i < sizeof CA_FILES / sizeof *CA_FILES; i++) {
    /* > 0: that many certificates in it didn't parse, the rest did */
    loaded =
        access(CA_FILES[i], R_OK) == 0 && parse_bundle(&g_ca, CA_FILES[i]) >= 0;
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

/* a connection on fd under conf, its handshake done (host: the name the
 * server's certificate must carry, NULL on the server side), or NULL */
static CTUI_WM_TLS *handshake(int fd, const mbedtls_ssl_config *conf,
                              const char *host, long deadline, char *err,
                              size_t err_cap) {
  CTUI_WM_TLS *t = calloc(1, sizeof *t);
  if (!t) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  t->fd = fd;
  lock();
  mbedtls_ssl_init(&t->ssl);
  int ret = mbedtls_ssl_setup(&t->ssl, conf);
  if (ret == 0 && host) {
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
      snprintf(err, err_cap, "TLS: %s's certificate: %s",
               host ? host : "the client", info);
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

CTUI_WM_TLS *ctui_wm_tls_open(int fd, const char *host, long deadline,
                              char *err, size_t err_cap) {
  if (setup(err, err_cap) != 0) {
    return NULL;
  }
  return handshake(fd, &g_conf, host, deadline, err, err_cap);
}

/* one side's own config: its certificate chain and key (a server's, or
 * a client's that presents one), the CA it checks the other side
 * against */
typedef struct {
  mbedtls_ssl_config conf;
  mbedtls_x509_crt chain, ca;
  mbedtls_pk_context key;
} SIDE;

struct CTUI_WM_TLS_SERVER {
  SIDE side;
};
struct CTUI_WM_TLS_CLIENT {
  SIDE side;
};

static void side_free(SIDE *s) {
  lock();
  mbedtls_ssl_config_free(&s->conf);
  mbedtls_x509_crt_free(&s->chain);
  mbedtls_x509_crt_free(&s->ca);
  mbedtls_pk_free(&s->key);
  unlock();
}

/* s set up as endpoint (MBEDTLS_SSL_IS_SERVER/CLIENT) from the PEM files
 * (cert and key: both or neither; ca: NULL = the other side isn't
 * checked; on a client the system's bundle instead): 0, or -1 with why
 * in err (s freed then) */
static int side_init(SIDE *s, int endpoint, const char *cert, const char *key,
                     const char *ca, char *err, size_t err_cap) {
  /* the client's setup starts PSA crypto; its CA bundle is only needed
   * by a client without a CA of its own */
  if (endpoint == MBEDTLS_SSL_IS_CLIENT && !ca) {
    if (setup(err, err_cap) != 0) {
      return -1;
    }
  } else {
    lock();
    int psa = psa_crypto_init();
    unlock();
    if (psa != PSA_SUCCESS) {
      snprintf(err, err_cap, "TLS: the crypto library didn't start");
      return -1;
    }
  }
  /* mbedtls says a missing file only as a number */
  const char *files[] = {cert, key, ca};
  for (int i = 0; i < 3; i++) {
    if (files[i] && access(files[i], R_OK) != 0) {
      snprintf(err, err_cap, "TLS: %s: %s", files[i], strerror(errno));
      return -1;
    }
  }
  lock();
  mbedtls_ssl_config_init(&s->conf);
  mbedtls_x509_crt_init(&s->chain);
  mbedtls_x509_crt_init(&s->ca);
  mbedtls_pk_init(&s->key);
  int ret = 0;
  const char *what = cert;
  if (cert) {
    ret = mbedtls_x509_crt_parse_file(&s->chain, cert);
  }
  if (ret == 0 && key) {
    what = key;
    ret = mbedtls_pk_parse_keyfile(&s->key, key, NULL);
  }
  if (ret == 0 && ca) {
    what = ca;
    ret = mbedtls_x509_crt_parse_file(&s->ca, ca);
  }
  if (ret == 0) {
    what = "config";
    ret = mbedtls_ssl_config_defaults(&s->conf, endpoint,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
  }
  if (ret == 0 && cert && key) {
    ret = mbedtls_ssl_conf_own_cert(&s->conf, &s->chain, &s->key);
  }
  if (ret == 0) {
    int checked = ca || endpoint == MBEDTLS_SSL_IS_CLIENT;
    mbedtls_ssl_conf_authmode(&s->conf, checked ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                : MBEDTLS_SSL_VERIFY_NONE);
    if (checked) {
      mbedtls_ssl_conf_ca_chain(&s->conf, ca ? &s->ca : &g_ca, NULL);
    }
  }
  unlock();
  if (ret != 0) {
    why(ret, what, err, err_cap);
    side_free(s);
    return -1;
  }
  return 0;
}

CTUI_WM_TLS_SERVER *ctui_wm_tls_server_new(const char *cert, const char *key,
                                           const char *client_ca, char *err,
                                           size_t err_cap) {
  CTUI_WM_TLS_SERVER *s = calloc(1, sizeof *s);
  if (!s) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  if (side_init(&s->side, MBEDTLS_SSL_IS_SERVER, cert, key, client_ca, err,
                err_cap) != 0) {
    free(s);
    return NULL;
  }
  return s;
}

void ctui_wm_tls_server_free(CTUI_WM_TLS_SERVER *s) {
  if (!s) {
    return;
  }
  side_free(&s->side);
  free(s);
}

CTUI_WM_TLS_CLIENT *ctui_wm_tls_client_new(const char *ca, const char *cert,
                                           const char *key, char *err,
                                           size_t err_cap) {
  if (!cert != !key) {
    snprintf(err, err_cap, "TLS: a client certificate needs its key");
    return NULL;
  }
  CTUI_WM_TLS_CLIENT *c = calloc(1, sizeof *c);
  if (!c) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  if (side_init(&c->side, MBEDTLS_SSL_IS_CLIENT, cert, key, ca, err, err_cap) !=
      0) {
    free(c);
    return NULL;
  }
  return c;
}

void ctui_wm_tls_client_free(CTUI_WM_TLS_CLIENT *c) {
  if (!c) {
    return;
  }
  side_free(&c->side);
  free(c);
}

CTUI_WM_TLS *ctui_wm_tls_connect(int fd, const char *host,
                                 CTUI_WM_TLS_CLIENT *c, long deadline,
                                 char *err, size_t err_cap) {
  return handshake(fd, &c->side.conf, host, deadline, err, err_cap);
}

int ctui_wm_tls_peer(CTUI_WM_TLS *t, char *cn, size_t cn_cap, char fpr[65]) {
  if (cn_cap) {
    cn[0] = '\0';
  }
  fpr[0] = '\0';
  lock();
  const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&t->ssl);
  unsigned char hash[32];
  size_t hl = 0;
  int ok = crt && crt->raw.len &&
           psa_hash_compute(PSA_ALG_SHA_256, crt->raw.p, crt->raw.len, hash,
                            sizeof hash, &hl) == PSA_SUCCESS &&
           hl == sizeof hash;
  /* the subject's (last) common name, printable bytes only: it ends up in
   * a CGI's environment */
  static const unsigned char OID_CN[] = {0x55, 0x04, 0x03};
  for (const mbedtls_x509_name *n = ok ? &crt->subject : NULL; n; n = n->next) {
    if (n->oid.len == sizeof OID_CN && n->oid.p &&
        memcmp(n->oid.p, OID_CN, sizeof OID_CN) == 0 && cn_cap) {
      size_t k = 0;
      for (size_t i = 0; i < n->val.len && k + 1 < cn_cap; i++) {
        unsigned char ch = n->val.p[i];
        cn[k++] = ch < 0x20 || ch == 0x7f ? '?' : (char)ch;
      }
      cn[k] = '\0';
    }
  }
  unlock();
  if (!ok) {
    return -1;
  }
  for (size_t i = 0; i < sizeof hash; i++) {
    snprintf(fpr + 2 * i, 3, "%02x", hash[i]);
  }
  return 0;
}

CTUI_WM_TLS *ctui_wm_tls_accept(int fd, CTUI_WM_TLS_SERVER *s, long deadline,
                                char *err, size_t err_cap) {
  return handshake(fd, &s->side.conf, NULL, deadline, err, err_cap);
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
