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

#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct SET SET;

struct CSERVE_TLS {
  int fd;
  mbedtls_ssl_context ssl;
  char host[256]; /* the name the server's certificate must carry ("" on
                     the server side: the client's is checked) */
  SET *set;       /* a names server's set it began under (one ref), or NULL */
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

long cserve_tls_pem_next(const char *buf, size_t len, size_t *pos,
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
 * certificates 4-8 ms -> 0.6 ms; ctui-wm's notes/self-improving.md (where this
 * began), session 219) -- certificates are public. A file without PEM blocks
 * (one DER certificate) goes to mbedtls whole. */
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
  while (der && (n = cserve_tls_pem_next(buf, len, &pos, der)) != 0) {
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

void cserve_crypto_lock(void) { lock(); }
void cserve_crypto_unlock(void) { unlock(); }

int cserve_crypto_start(void) {
  lock();
  int ok = psa_crypto_init() == PSA_SUCCESS;
  unlock();
  return ok ? 0 : -1;
}

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
static int again(CSERVE_TLS *t, int ret, const char *what, long deadline,
                 char *err, size_t err_cap) {
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    return cserve_net_wait(t->fd, POLLIN, deadline, err, err_cap);
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return cserve_net_wait(t->fd, POLLOUT, deadline, err, err_cap);
  }
  why(ret, what, err, err_cap);
  return -1;
}

/* a connection on fd under conf, its handshake not begun (host: the
 * name the server's certificate must carry, NULL on the server side), or
 * NULL with why in err */
static CSERVE_TLS *start(int fd, const mbedtls_ssl_config *conf,
                         const char *host, char *err, size_t err_cap) {
  CSERVE_TLS *t = calloc(1, sizeof *t);
  if (!t) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  t->fd = fd;
  snprintf(t->host, sizeof t->host, "%s", host ? host : "");
  lock();
  mbedtls_ssl_init(&t->ssl);
  int ret = mbedtls_ssl_setup(&t->ssl, conf);
  if (ret == 0 && host) {
    ret = mbedtls_ssl_set_hostname(&t->ssl, host);
  }
  mbedtls_ssl_set_bio(&t->ssl, &t->fd, bio_send, bio_recv, NULL);
  if (ret != 0) {
    mbedtls_ssl_free(&t->ssl);
  }
  unlock();
  if (ret != 0) {
    why(ret, "setup", err, err_cap);
    free(t);
    return NULL;
  }
  return t;
}

/* mbedtls's WANT_READ/WANT_WRITE as this seam's */
static int want(int ret) {
  return ret == MBEDTLS_ERR_SSL_WANT_READ    ? CSERVE_TLS_WANT_READ
         : ret == MBEDTLS_ERR_SSL_WANT_WRITE ? CSERVE_TLS_WANT_WRITE
                                             : 0;
}

int cserve_tls_step(CSERVE_TLS *t, char *err, size_t err_cap) {
  lock();
  int ret = mbedtls_ssl_handshake(&t->ssl);
  uint32_t verify = mbedtls_ssl_get_verify_result(&t->ssl);
  /* pick() refused the name: mbedtls says nothing to the client, so the
   * alert is sent here (as far as the socket takes it at once) */
  if (ret == MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME) {
    (void)mbedtls_ssl_send_alert_message(
        &t->ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
        MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME);
  }
  unlock();
  if (ret == 0) {
    return 0;
  }
  if (want(ret)) {
    return want(ret);
  }
  if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
    char info[256];
    mbedtls_x509_crt_verify_info(info, sizeof info, "", verify);
    info[strcspn(info, "\n")] = '\0';
    snprintf(err, err_cap, "TLS: %s's certificate: %s",
             t->host[0] ? t->host : "the client", info);
    return -1;
  }
  why(ret, "handshake", err, err_cap);
  return -1;
}

static void set_release(SET *set);

/* t freed, and its set's ref given back (no close_notify) */
static void tls_free(CSERVE_TLS *t) {
  lock();
  mbedtls_ssl_free(&t->ssl);
  set_release(t->set);
  unlock();
  free(t);
}

/* a started connection (or NULL), its handshake done before deadline, or
 * NULL (t freed) */
static CSERVE_TLS *finish(CSERVE_TLS *t, long deadline, char *err,
                          size_t err_cap) {
  for (int ret; t && (ret = cserve_tls_step(t, err, err_cap)) != 0;) {
    if (ret == -1 ||
        cserve_net_wait(t->fd, ret == CSERVE_TLS_WANT_READ ? POLLIN : POLLOUT,
                        deadline, err, err_cap) != 0) {
      tls_free(t);
      return NULL;
    }
  }
  return t;
}

/* start()'s connection, its handshake done before deadline, or NULL */
static CSERVE_TLS *handshake(int fd, const mbedtls_ssl_config *conf,
                             const char *host, long deadline, char *err,
                             size_t err_cap) {
  return finish(start(fd, conf, host, err, err_cap), deadline, err, err_cap);
}

CSERVE_TLS *cserve_tls_open(int fd, const char *host, long deadline, char *err,
                            size_t err_cap) {
  if (setup(err, err_cap) != 0) {
    return NULL;
  }
  return handshake(fd, &g_conf, host, deadline, err, err_cap);
}

/* a server's config: TLS 1.3, nothing older */
static void only_tls13(mbedtls_ssl_config *conf) {
  mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
  mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
}

/* one side's own config: its certificate chain and key (a server's, or
 * a client's that presents one), the CA it checks the other side
 * against */
typedef struct {
  mbedtls_ssl_config conf;
  mbedtls_x509_crt chain, ca;
  mbedtls_pk_context key;
} SIDE;

struct CSERVE_TLS_SERVER {
  SIDE side; /* a server of one certificate's */
  /* a names server's (cserve_tls_names_new()): its set now (under the
   * lock), and the directory it's read from */
  SET *set;
  char dir[PATH_MAX];
};
struct CSERVE_TLS_CLIENT {
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
  if (ret == 0 && endpoint == MBEDTLS_SSL_IS_SERVER) {
    only_tls13(&s->conf);
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

CSERVE_TLS_SERVER *cserve_tls_server_new(const char *cert, const char *key,
                                         const char *client_ca, char *err,
                                         size_t err_cap) {
  CSERVE_TLS_SERVER *s = calloc(1, sizeof *s);
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

void cserve_tls_server_free(CSERVE_TLS_SERVER *s) {
  if (!s) {
    return;
  }
  if (s->dir[0]) {
    lock();
    set_release(s->set);
    unlock();
  } else {
    side_free(&s->side);
  }
  free(s);
}

/* --- many names, picked by SNI --- */

#define NAMES_MAX 32

typedef struct {
  char name[254];
  mbedtls_x509_crt chain;
  mbedtls_pk_context key;
} NAMED;

/* one reading of a names server's directory: freed when its last ref
 * goes -- the server's own, or a connection's that began under it.
 * refs is the lock's. */
struct SET {
  int refs;
  mbedtls_ssl_config conf;
  int n;
  NAMED names[NAMES_MAX];
};

int cserve_tls_name_ok(const char *name, size_t n) {
  if (n == 0 || n > 253) {
    return 0;
  }
  size_t label = 0;
  for (size_t i = 0; i < n; i++) {
    char c = name[i];
    if (c == '.') {
      if (label == 0 || name[i - 1] == '-') {
        return 0;
      }
      label = 0;
    } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               (c == '-' && label > 0)) {
      if (++label > 63) {
        return 0;
      }
    } else {
      return 0;
    }
  }
  return label > 0 && name[n - 1] != '-';
}

/* set's entry for host (n bytes, any case), or NULL; under the lock */
static NAMED *find(SET *set, const char *host, size_t n) {
  for (int i = 0; set && i < set->n; i++) {
    if (strlen(set->names[i].name) == n &&
        strncasecmp(set->names[i].name, host, n) == 0) {
      return &set->names[i];
    }
  }
  return NULL;
}

/* under the lock */
static void set_release(SET *set) {
  if (!set || --set->refs > 0) {
    return;
  }
  mbedtls_ssl_config_free(&set->conf);
  for (int i = 0; i < set->n; i++) {
    mbedtls_x509_crt_free(&set->names[i].chain);
    mbedtls_pk_free(&set->names[i].key);
  }
  free(set);
}

/* the handshake's certificate, by the name the client asked for: mbedtls
 * calls it (under the lock) once the ClientHello is read, SNI or none */
static int pick(mbedtls_ssl_context *ssl) {
  CSERVE_TLS *t = (CSERVE_TLS *)((char *)ssl - offsetof(CSERVE_TLS, ssl));
  size_t n = 0;
  const unsigned char *sni = mbedtls_ssl_get_hs_sni(ssl, &n);
  NAMED *e = sni ? find(t->set, (const char *)sni, n) : NULL;
  if (!e) {
    return MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME;
  }
  return mbedtls_ssl_set_hs_own_cert(ssl, &e->chain, &e->key);
}

/* 1 when crt's subjectAltName carries name as a DNS name */
static int carries(const mbedtls_x509_crt *crt, const char *name) {
  size_t n = strlen(name);
  for (const mbedtls_x509_sequence *s = &crt->subject_alt_names; s;
       s = s->next) {
    if (s->buf.tag ==
            (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME) &&
        s->buf.len == n && strncasecmp((const char *)s->buf.p, name, n) == 0) {
      return 1;
    }
  }
  return 0;
}

/* dir/name's pair into e: 0, or -1 with why in err; under the lock (e's
 * contexts inited, freed by the caller either way) */
static int named_load(NAMED *e, const char *dir, const char *name, char *err,
                      size_t err_cap) {
  char cert[PATH_MAX], key[PATH_MAX];
  snprintf(e->name, sizeof e->name, "%s", name);
  if (snprintf(cert, sizeof cert, "%s/%s/cert.pem", dir, name) >=
          (int)sizeof cert ||
      snprintf(key, sizeof key, "%s/%s/key.pem", dir, name) >=
          (int)sizeof key) {
    snprintf(err, err_cap, "TLS: %s/%s: too long a path", dir, name);
    return -1;
  }
  const char *files[] = {cert, key};
  for (int i = 0; i < 2; i++) {
    if (access(files[i], R_OK) != 0) {
      snprintf(err, err_cap, "TLS: %s: %s", files[i], strerror(errno));
      return -1;
    }
  }
  int ret = mbedtls_x509_crt_parse_file(&e->chain, cert);
  if (ret != 0) {
    why(ret, cert, err, err_cap);
    return -1;
  }
  if ((ret = mbedtls_pk_parse_keyfile(&e->key, key, NULL)) != 0) {
    why(ret, key, err, err_cap);
    return -1;
  }
  if (mbedtls_pk_get_bitlen(&e->key) != 256 ||
      mbedtls_pk_get_key_type(&e->key) !=
          PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
    snprintf(err, err_cap, "TLS: %s: not a P-256 key", key);
    return -1;
  }
  if (mbedtls_pk_check_pair(&e->chain.pk, &e->key) != 0) {
    snprintf(err, err_cap, "TLS: %s: not the key of %s", key, cert);
    return -1;
  }
  if (!carries(&e->chain, name)) {
    snprintf(err, err_cap, "TLS: %s: not a certificate for %s", cert, name);
    return -1;
  }
  return 0;
}

/* dir read into a set (one ref), or NULL with why in err */
static SET *set_load(const char *dir, char *err, size_t err_cap) {
  lock();
  int psa = psa_crypto_init();
  unlock();
  if (psa != PSA_SUCCESS) {
    snprintf(err, err_cap, "TLS: the crypto library didn't start");
    return NULL;
  }
  DIR *d = opendir(dir);
  if (!d) {
    snprintf(err, err_cap, "TLS: %s: %s", dir, strerror(errno));
    return NULL;
  }
  SET *set = calloc(1, sizeof *set);
  if (!set) {
    closedir(d);
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  set->refs = 1;
  lock();
  mbedtls_ssl_config_init(&set->conf);
  int bad = 0;
  for (const struct dirent *de; !bad && (de = readdir(d));) {
    const char *name = de->d_name;
    if (name[0] == '.') {
      continue; /* ".", "..", and a writer's work in progress */
    }
    if (!cserve_tls_name_ok(name, strlen(name))) {
      snprintf(err, err_cap, "TLS: %s/%s: not a lowercase DNS name", dir, name);
      bad = 1;
    } else if (set->n == NAMES_MAX) {
      snprintf(err, err_cap, "TLS: %s: more than %d names", dir, NAMES_MAX);
      bad = 1;
    } else {
      NAMED *e = &set->names[set->n++];
      mbedtls_x509_crt_init(&e->chain);
      mbedtls_pk_init(&e->key);
      bad = named_load(e, dir, name, err, err_cap) != 0;
    }
  }
  closedir(d);
  int ret = bad ? 0
                : mbedtls_ssl_config_defaults(&set->conf, MBEDTLS_SSL_IS_SERVER,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT);
  if (!bad && ret != 0) {
    why(ret, "config", err, err_cap);
    bad = 1;
  }
  if (!bad) {
    only_tls13(&set->conf);
    mbedtls_ssl_conf_authmode(&set->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_cert_cb(&set->conf, pick);
  }
  if (bad) {
    set_release(set);
    set = NULL;
  }
  unlock();
  return set;
}

CSERVE_TLS_SERVER *cserve_tls_names_new(const char *dir, char *err,
                                        size_t err_cap) {
  CSERVE_TLS_SERVER *s = calloc(1, sizeof *s);
  if (!s) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  if (!*dir ||
      snprintf(s->dir, sizeof s->dir, "%s", dir) >= (int)sizeof s->dir) {
    snprintf(err, err_cap, "TLS: %s: not a directory's path", dir);
    free(s);
    return NULL;
  }
  if (!(s->set = set_load(dir, err, err_cap))) {
    free(s);
    return NULL;
  }
  return s;
}

int cserve_tls_names_reload(CSERVE_TLS_SERVER *s, char *err, size_t err_cap) {
  if (!s->dir[0]) {
    snprintf(err, err_cap, "TLS: not a server of names");
    return -1;
  }
  SET *set = set_load(s->dir, err, err_cap);
  if (!set) {
    return -1;
  }
  lock();
  SET *old = s->set;
  s->set = set;
  set_release(old);
  unlock();
  return 0;
}

int cserve_tls_names_count(CSERVE_TLS_SERVER *s) {
  lock();
  int n = s->dir[0] && s->set ? s->set->n : 0;
  unlock();
  return n;
}

int cserve_tls_names_has(CSERVE_TLS_SERVER *s, const char *host, size_t n) {
  lock();
  int has = s->dir[0] && find(s->set, host, n) != NULL;
  unlock();
  return has;
}

/* a server's connection on fd, its handshake not begun: under the set
 * it has now, which it holds to its end */
static CSERVE_TLS *server_start(int fd, CSERVE_TLS_SERVER *s, char *err,
                                size_t err_cap) {
  if (!s->dir[0]) {
    return start(fd, &s->side.conf, NULL, err, err_cap);
  }
  lock();
  SET *set = s->set;
  set->refs++;
  unlock();
  CSERVE_TLS *t = start(fd, &set->conf, NULL, err, err_cap);
  if (!t) {
    lock();
    set_release(set);
    unlock();
    return NULL;
  }
  t->set = set;
  return t;
}

CSERVE_TLS_CLIENT *cserve_tls_client_new(const char *ca, const char *cert,
                                         const char *key, char *err,
                                         size_t err_cap) {
  if (!cert != !key) {
    snprintf(err, err_cap, "TLS: a client certificate needs its key");
    return NULL;
  }
  CSERVE_TLS_CLIENT *c = calloc(1, sizeof *c);
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

void cserve_tls_client_free(CSERVE_TLS_CLIENT *c) {
  if (!c) {
    return;
  }
  side_free(&c->side);
  free(c);
}

CSERVE_TLS *cserve_tls_connect(int fd, const char *host, CSERVE_TLS_CLIENT *c,
                               long deadline, char *err, size_t err_cap) {
  return handshake(fd, &c->side.conf, host, deadline, err, err_cap);
}

int cserve_tls_peer(CSERVE_TLS *t, char *cn, size_t cn_cap, char fpr[65]) {
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

CSERVE_TLS *cserve_tls_accept(int fd, CSERVE_TLS_SERVER *s, long deadline,
                              char *err, size_t err_cap) {
  return finish(server_start(fd, s, err, err_cap), deadline, err, err_cap);
}

CSERVE_TLS *cserve_tls_server_start(int fd, CSERVE_TLS_SERVER *s, char *err,
                                    size_t err_cap) {
  return server_start(fd, s, err, err_cap);
}

long cserve_tls_send(CSERVE_TLS *t, const char *buf, size_t n, char *err,
                     size_t err_cap) {
  lock();
  int w = mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf, n);
  unlock();
  if (w > 0 || want(w)) {
    return w > 0 ? w : want(w);
  }
  why(w, "sending", err, err_cap);
  return -1;
}

long cserve_tls_recv(CSERVE_TLS *t, char *buf, size_t n, char *err,
                     size_t err_cap) {
  for (;;) {
    lock();
    int r = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, n);
    unlock();
    if (r >= 0) {
      return r;
    }
    if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
        r == MBEDTLS_ERR_SSL_CONN_EOF) {
      return 0;
    }
    if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      continue;
    }
    if (want(r)) {
      return want(r);
    }
    why(r, "receiving", err, err_cap);
    return -1;
  }
}

int cserve_tls_write(CSERVE_TLS *t, const char *buf, size_t n, long deadline,
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

ssize_t cserve_tls_read(CSERVE_TLS *t, char *buf, size_t n, long deadline,
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

size_t cserve_tls_pending(const CSERVE_TLS *t) {
  lock();
  size_t n = mbedtls_ssl_get_bytes_avail(&t->ssl);
  unlock();
  return n;
}

void cserve_tls_close(CSERVE_TLS *t) {
  if (!t) {
    return;
  }
  lock();
  mbedtls_ssl_close_notify(&t->ssl);
  mbedtls_ssl_free(&t->ssl);
  set_release(t->set);
  unlock();
  free(t);
}
