/* cserve-acme: certificates from an ACME server (RFC 8555), by HTTP-01,
 * for the names cserve serves (tls.h's --certs). Run it now and then (a
 * timer): each --name whose certificate is missing or ends within --days
 * gets a new one -- its own order, its own fresh P-256 key -- and the
 * rest are left alone. Its answers to the challenges go into --challenges
 * as files named by their token, which cserve's plain listener serves
 * (--acme-dir there); the certificate and its key go into
 * --certs/NAME/{cert,key}.pem, each written beside its place and renamed
 * into it, the key first. It signals nobody: whatever runs it tells cserve
 * (SIGHUP) once it's done, so the account key never shares a process
 * with what faces the internet.
 *
 * Exit: 0 when every name has a certificate good for --days (one made
 * now or one already there), 1 when any doesn't, 2 for usage. */
/* setenv, mkdtemp, fsync: POSIX, not C11 */
#define _GNU_SOURCE
#include "acme.h"
#include "http.h"
#include "net.h"
#include "tls.h"

#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NAMES_MAX 32
#define POLLS 60 /* a status asked again at most this many times */

typedef struct {
  const char *certs, *challenges;
  CSERVE_ACME_KEY account;
  CSERVE_ACME_DIRECTORY dir;
  char kid[CSERVE_ACME_URL];
  char nonce[256];
} CLIENT;

static int usage(void) {
  fprintf(stderr,
          "usage: cserve-acme --directory URL [--ca FILE] --account KEY\n"
          "       --certs DIR --challenges DIR --name NAME... [--days N]\n"
          "       [--force]\n");
  return 2;
}

/* the reply's Replay-Nonce kept for the next request, when it has one */
static void keep_nonce(CLIENT *c, const CSERVE_HTTP_REPLY *rep) {
  char n[256];
  if (cserve_http_reply_header(rep, "Replay-Nonce", n, sizeof n) &&
      cserve_acme_token_ok(n, strlen(n))) {
    memcpy(c->nonce, n, sizeof n);
  }
}

/* a GET of url: 0 with rep filled, or -1 with why in err */
static int get(const char *url, CSERVE_HTTP_REPLY *rep, char *err,
               size_t err_cap) {
  CSERVE_HTTP_REQ req = {.url = url, .agent = "c-serve-acme"};
  memset(rep, 0, sizeof *rep);
  return cserve_net_http(&req, rep, err, err_cap);
}

static int fresh_nonce(CLIENT *c, char *err, size_t err_cap) {
  CSERVE_HTTP_REPLY rep;
  if (get(c->dir.new_nonce, &rep, err, err_cap) != 0) {
    return -1;
  }
  c->nonce[0] = '\0';
  keep_nonce(c, &rep);
  free(rep.body);
  if (!c->nonce[0]) {
    snprintf(err, err_cap, "newNonce gave no Replay-Nonce");
    return -1;
  }
  return 0;
}

/* payload POSTed to url as a JWS (the account's kid once it has one, else
 * its JWK), a badNonce retried once with the nonce it came with: 0 with
 * rep filled (any status), or -1 with why in err */
static int post(CLIENT *c, const char *url, const char *payload,
                CSERVE_HTTP_REPLY *rep, char *err, size_t err_cap) {
  /* nothing of an earlier reply left in it, whichever way this returns */
  memset(rep, 0, sizeof *rep);
  for (int attempt = 0;; attempt++) {
    if (!c->nonce[0] && fresh_nonce(c, err, err_cap) != 0) {
      return -1;
    }
    char *jws = cserve_acme_jws(&c->account, c->kid[0] ? c->kid : NULL,
                                c->nonce, url, payload, err, err_cap);
    if (!jws) {
      return -1;
    }
    c->nonce[0] = '\0'; /* spent */
    static const char *const accept[] = {
        "Accept: application/pem-certificate-chain, application/json", NULL};
    CSERVE_HTTP_REQ req = {.method = "POST",
                           .url = url,
                           .content_type = "application/jose+json",
                           .body = jws,
                           .body_len = strlen(jws),
                           .headers = accept,
                           .agent = "c-serve-acme"};
    memset(rep, 0, sizeof *rep);
    int rc = cserve_net_http(&req, rep, err, err_cap);
    free(jws);
    if (rc != 0) {
      return -1;
    }
    keep_nonce(c, rep);
    CSERVE_ACME_PROBLEM p;
    cserve_acme_problem(rep->body, &p);
    if (rep->status == 400 && attempt == 0 &&
        !strcmp(p.type, "urn:ietf:params:acme:error:badNonce")) {
      free(rep->body);
      memset(rep, 0, sizeof *rep);
      continue;
    }
    return 0;
  }
}

/* a reply that isn't status (nor 200 when ok200): -1 with the server's
 * problem in err */
static int expect(const CSERVE_HTTP_REPLY *rep, int status, int ok200,
                  const char *what, char *err, size_t err_cap) {
  if (rep->status == status || (ok200 && rep->status == 200)) {
    return 0;
  }
  CSERVE_ACME_PROBLEM p;
  cserve_acme_problem(rep->body, &p);
  snprintf(err, err_cap, "%s: %d %s%s%s", what, rep->status,
           p.type[0] ? p.type : "", p.detail[0] ? ": " : "", p.detail);
  return -1;
}

static int account(CLIENT *c, char *err, size_t err_cap) {
  CSERVE_HTTP_REPLY rep;
  if (post(c, c->dir.new_account, "{\"termsOfServiceAgreed\":true}", &rep, err,
           err_cap) != 0) {
    return -1;
  }
  int rc = expect(&rep, 201, 1, "newAccount", err, err_cap);
  if (rc == 0 &&
      (!cserve_http_reply_header(&rep, "Location", c->kid, sizeof c->kid) ||
       strncmp(c->kid, "https://", 8) != 0)) {
    snprintf(err, err_cap, "newAccount: no account URL in its Location");
    rc = -1;
  }
  free(rep.body);
  return rc;
}

static void pause_ms(long ms) {
  struct timespec ts = {ms / 1000, ms % 1000 * 1000000L};
  nanosleep(&ts, NULL);
}

/* how long the reply says to wait before asking again (Retry-After, in
 * seconds, 1-10), else a second */
static long retry_after(const CSERVE_HTTP_REPLY *rep) {
  char v[16];
  long s = cserve_http_reply_header(rep, "Retry-After", v, sizeof v)
               ? strtol(v, NULL, 10)
               : 1;
  return (s < 1 ? 1 : s > 10 ? 10 : s) * 1000;
}

/* path written whole (mode), synced: 0, or -1 with why in err */
static int write_file(const char *path, const char *text, size_t n, mode_t mode,
                      char *err, size_t err_cap) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
  ssize_t w = fd >= 0 ? write(fd, text, n) : -1;
  int ok = w == (ssize_t)n && fchmod(fd, mode) == 0 && fsync(fd) == 0;
  if (fd >= 0) {
    ok = close(fd) == 0 && ok;
  }
  if (!ok) {
    snprintf(err, err_cap, "%s: %s", path, strerror(errno ? errno : EIO));
    return -1;
  }
  return 0;
}

/* name's authorization (at url) answered and valid: 0, or -1 */
static int authorize(CLIENT *c, const char *url, const char *name, char *err,
                     size_t err_cap) {
  CSERVE_HTTP_REPLY rep;
  CSERVE_ACME_AUTHZ a;
  if (post(c, url, "", &rep, err, err_cap) != 0) {
    return -1;
  }
  int rc = expect(&rep, 200, 0, "an authorization", err, err_cap);
  if (rc == 0) {
    rc = cserve_acme_authz(rep.body, &a, err, err_cap);
  }
  free(rep.body);
  rep.body = NULL;
  if (rc != 0) {
    return -1;
  }
  if (strcmp(a.name, name) != 0) {
    snprintf(err, err_cap, "an authorization for %s, not %s", a.name, name);
    return -1;
  }
  if (!strcmp(a.status, "valid")) {
    return 0;
  }
  char file[PATH_MAX], answer[256];
  int an =
      snprintf(answer, sizeof answer, "%s.%s", a.token, c->account.thumbprint);
  if (snprintf(file, sizeof file, "%s/%s", c->challenges, a.token) >=
          (int)sizeof file ||
      write_file(file, answer, (size_t)an, 0644, err, err_cap) != 0) {
    return -1;
  }
  /* the server is told to look, then asked until it has */
  rc = post(c, a.url, "{}", &rep, err, err_cap);
  if (rc == 0) {
    rc = expect(&rep, 200, 0, "the challenge", err, err_cap);
    free(rep.body);
    rep.body = NULL;
  }
  for (int i = 0; rc == 0 && i < POLLS; i++) {
    if (post(c, url, "", &rep, err, err_cap) != 0) {
      rc = -1;
      break;
    }
    long wait = retry_after(&rep);
    rc = expect(&rep, 200, 0, "an authorization", err, err_cap);
    if (rc == 0) {
      rc = cserve_acme_authz(rep.body, &a, err, err_cap);
    }
    free(rep.body);
    rep.body = NULL;
    if (rc == 0 && !strcmp(a.status, "valid")) {
      break;
    }
    if (rc == 0 && strcmp(a.status, "pending") != 0) {
      snprintf(err, err_cap, "%s's authorization: %s", name, a.status);
      rc = -1;
    } else if (rc == 0 && i == POLLS - 1) {
      snprintf(err, err_cap, "%s's authorization: still pending", name);
      rc = -1;
    } else if (rc == 0) {
      pause_ms(wait);
    }
  }
  unlink(file);
  return rc;
}

/* the order at url asked until its status isn't was (and is want): 0 with
 * o filled, or -1 */
static int await_order(CLIENT *c, const char *url, const char *was,
                       const char *want, CSERVE_ACME_ORDER *o, char *err,
                       size_t err_cap) {
  for (int i = 0; i < POLLS; i++) {
    CSERVE_HTTP_REPLY rep;
    if (post(c, url, "", &rep, err, err_cap) != 0) {
      return -1;
    }
    long wait = retry_after(&rep);
    int rc = expect(&rep, 200, 0, "the order", err, err_cap);
    if (rc == 0) {
      rc = cserve_acme_order(rep.body, o, err, err_cap);
    }
    free(rep.body);
    if (rc != 0) {
      return -1;
    }
    if (!strcmp(o->status, want)) {
      return 0;
    }
    if (strcmp(o->status, was) != 0) {
      snprintf(err, err_cap, "the order: %s, not %s", o->status, want);
      return -1;
    }
    pause_ms(wait);
  }
  snprintf(err, err_cap, "the order: still %s", was);
  return -1;
}

/* the days name's certificate (certs/NAME/cert.pem) has left: < 0 when
 * there's none, or it doesn't parse */
static long days_left(const char *certs, const char *name) {
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/%s/cert.pem", certs, name);
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  long days = -1;
  if (access(path, R_OK) == 0 && mbedtls_x509_crt_parse_file(&crt, path) == 0) {
    struct tm t = {.tm_year = crt.valid_to.year - 1900,
                   .tm_mon = crt.valid_to.mon - 1,
                   .tm_mday = crt.valid_to.day,
                   .tm_hour = crt.valid_to.hour,
                   .tm_min = crt.valid_to.min,
                   .tm_sec = crt.valid_to.sec};
    time_t end = timegm(&t);
    time_t now = time(NULL);
    days = end > now ? (long)((end - now) / 86400) : 0;
  }
  mbedtls_x509_crt_free(&crt);
  return days;
}

/* name's certificate got and put in place: 0, or -1 with why in err */
static int issue(CLIENT *c, const char *name, char *err, size_t err_cap) {
  char payload[400];
  snprintf(payload, sizeof payload,
           "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", name);
  CSERVE_HTTP_REPLY rep;
  if (post(c, c->dir.new_order, payload, &rep, err, err_cap) != 0) {
    return -1;
  }
  char url[CSERVE_ACME_URL];
  CSERVE_ACME_ORDER o;
  int rc = expect(&rep, 201, 0, "newOrder", err, err_cap);
  if (rc == 0) {
    rc = cserve_acme_order(rep.body, &o, err, err_cap);
  }
  if (rc == 0 &&
      (!cserve_http_reply_header(&rep, "Location", url, sizeof url) ||
       strncmp(url, "https://", 8) != 0)) {
    snprintf(err, err_cap, "newOrder: no order URL in its Location");
    rc = -1;
  }
  free(rep.body);
  for (int i = 0; rc == 0 && i < o.nauthz; i++) {
    rc = authorize(c, o.authz[i], name, err, err_cap);
  }
  if (rc == 0 && strcmp(o.status, "ready") != 0) {
    rc = await_order(c, url, "pending", "ready", &o, err, err_cap);
  }
  /* the certificate's key: new each time, never the account's */
  CSERVE_ACME_KEY key;
  char csr[1500];
  if (rc != 0 || cserve_acme_key_new(&key, err, err_cap) != 0) {
    return -1;
  }
  char fin[1600];
  rc = cserve_acme_csr(&key, name, csr, sizeof csr, err, err_cap);
  if (rc == 0) {
    snprintf(fin, sizeof fin, "{\"csr\":\"%s\"}", csr);
    rc = post(c, o.finalize, fin, &rep, err, err_cap);
    if (rc == 0) {
      rc = expect(&rep, 200, 0, "finalize", err, err_cap);
      free(rep.body);
    }
  }
  if (rc == 0) {
    rc = await_order(c, url, "processing", "valid", &o, err, err_cap);
  }
  if (rc == 0 && !o.certificate[0]) {
    snprintf(err, err_cap, "the order is valid but names no certificate");
    rc = -1;
  }
  rep.body = NULL;
  if (rc == 0) {
    rc = post(c, o.certificate, "", &rep, err, err_cap);
  }
  if (rc == 0) {
    rc = expect(&rep, 200, 0, "the certificate", err, err_cap);
  }
  /* what came is a PEM chain whose first certificate is name's own */
  mbedtls_x509_crt chain;
  mbedtls_x509_crt_init(&chain);
  if (rc == 0 &&
      (mbedtls_x509_crt_parse(&chain, (const unsigned char *)rep.body,
                              rep.len + 1) != 0 ||
       !strstr(rep.body, "-----BEGIN CERTIFICATE-----"))) {
    snprintf(err, err_cap, "the certificate: not a PEM chain");
    rc = -1;
  }
  mbedtls_x509_crt_free(&chain);
  char dir[PATH_MAX], kp[PATH_MAX], cp[PATH_MAX], kn[PATH_MAX + 8],
      cn[PATH_MAX + 8];
  snprintf(dir, sizeof dir, "%s/%s", c->certs, name);
  snprintf(kp, sizeof kp, "%s/key.pem", dir);
  snprintf(cp, sizeof cp, "%s/cert.pem", dir);
  snprintf(kn, sizeof kn, "%s.new", kp);
  snprintf(cn, sizeof cn, "%s.new", cp);
  if (rc == 0 && mkdir(dir, 0755) != 0 && errno != EEXIST) {
    snprintf(err, err_cap, "%s: %s", dir, strerror(errno));
    rc = -1;
  }
  /* beside their places, then renamed in: the key first, so a reload
   * between the two sees a pair that doesn't match and keeps the old
   * set (tls.h) */
  if (rc == 0 &&
      (write_file(kn, key.pem, strlen(key.pem), 0600, err, err_cap) != 0 ||
       write_file(cn, rep.body, rep.len, 0644, err, err_cap) != 0 ||
       rename(kn, kp) != 0 || rename(cn, cp) != 0)) {
    if (!err[0]) {
      snprintf(err, err_cap, "%s: %s", dir, strerror(errno));
    }
    rc = -1;
  }
  free(rep.body);
  cserve_acme_key_free(&key);
  return rc;
}

int main(int argc, char **argv) {
  const char *directory = NULL, *ca = NULL, *account_path = NULL;
  const char *names[NAMES_MAX];
  int nnames = 0, force = 0;
  long days = 30;
  CLIENT c = {0};
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    int more = i + 1 < argc;
    if (!strcmp(a, "--directory") && more) {
      directory = argv[++i];
    } else if (!strcmp(a, "--ca") && more) {
      ca = argv[++i];
    } else if (!strcmp(a, "--account") && more) {
      account_path = argv[++i];
    } else if (!strcmp(a, "--certs") && more) {
      c.certs = argv[++i];
    } else if (!strcmp(a, "--challenges") && more) {
      c.challenges = argv[++i];
    } else if (!strcmp(a, "--name") && more && nnames < NAMES_MAX &&
               cserve_tls_name_ok(argv[i + 1], strlen(argv[i + 1]))) {
      names[nnames++] = argv[++i];
    } else if (!strcmp(a, "--days") && more) {
      char *end;
      days = strtol(argv[++i], &end, 10);
      if (*end || days < 1 || days > 365) {
        return usage();
      }
    } else if (!strcmp(a, "--force")) {
      force = 1;
    } else {
      return usage();
    }
  }
  if (!directory || !account_path || !c.certs || !c.challenges || !nnames ||
      strncmp(directory, "https://", 8) != 0) {
    return usage();
  }
  /* the ACME server's CA, for a test's (Pebble's): the process's bundle */
  if (ca && setenv("SSL_CERT_FILE", ca, 1) != 0) {
    return 1;
  }
  /* mbedtls 4 reads an EC certificate through PSA: without it, every
   * certificate on disk would look missing and be issued again */
  if (psa_crypto_init() != PSA_SUCCESS) {
    fprintf(stderr, "cserve-acme: the crypto library didn't start\n");
    return 1;
  }
  char err[600] = "";
  int todo[NAMES_MAX], any = 0;
  for (int i = 0; i < nnames; i++) {
    long left = days_left(c.certs, names[i]);
    todo[i] = force || left < days;
    any |= todo[i];
    if (!todo[i]) {
      printf("%s: %ld days left, kept\n", names[i], left);
    }
  }
  if (!any) {
    return 0;
  }
  /* the account's key: made the first time (0600, never overwritten) */
  if (access(account_path, F_OK) != 0) {
    CSERVE_ACME_KEY k;
    if (cserve_acme_key_new(&k, err, sizeof err) != 0 ||
        write_file(account_path, k.pem, strlen(k.pem), 0600, err, sizeof err) !=
            0) {
      fprintf(stderr, "cserve-acme: the account key: %s\n", err);
      return 1;
    }
    cserve_acme_key_free(&k);
  }
  if (cserve_acme_key_load(&c.account, account_path, err, sizeof err) != 0) {
    fprintf(stderr, "cserve-acme: %s\n", err);
    return 1;
  }
  CSERVE_HTTP_REPLY rep;
  int rc = get(directory, &rep, err, sizeof err);
  if (rc == 0) {
    rc = rep.status == 200
             ? cserve_acme_directory(rep.body, &c.dir, err, sizeof err)
             : (snprintf(err, sizeof err, "the directory: %d", rep.status), -1);
    free(rep.body);
  }
  if (rc != 0 || account(&c, err, sizeof err) != 0) {
    fprintf(stderr, "cserve-acme: %s: %s\n", directory, err);
    cserve_acme_key_free(&c.account);
    return 1;
  }
  int failed = 0;
  for (int i = 0; i < nnames; i++) {
    if (!todo[i]) {
      continue;
    }
    err[0] = '\0';
    if (issue(&c, names[i], err, sizeof err) != 0) {
      fprintf(stderr, "cserve-acme: %s: %s\n", names[i], err);
      failed = 1;
    } else {
      printf("%s: issued, %ld days left\n", names[i],
             days_left(c.certs, names[i]));
    }
  }
  cserve_acme_key_free(&c.account);
  cserve_net_idle_close();
  return failed;
}
