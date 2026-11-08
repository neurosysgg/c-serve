/* tls.h's server of names: what a name is, which directories load (and
 * why each refused one is), the handshake by SNI on a real loop -- a
 * known name, another, an unknown one, none -- and a reload: a new
 * connection gets the new certificate while one begun before keeps
 * talking, and a set that doesn't load leaves the old in place. Then
 * loop.h's watch, and acme.h's token. The fixtures are
 * tests/data/names/make.sh's. */
#define _GNU_SOURCE

#include "acme.h"
#include "listen.h"
#include "loop.h"
#include "tls.h"

#include "test.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define D "tests/data/names"

static void handler(const CSERVE_HTTPD_REQ *r, const char *body,
                    CSERVE_HTTPD_REPLY *rep, void *ud) {
  (void)body;
  (void)ud;
  const char *t = r->tls ? "over tls\n" : "plain\n";
  cserve_httpd_text(rep, 200, "text/plain", t, strlen(t));
}

typedef struct {
  CSERVE_LOOP *loop;
  pthread_t thread;
  int stop[2];
  int port;
} RUN;

static void *run_loop(void *arg) {
  RUN *r = arg;
  char err[200];
  (void)cserve_loop_run(r->loop, r->stop[0], 2000, err, sizeof err);
  return NULL;
}

/* a loop on port 0 under tls, watching wfd (>= 0) with watched() */
static void watched(void *ud);
static int start_watching(RUN *r, CSERVE_TLS_SERVER *tls, int wfd, void *ud) {
  char err[200];
  CSERVE_LOOP_CONFIG cfg = {.handler = handler};
  memset(r, 0, sizeof *r);
  r->loop = cserve_loop_new(&cfg, err, sizeof err);
  int fd = r->loop
               ? cserve_listen_socket("127.0.0.1", 0, &r->port, err, sizeof err)
               : -1;
  if (fd < 0 || cserve_loop_listen(r->loop, fd, tls, err, sizeof err) != 0 ||
      pipe(r->stop) != 0 ||
      (wfd >= 0 &&
       cserve_loop_watch(r->loop, wfd, watched, ud, err, sizeof err) != 0)) {
    printf("    the loop: %s\n", err);
    return -1;
  }
  return pthread_create(&r->thread, NULL, run_loop, r);
}

static int start(RUN *r, CSERVE_TLS_SERVER *tls) {
  return start_watching(r, tls, -1, NULL);
}

static void stop(RUN *r) {
  (void)!write(r->stop[1], "x", 1);
  pthread_join(r->thread, NULL);
  cserve_loop_free(r->loop);
  close(r->stop[0]);
  close(r->stop[1]);
}

static int dial(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
    close(fd);
    return -1;
  }
  /* tls.h's client wants it so */
  if (fd >= 0) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  }
  return fd;
}

/* a TLS connection to port asking for name (NULL: no SNI), or NULL */
static CSERVE_TLS *hello(int port, const char *name, CSERVE_TLS_CLIENT *cl,
                         int *fd) {
  char err[200];
  *fd = dial(port);
  CSERVE_TLS *t =
      *fd >= 0 ? cserve_tls_connect(*fd, name, cl, cserve_net_now() + 5000, err,
                                    sizeof err)
               : NULL;
  if (!t && *fd >= 0) {
    close(*fd);
    *fd = -1;
  }
  return t;
}

/* one request on t, keeping the connection: 1 when it was answered */
static int ask(CSERVE_TLS *t) {
  char err[200], buf[512] = "";
  static const char REQ[] = "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
  long deadline = cserve_net_now() + 5000;
  if (cserve_tls_write(t, REQ, sizeof REQ - 1, deadline, err, sizeof err)) {
    return 0;
  }
  size_t len = 0;
  while (len + 1 < sizeof buf && !strstr(buf, "over tls\n")) {
    ssize_t n = cserve_tls_read(t, buf + len, sizeof buf - 1 - len, deadline,
                                err, sizeof err);
    if (n <= 0) {
      break;
    }
    len += (size_t)n;
    buf[len] = '\0';
  }
  buf[len] = '\0';
  return strstr(buf, "200 OK") && strstr(buf, "over tls\n");
}

/* the certificate t's server showed: its CN, its fingerprint */
static void shown(CSERVE_TLS *t, char cn[64], char fpr[65]) {
  if (!t || cserve_tls_peer(t, cn, 64, fpr) != 0) {
    cn[0] = fpr[0] = '\0';
  }
}

static void test_name_ok(void) {
  static const struct {
    const char *name;
    int ok;
  } T[] = {
      {"a.test", 1},   {"neurosys.gg", 1}, {"x", 1},        {"a-b.c0.d", 1},
      {"", 0},         {"A.test", 0},      {"a.test.", 0},  {".a.test", 0},
      {"a..test", 0},  {"-a.test", 0},     {"a-.test", 0},  {"a.-test", 0},
      {"a_b.test", 0}, {"a.test:443", 0},  {"*.a.test", 0}, {"a/b", 0},
      {"..", 0},       {"a test", 0}};
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    CSERVE_TEST_ASSERT(
        cserve_tls_name_ok(T[i].name, strlen(T[i].name)) == T[i].ok,
        "a name: \"%s\" %s", T[i].name, T[i].ok ? "taken" : "refused");
  }
  char label[80], name[300];
  memset(label, 'a', 63);
  label[63] = '\0';
  CSERVE_TEST_ASSERT(
      cserve_tls_name_ok(label, 63) &&
          !cserve_tls_name_ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              64),
      "a name: a label of 63 bytes taken, of 64 refused");
  snprintf(name, sizeof name, "%s.%s.%s.%.61s", label, label, label, label);
  CSERVE_TEST_ASSERT(cserve_tls_name_ok(name, 253) &&
                         !cserve_tls_name_ok("a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                             254),
                     "a name: 253 bytes taken, 254 refused");
}

static void test_loading(void) {
  char err[300];
  static const struct {
    const char *dir, *why;
  } BAD[] = {
      {D "/wrong-key", "not the key of"},
      {D "/wrong-name", "not a certificate for a.test"},
      {D "/rsa", "not a P-256 key"},
      {D "/not-a-name", "not a lowercase DNS name"},
      {D "/nowhere", "No such file"},
      {D "/good/a.test/cert.pem", "Not a directory"},
  };
  for (size_t i = 0; i < sizeof BAD / sizeof *BAD; i++) {
    err[0] = '\0';
    CSERVE_TLS_SERVER *s = cserve_tls_names_new(BAD[i].dir, err, sizeof err);
    CSERVE_TEST_ASSERT(!s && strstr(err, BAD[i].why), "names: %s refused (%s)",
                       BAD[i].dir, err);
    cserve_tls_server_free(s);
  }
  char empty[] = "/tmp/cserve-names-XXXXXX";
  if (mkdtemp(empty)) {
    CSERVE_TLS_SERVER *s = cserve_tls_names_new(empty, err, sizeof err);
    CSERVE_TEST_ASSERT(s && cserve_tls_names_count(s) == 0 &&
                           !cserve_tls_names_has(s, "a.test", 6),
                       "names: an empty directory is a set of none");
    cserve_tls_server_free(s);
    rmdir(empty);
  }
  CSERVE_TLS_SERVER *s = cserve_tls_names_new(D "/good", err, sizeof err);
  CSERVE_TEST_ASSERT(s, "names: the good set loads (%s)", s ? "" : err);
  if (s) {
    CSERVE_TEST_ASSERT(cserve_tls_names_has(s, "a.test", 6) &&
                           cserve_tls_names_has(s, "B.Test", 6) &&
                           cserve_tls_names_has(s, "a.test:80", 6) &&
                           !cserve_tls_names_has(s, "a.tes", 5) &&
                           !cserve_tls_names_has(s, "c.test", 6) &&
                           !cserve_tls_names_has(s, "a.test.", 7) &&
                           cserve_tls_names_count(s) == 2,
                       "names: has() knows a.test and b.test, in any case, "
                       "and nothing else");
  }
  CSERVE_TLS_SERVER *one =
      cserve_tls_server_new("tests/data/pki/server.crt",
                            "tests/data/pki/server.key", NULL, err, sizeof err);
  CSERVE_TEST_ASSERT(one && cserve_tls_names_reload(one, err, sizeof err) &&
                         !cserve_tls_names_has(one, "localhost", 9),
                     "names: a one-certificate server neither reloads nor has "
                     "names");
  cserve_tls_server_free(one);
  cserve_tls_server_free(s);
}

/* cp -r src/name dst/name, by the shell (a test's convenience) */
static int put(const char *src, const char *name, const char *dst) {
  char cmd[600];
  snprintf(cmd, sizeof cmd, "rm -rf '%s/%s' && cp -r '%s/%s' '%s/'", dst, name,
           src, name, dst);
  return system(cmd);
}

static void test_handshakes(void) {
  char err[300], dir[] = "/tmp/cserve-names-XXXXXX";
  if (!mkdtemp(dir) || put(D "/good", "a.test", dir) != 0 ||
      put(D "/good", "b.test", dir) != 0) {
    CSERVE_TEST_ASSERT(0, "a scratch copy of the good set");
    return;
  }
  CSERVE_TLS_SERVER *s = cserve_tls_names_new(dir, err, sizeof err);
  CSERVE_TLS_CLIENT *cl =
      cserve_tls_client_new(D "/ca.crt", NULL, NULL, err, sizeof err);
  RUN r;
  if (!s || !cl || start(&r, s) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop with the names (%s)", err);
    cserve_tls_server_free(s);
    cserve_tls_client_free(cl);
    return;
  }
  int fa, fb, fx, fn;
  char cn[64], fpr[65], cn2[64], fpr2[65];
  CSERVE_TLS *a = hello(r.port, "a.test", cl, &fa);
  shown(a, cn, fpr);
  CSERVE_TEST_ASSERT(a && !strcmp(cn, "a.test") && ask(a),
                     "SNI a.test: a.test's certificate, and an answer");
  CSERVE_TLS *b = hello(r.port, "b.test", cl, &fb);
  shown(b, cn2, fpr2);
  CSERVE_TEST_ASSERT(b && !strcmp(cn2, "b.test") && ask(b),
                     "SNI b.test: b.test's certificate");
  cserve_tls_close(b);
  close(fb);
  CSERVE_TLS *x = hello(r.port, "c.test", cl, &fx);
  CSERVE_TEST_ASSERT(!x, "SNI c.test: refused in the handshake");
  CSERVE_TLS *none = hello(r.port, NULL, cl, &fn);
  CSERVE_TEST_ASSERT(!none, "no SNI: refused in the handshake");

  /* a renewal: a.test's pair replaced, then the set read again */
  int rc = put(D "/renewed", "a.test", dir);
  CSERVE_TEST_ASSERT(rc == 0 &&
                         cserve_tls_names_reload(s, err, sizeof err) == 0,
                     "reload: the renewed set loads (%s)", err);
  CSERVE_TEST_ASSERT(ask(a), "reload: a connection begun before it still "
                             "answers");
  int fa2;
  CSERVE_TLS *a2 = hello(r.port, "a.test", cl, &fa2);
  shown(a2, cn2, fpr2);
  CSERVE_TEST_ASSERT(a2 && !strcmp(cn2, "a.test") && strcmp(fpr, fpr2) != 0 &&
                         ask(a2),
                     "reload: a new connection gets the new certificate");
  cserve_tls_close(a2);
  close(fa2);

  /* a broken pair: refused, the set before stays */
  char cmd[400];
  snprintf(cmd, sizeof cmd, "cp '%s/good/b.test/key.pem' '%s/a.test/key.pem'",
           D, dir);
  rc = system(cmd);
  err[0] = '\0';
  CSERVE_TEST_ASSERT(rc == 0 && cserve_tls_names_reload(s, err, sizeof err) &&
                         strstr(err, "not the key of"),
                     "reload: a mismatched pair refused (%s)", err);
  a2 = hello(r.port, "a.test", cl, &fa2);
  char cn3[64], fpr3[65];
  shown(a2, cn3, fpr3);
  CSERVE_TEST_ASSERT(a2 && !strcmp(fpr3, fpr2) && ask(a2),
                     "reload: after a refused one, the set before still "
                     "serves new connections");
  CSERVE_TEST_ASSERT(ask(a), "reload: and the first connection, begun two "
                             "sets ago, still answers");
  cserve_tls_close(a2);
  close(fa2);
  cserve_tls_close(a);
  close(fa);
  stop(&r);
  cserve_tls_server_free(s);
  cserve_tls_client_free(cl);
  snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
  (void)!system(cmd);
}

static int g_watched;
static int g_watch[2];

static void watched(void *ud) {
  char c;
  while (read(g_watch[0], &c, 1) == 1) {
    __atomic_add_fetch((int *)ud, 1, __ATOMIC_SEQ_CST);
  }
}

static void test_watch(void) {
  RUN r;
  if (pipe2(g_watch, O_NONBLOCK) != 0 ||
      start_watching(&r, NULL, g_watch[0], &g_watched) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop to watch on");
    return;
  }
  int rc = 0;
  (void)!write(g_watch[1], "xy", 2);
  for (int i = 0; i < 100 && __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST) < 2;
       i++) {
    usleep(10000);
  }
  stop(&r);
  CSERVE_TEST_ASSERT(rc == 0 &&
                         __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST) == 2,
                     "the loop's watch: fn ran on the loop when its fd "
                     "turned readable");
  close(g_watch[0]);
  close(g_watch[1]);
}

static void test_token(void) {
  static const struct {
    const char *t;
    int ok;
  } T[] = {{"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0", 1},
           {"a-b_C9", 1},
           {"", 0},
           {"..", 0},
           {"a/b", 0},
           {"a.b", 0},
           {"a b", 0},
           {"a=", 0},
           {"a+b", 0},
           {"%2e%2e", 0}};
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    CSERVE_TEST_ASSERT(cserve_acme_token_ok(T[i].t, strlen(T[i].t)) == T[i].ok,
                       "a token: \"%s\" %s", T[i].t,
                       T[i].ok ? "taken" : "refused");
  }
  char long_one[130];
  memset(long_one, 'a', sizeof long_one);
  CSERVE_TEST_ASSERT(cserve_acme_token_ok(long_one, 128) &&
                         !cserve_acme_token_ok(long_one, 129),
                     "a token: 128 bytes taken, 129 refused");
}

int main(void) {
  test_name_ok();
  test_loading();
  test_handshakes();
  test_watch();
  test_token();
  return cserve_test_summary();
}
