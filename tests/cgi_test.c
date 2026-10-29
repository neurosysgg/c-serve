/* cgi.c: a CGI's reply head, its environment, and the bridge whole -- a
 * listener on loopback (plain HTTP), a shell script standing in for
 * php-cgi */
/* mkdtemp/setenv are POSIX, not C11 */
#define _GNU_SOURCE

#include "cgi.h"
#include "conn.h"
#include "httpd.h"
#include "listen.h"

#include "test.h"

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[] = "/tmp/cserve-cgi-XXXXXX";
static char g_root[PATH_MAX];

static void put(const char *rel, const char *text) {
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/%s", g_dir, rel);
  FILE *f = fopen(path, "w");
  if (f) {
    fputs(text, f);
    fclose(f);
  }
}

static long head(const char *text, CSERVE_HTTPD_REPLY *rep, char *type,
                 char *err) {
  memset(rep, 0, sizeof *rep);
  return cserve_cgi_head(text, strlen(text), rep, type, 64, err, 160);
}

static void test_head(void) {
  CSERVE_HTTPD_REPLY rep;
  char type[64], err[160];
  const char *a = "Content-type: text/html; charset=UTF-8\r\n"
                  "X-Powered-By: PHP\r\nSet-Cookie: a=1\r\n\r\n<html>";
  long n = head(a, &rep, type, err);
  CSERVE_TEST_ASSERT(
      n > 0 && !strcmp(a + n, "<html>") && rep.status == 200 &&
          !strcmp(type, "text/html; charset=UTF-8") &&
          !strcmp(rep.headers, "X-Powered-By: PHP\r\nSet-Cookie: a=1\r\n"),
      "a head: the type taken out, the rest kept, the body after");
  n = head("Status: 404 Not Found\nContent-Type: text/plain\n\nnone", &rep,
           type, err);
  CSERVE_TEST_ASSERT(n > 0 && rep.status == 404 && !strcmp(type, "text/plain"),
                     "bare LFs; Status sets the status");
  n = head("Location: /there\r\n\r\n", &rep, type, err);
  CSERVE_TEST_ASSERT(n > 0 && rep.status == 302 && !type[0] &&
                         !strcmp(rep.headers, "Location: /there\r\n"),
                     "Location alone: a 302");
  n = head("Status: 301\r\nLocation: /x\r\nConnection: close\r\n"
           "Content-Length: 5\r\nTransfer-Encoding: chunked\r\nServer: php"
           "\r\n\r\n",
           &rep, type, err);
  CSERVE_TEST_ASSERT(n > 0 && rep.status == 301 &&
                         !strcmp(rep.headers, "Location: /x\r\n"),
                     "Status over Location's 302; the framing's headers "
                     "dropped");
  CSERVE_TEST_ASSERT(head("Content-Type: text/plain\r\n", &rep, type, err) ==
                             0 &&
                         head("", &rep, type, err) == 0,
                     "not whole yet: 0");
  const char *bad[] = {"no colon here\n\n", ": empty name\n\n",
                       "Bad Name: x\n\n",   "Status: abc\n\n",
                       "Status: 99\n\n",    "Status: 700 Odd\n\n",
                       "Status: 2000\n\n",  "X: a\x01b\n\n"};
  for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
    CSERVE_TEST_ASSERT(head(bad[i], &rep, type, err) == -1 &&
                           strstr(err, "head"),
                       "refused: %s", err);
  }
  char big[20000];
  memset(big, 'a', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  big[0] = 'X';
  big[1] = ':';
  CSERVE_TEST_ASSERT(head(big, &rep, type, err) == -1 && strstr(err, "long"),
                     "a head that never ends: refused at 16 KB");
  char many[9000];
  size_t k = 0;
  for (int i = 0; i < 700; i++) {
    k += (size_t)snprintf(many + k, sizeof many - k, "X-%d: v\n", i);
  }
  snprintf(many + k, sizeof many - k, "\n");
  CSERVE_TEST_ASSERT(head(many, &rep, type, err) == -1 &&
                         strstr(err, "headers are too long"),
                     "more headers than the reply holds: refused");
}

static int has(char **env, const char *kv) {
  for (int i = 0; env && env[i]; i++) {
    if (!strcmp(env[i], kv)) {
      return 1;
    }
  }
  return 0;
}

static int has_key(char **env, const char *k) {
  size_t n = strlen(k);
  for (int i = 0; env && env[i]; i++) {
    if (!strncmp(env[i], k, n) && env[i][n] == '=') {
      return 1;
    }
  }
  return 0;
}

static void test_env(void) {
  const char *host_env[] = {"PHPANTA_ENVIRONMENT=development", NULL};
  const char *extra[] = {"REMOTE_USER=phone", NULL};
  CSERVE_CGI c = {.root = "/srv/r",
                  .script = "index.php",
                  .port = 8443,
                  .https = 1,
                  .env = host_env};
  char buf[1024];
  snprintf(buf, sizeof buf,
           "POST /media/play?x=1 HTTP/1.1\nHost: [fd00::5]:8443\n"
           "Content-Type: application/json\nContent-Length: 2\n"
           "Cookie: a=1\nCookie: b=2\nAccept: a\nAccept: b\n"
           "X-Under_Score: no\nProxy: http://evil\nUser-Agent: Phone\n");
  CSERVE_HTTPD_REQ r;
  char err[128];
  int parsed = cserve_httpd_parse(buf, &r, err, sizeof err) == 0;
  r.peer = "[fd00::7]:51234";
  setenv("CSERVE_CGI_LEAK", "1", 1);
  setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
  char **env = parsed ? cserve_cgi_env(&c, &r, extra) : NULL;
  CSERVE_TEST_ASSERT(
      env && has(env, "REQUEST_METHOD=POST") &&
          has(env, "REQUEST_URI=/media/play?x=1") &&
          has(env, "QUERY_STRING=x=1") && has(env, "SERVER_NAME=[fd00::5]") &&
          has(env, "SERVER_PORT=8443") &&
          has(env, "SERVER_PROTOCOL=HTTP/1.1") &&
          has(env, "SERVER_SOFTWARE=c-serve") &&
          has(env, "SCRIPT_NAME=/index.php") &&
          has(env, "SCRIPT_FILENAME=/srv/r/index.php") &&
          has(env, "DOCUMENT_ROOT=/srv/r") && has(env, "REDIRECT_STATUS=200") &&
          has(env, "REMOTE_ADDR=fd00::7") && has(env, "REMOTE_PORT=51234") &&
          has(env, "CONTENT_LENGTH=2") &&
          has(env, "CONTENT_TYPE=application/json"),
      "the CGI's request variables");
  CSERVE_TEST_ASSERT(env && has(env, "HTTPS=on") &&
                         has(env, "REQUEST_SCHEME=https") &&
                         has(env, "PHPANTA_ENVIRONMENT=development") &&
                         has(env, "REMOTE_USER=phone"),
                     "TLS said; the host's variables and the request's own");
  CSERVE_TEST_ASSERT(
      env && has(env, "HTTP_COOKIE=a=1; b=2") && has(env, "HTTP_ACCEPT=a, b") &&
          has(env, "HTTP_USER_AGENT=Phone") &&
          has(env, "HTTP_HOST=[fd00::5]:8443") &&
          !has_key(env, "HTTP_X_UNDER_SCORE") && !has_key(env, "HTTP_PROXY") &&
          !has_key(env, "HTTP_CONTENT_TYPE"),
      "the headers: repeats joined, '_' names and Proxy dropped");
  CSERVE_TEST_ASSERT(env && has(env, "XDG_RUNTIME_DIR=/run/user/1000") &&
                         !has_key(env, "CSERVE_CGI_LEAK"),
                     "ours: only the kept few");
  cserve_cgi_env_free(env);
  c.https = 0;
  c.software = "neurosys";
  c.env = NULL;
  env = parsed ? cserve_cgi_env(&c, &r, NULL) : NULL;
  CSERVE_TEST_ASSERT(
      env && !has_key(env, "HTTPS") && has(env, "REQUEST_SCHEME=http") &&
          has(env, "SERVER_SOFTWARE=neurosys") && !has_key(env, "REMOTE_USER"),
      "plain HTTP: no HTTPS");
  cserve_cgi_env_free(env);
  unsetenv("CSERVE_CGI_LEAK");
}

/* --- the bridge whole --- */

typedef struct {
  CSERVE_CGI cgi;
  const char *argv[3];
  CSERVE_LISTEN *ls;
  int stop[2];
  pthread_t th;
} SRV;

static SRV g_srv;

static void on_request(const CSERVE_HTTPD_REQ *r, const char *body,
                       CSERVE_HTTPD_REPLY *rep, void *ud) {
  (void)ud;
  CSERVE_CGI c = g_srv.cgi;
  c.port = g_srv.ls->port;
  cserve_cgi(&c, r, body, NULL, rep);
}

static void on_conn(CSERVE_CONN *c, const char *peer, void *ud) {
  (void)ud;
  CSERVE_HTTPD h = {.handler = on_request};
  cserve_httpd_serve(&h, c, peer);
}

static void *serve_run(void *arg) {
  SRV *s = arg;
  char err[128];
  cserve_listen_serve(&s->ls, 1, s->stop[0], err, sizeof err);
  return NULL;
}

/* req sent, everything back until the server closes into got (malloc'd,
 * NUL-terminated) */
static char *ask(const char *req, size_t req_len) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)g_srv.ls->port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  size_t cap = 1 << 20, len = 0;
  char *got = calloc(1, cap);
  if (got && fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0) {
    size_t sent = 0;
    while (sent < req_len) {
      ssize_t w = send(fd, req + sent, req_len - sent, MSG_NOSIGNAL);
      if (w <= 0) {
        break;
      }
      sent += (size_t)w;
    }
    struct pollfd p = {.fd = fd, .events = POLLIN};
    ssize_t r;
    while (poll(&p, 1, 5000) > 0 &&
           (r = recv(fd, got + len, cap - 1 - len, 0)) > 0) {
      len += (size_t)r;
    }
  }
  if (fd >= 0) {
    close(fd);
  }
  return got;
}

static char *get(const char *target) {
  char req[1024];
  int n = snprintf(req, sizeof req,
                   "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: "
                   "close\r\n\r\n",
                   target);
  return ask(req, (size_t)n);
}

static const char *body_of(const char *got) {
  const char *b = strstr(got, "\r\n\r\n");
  return b ? b + 4 : "";
}

static const char *CGI_SH =
    "#!/bin/sh\n"
    "case \"$REQUEST_URI\" in\n"
    "/env*) printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
    "  echo \"$HTTPS|$SCRIPT_FILENAME|$DOCUMENT_ROOT|$(pwd)|$APP_MODE\" ;;\n"
    "/post*) printf 'Content-Type: text/plain\\r\\nX-Len: %s\\r\\n\\r\\n' "
    "\"$CONTENT_LENGTH\"; cat ;;\n"
    "/slow*) printf 'Content-Type: text/plain\\r\\n\\r\\n'; echo one; "
    "sleep 0.3; echo two ;;\n"
    "/missing*) printf 'Status: 404 Not Found\\r\\nContent-Type: "
    "text/plain\\r\\n\\r\\nno such page' ;;\n"
    "/broken*) echo 'not a header' ;;\n"
    "/quiet*) sleep 5 ;;\n"
    "esac\n";

static int start(void) {
  char err[256], script[PATH_MAX];
  static const char *host_env[] = {"APP_MODE=test", NULL};
  put("cgi.sh", CGI_SH);
  snprintf(script, sizeof script, "%s/cgi.sh", g_dir);
  static char script_store[PATH_MAX];
  snprintf(script_store, sizeof script_store, "%s", script);
  g_srv.argv[0] = "/bin/sh";
  g_srv.argv[1] = script_store;
  g_srv.cgi = (CSERVE_CGI){.argv = g_srv.argv,
                           .root = g_root,
                           .script = "index.php",
                           .env = host_env,
                           .head_ms = 1000};
  g_srv.ls =
      cserve_listen_new("127.0.0.1", 0, on_conn, &g_srv, err, sizeof err);
  if (!g_srv.ls || pipe(g_srv.stop) != 0) {
    CSERVE_TEST_ASSERT(0, "the server (%s)", err);
    return -1;
  }
  pthread_create(&g_srv.th, NULL, serve_run, &g_srv);
  return 0;
}

static void stop(void) {
  ssize_t w = write(g_srv.stop[1], "x", 1);
  (void)w;
  pthread_join(g_srv.th, NULL);
  for (int i = 0; i < 100 && cserve_listen_active() > 0; i++) {
    nanosleep(&(struct timespec){0, 20000000}, NULL);
  }
  CSERVE_TEST_ASSERT(cserve_listen_active() == 0, "every connection done");
  cserve_listen_free(g_srv.ls);
  close(g_srv.stop[0]);
  close(g_srv.stop[1]);
}

static void test_bridge(void) {
  if (start() != 0) {
    return;
  }
  char *got = get("/env");
  char want[PATH_MAX * 3 + 64];
  snprintf(want, sizeof want, "|%s/index.php|%s|%s|test\n", g_root, g_root,
           g_root);
  CSERVE_TEST_ASSERT(
      strstr(got, "Transfer-Encoding: chunked") && strstr(got, want),
      "the CGI: where it runs, the host's variables (%s)", body_of(got));
  free(got);

  /* bigger than a pipe holds both ways: fed while read */
  size_t big = 300000;
  char *req = malloc(big + 256);
  int hn = snprintf(req, 256,
                    "POST /post HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                    "%zu\r\nConnection: close\r\n\r\n",
                    big);
  for (size_t i = 0; i < big; i++) {
    req[hn + (int)i] = (char)('a' + i % 26);
  }
  got = ask(req, (size_t)hn + big);
  /* the chunks joined back */
  size_t joined = 0, ok = 1;
  const char *p = body_of(got);
  for (;;) {
    unsigned long n = strtoul(p, (char **)&p, 16);
    if (strncmp(p, "\r\n", 2)) {
      ok = 0;
      break;
    }
    p += 2;
    if (n == 0) {
      break;
    }
    for (unsigned long i = 0; i < n && ok; i++) {
      ok = p[i] == (char)('a' + (joined + i) % 26);
    }
    joined += n;
    p += n + 2;
  }
  CSERVE_TEST_ASSERT(strstr(got, "X-Len: 300000\r\n") && ok && joined == big,
                     "a 300 KB POST through the CGI and back (%zu)", joined);
  free(req);
  free(got);

  long t0 = cserve_net_now();
  got = get("/slow");
  CSERVE_TEST_ASSERT(strstr(got, "\r\n4\r\none\n\r\n4\r\ntwo\n\r\n0\r\n\r\n") &&
                         cserve_net_now() - t0 >= 250,
                     "a CGI's body as it comes: a chunk per piece");
  free(got);
  got = get("/missing");
  CSERVE_TEST_ASSERT(strstr(got, "HTTP/1.1 404 Not Found") &&
                         strstr(got, "no such page"),
                     "the CGI's Status");
  free(got);
  got = get("/broken");
  CSERVE_TEST_ASSERT(strstr(got, "HTTP/1.1 502 ") && strstr(got, "head"),
                     "a broken head: 502");
  free(got);
  got = get("/nothing");
  CSERVE_TEST_ASSERT(strstr(got, "HTTP/1.1 502 ") &&
                         strstr(got, "without a reply"),
                     "a CGI that says nothing: 502");
  free(got);
  t0 = cserve_net_now();
  got = get("/quiet");
  CSERVE_TEST_ASSERT(strstr(got, "HTTP/1.1 504 ") &&
                         cserve_net_now() - t0 < 3000,
                     "one that doesn't answer: 504 at head_ms, killed");
  free(got);
  const char *saved = g_srv.argv[0];
  g_srv.argv[0] = "/nonexistent/php-cgi";
  got = get("/env");
  CSERVE_TEST_ASSERT(strstr(got, "HTTP/1.1 502 ") && strstr(got, "php-cgi"),
                     "no CGI program: 502, named");
  free(got);
  g_srv.argv[0] = saved;
  stop();
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  if (!mkdtemp(g_dir)) {
    CSERVE_TEST_ASSERT(0, "a scratch dir");
    return cserve_test_summary();
  }
  char pub[PATH_MAX];
  snprintf(pub, sizeof pub, "%s/public", g_dir);
  mkdir(pub, 0700);
  if (!realpath(pub, g_root)) {
    return 1;
  }
  test_head();
  test_env();
  test_bridge();
  char rm[PATH_MAX + 16];
  snprintf(rm, sizeof rm, "rm -rf '%s'", g_dir);
  int rc = system(rm);
  (void)rc;
  return cserve_test_summary();
}
