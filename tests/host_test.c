/* the host as built (CSERVE_BIN: build/O2/bin): cserve with the hello app
 * dlopen()ed, cserve-static with it linked in -- the order a request
 * goes through (a file, an app's routes, the front controller or the
 * app's own 404), the app's security headers on what it answers and on
 * nothing else, its pages as the toolkit makes them (the language, the
 * fragment, a 304, the switch's cookie), the climb modes, an app it
 * can't have, a clean stop on SIGTERM */
/* mkdtemp/kill are POSIX, not C11 */
#define _GNU_SOURCE

#include "process.h"

#include "test.h"

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[] = "/tmp/cserve-host-XXXXXX";
static char g_root[PATH_MAX], g_front[PATH_MAX];

static void put(const char *path, const char *text, mode_t mode) {
  FILE *f = fopen(path, "w");
  if (f) {
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
  }
}

typedef struct {
  CSERVE_PROC proc;
  int port;
} HOST;

/* bin with args (NULL-terminated) started: 0 once it says where it
 * listens, -1 if it doesn't (its exit status in *status, when it ended) */
static int start(HOST *h, const char *bin, const char *const *args,
                 int *status) {
  const char *argv[24] = {bin};
  int n = 1;
  for (int i = 0; args[i] && n < 23; i++) {
    argv[n++] = args[i];
  }
  argv[n] = NULL;
  extern char **environ;
  CSERVE_SPAWN s = {.argv = argv, .envp = (const char *const *)environ};
  *status = -1;
  h->port = 0;
  if (cserve_spawn(&s, &h->proc) != 0) {
    return -1;
  }
  char buf[256];
  size_t len = 0;
  struct pollfd p = {.fd = h->proc.out, .events = POLLIN};
  while (len + 1 < sizeof buf && poll(&p, 1, 5000) > 0) {
    ssize_t r = read(h->proc.out, buf + len, sizeof buf - 1 - len);
    if (r <= 0) {
      break;
    }
    len += (size_t)r;
    buf[len] = '\0';
    const char *at = strstr(buf, "listening on 127.0.0.1:");
    if (at && strchr(at, '\n')) {
      h->port = atoi(at + 23);
      return 0;
    }
  }
  *status = cserve_spawn_wait(&h->proc, 5000);
  return -1;
}

/* SIGTERM, then its exit status */
static int stop(HOST *h) {
  kill(h->proc.pid, SIGTERM);
  return cserve_spawn_wait(&h->proc, 5000);
}

/* method target on h, with extra header lines (each ending in CRLF; NULL:
 * none): the whole reply (malloc'd) */
static char *ask_with(const HOST *h, const char *method, const char *target,
                      const char *extra) {
  char req[1024];
  int rn = snprintf(req, sizeof req,
                    "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                    "0\r\n%sConnection: close\r\n\r\n",
                    method, target, extra ? extra : "");
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)h->port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  size_t cap = 65536, len = 0;
  char *got = calloc(1, cap);
  if (got && fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0 &&
      send(fd, req, (size_t)rn, MSG_NOSIGNAL) == rn) {
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

static char *ask(const HOST *h, const char *method, const char *target) {
  return ask_with(h, method, target, NULL);
}

static int replied(const HOST *h, const char *method, const char *target,
                   const char *status, const char *has) {
  char *got = ask(h, method, target);
  int ok = got && strstr(got, status) && (!has || strstr(got, has));
  free(got);
  return ok;
}

/* the hello app's security headers, the way phpanta sends them */
static const char CSP[] =
    "Content-Security-Policy: default-src 'self'; script-src 'self'; "
    "style-src 'self'; img-src 'self' https://images.example; frame-src "
    "'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'\r\n";

/* what target with extra headers gets: whether it has each of the
 * NULL-terminated strings */
static int has_all(const HOST *h, const char *target, const char *extra, ...) {
  char *got = ask_with(h, "GET", target, extra);
  int ok = got != NULL;
  va_list ap;
  va_start(ap, extra);
  for (const char *s; ok && (s = va_arg(ap, const char *));) {
    ok = strstr(got, s) != NULL;
    if (!ok) {
      printf("    no \"%s\" in:\n%s\n", s, got);
    }
  }
  va_end(ap);
  free(got);
  return ok;
}

/* the value of header name in reply (into v) */
static void value_of(const char *reply, const char *name, char *v, size_t cap) {
  v[0] = '\0';
  const char *at = reply ? strstr(reply, name) : NULL;
  if (at) {
    at += strlen(name);
    snprintf(v, cap, "%.*s", (int)strcspn(at, "\r"), at);
  }
}

/* the app's pages, as the toolkit answers them */
static void pages(const HOST *h, const char *bin) {
  char hello[PATH_MAX + 64];
  snprintf(hello, sizeof hello, "<p>hello, world (from %s)</p>", g_root);
  CSERVE_TEST_ASSERT(
      has_all(h, "/hello", NULL, " 200 ", hello, "<!DOCTYPE html>\n",
              "<title>world \xE2\x80\x94 hello</title>",
              "Content-Language: en\r\n", "Cache-Control: no-cache\r\n",
              "Vary: X-Requested-With, Accept-Language, Cookie\r\n",
              "Strict-Transport-Security: max-age=31536000; "
              "includeSubDomains\r\n",
              CSP, "Cross-Origin-Resource-Policy: same-origin\r\n", NULL),
      "%s: the app's page, its init() seen, its security headers on it", bin);
  CSERVE_TEST_ASSERT(has_all(h, "/hello/neuro", "Accept-Language: de-AT\r\n",
                             " 200 ", "<p>hallo, neuro (aus ",
                             "Content-Language: de\r\n", NULL),
                     "%s: a capture, in the language asked for", bin);
  CSERVE_TEST_ASSERT(
      has_all(h, "/hello",
              "Accept-Language: de\r\nCookie: theme=dark; lang=en\r\n",
              "<p>hello, world", NULL),
      "%s: the cookie before Accept-Language", bin);
  char *doc = ask(h, "GET", "/hello");
  char *frag =
      ask_with(h, "GET", "/hello", "X-Requested-With: XMLHttpRequest\r\n");
  char etag[80] = "", fetag[80] = "";
  value_of(doc, "ETag: ", etag, sizeof etag);
  value_of(frag, "ETag: ", fetag, sizeof fetag);
  CSERVE_TEST_ASSERT(
      frag &&
          strstr(frag, "\r\n\r\n<title>world \xE2\x80\x94 "
                       "hello</title>\n<p>hello") &&
          !strstr(frag, "<html") && *etag && *fetag && strcmp(etag, fetag),
      "%s: the SPA's fetch: the fragment, its own validator", bin);
  char inm[128];
  snprintf(inm, sizeof inm, "If-None-Match: %s\r\n", etag);
  char *again = ask_with(h, "GET", "/hello", inm);
  CSERVE_TEST_ASSERT(again && strstr(again, " 304 ") &&
                         strstr(again, "Content-Length: 0\r\n") &&
                         !strstr(again, "\r\nContent-Type:") &&
                         strstr(again, CSP),
                     "%s: the copy the client holds: 304", bin);
  free(doc);
  free(frag);
  free(again);
  CSERVE_TEST_ASSERT(
      has_all(h, "/language/de", "Referer: http://localhost/hello/x\r\n",
              " 303 ", "Location: /hello/x\r\n",
              "Set-Cookie: lang=de; Path=/; Max-Age=31536000; SameSite=Lax; "
              "Secure; HttpOnly\r\n",
              "Cache-Control: no-store, private\r\n", NULL),
      "%s: the language switch: the cookie, and back", bin);
  CSERVE_TEST_ASSERT(has_all(h, "/language/de",
                             "Referer: http://localhost//evil.example\r\n",
                             "Location: /\r\n", NULL),
                     "%s: back to nowhere off the origin: home", bin);
  CSERVE_TEST_ASSERT(replied(h, "GET", "/language/fr", " 404 ", CSP),
                     "%s: a language not offered: 404", bin);
  char *file = ask(h, "GET", "/hello.txt");
  CSERVE_TEST_ASSERT(file && strstr(file, " 200 ") &&
                         !strstr(file, "Content-Security-Policy"),
                     "%s: a file: none of the app's headers", bin);
  free(file);
}

/* the same checks for either host, app given as app */
static void serve_through(const char *bin, const char *app) {
  HOST h;
  int status;
  const char *args[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--cgi",
                        g_front,    "--app",       app,      NULL};
  if (start(&h, bin, args, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "%s --app %s started (%d)", bin, app, status);
    return;
  }
  pages(&h, bin);
  CSERVE_TEST_ASSERT(
      replied(&h, "POST", "/hello", " 405 ", "Allow: GET, HEAD") &&
          replied(&h, "POST", "/hello", " 405 ", CSP),
      "%s: a method the route hasn't: 405, secured", bin);
  CSERVE_TEST_ASSERT(replied(&h, "GET", "/hello.txt", " 200 ", "a file"),
                     "%s: a file comes first", bin);
  CSERVE_TEST_ASSERT(
      replied(&h, "GET", "/other?x=1", " 200 ", "front /other?x=1"),
      "%s: the rest to the front", bin);
  CSERVE_TEST_ASSERT(replied(&h, "GET", "/hello/../x", " 400 ", NULL),
                     "%s: a climbing path refused by default", bin);
  CSERVE_TEST_ASSERT(stop(&h) == 0, "%s: SIGTERM: a clean exit", bin);
}

static void test_hosts(void) {
  char dev[PATH_MAX], stat_bin[PATH_MAX], so[PATH_MAX];
  snprintf(dev, sizeof dev, "%s/cserve", CSERVE_BIN);
  snprintf(stat_bin, sizeof stat_bin, "%s/cserve-static", CSERVE_BIN);
  snprintf(so, sizeof so, "%s/apps/hello.so", CSERVE_BIN);
  serve_through(dev, so);
  serve_through(stat_bin, "hello");

  HOST h;
  int status;
  const char *own[] = {"--listen", "127.0.0.1:0", "--root", g_root,
                       "--app",    "hello",       NULL};
  if (start(&h, stat_bin, own, &status) == 0) {
    CSERVE_TEST_ASSERT(
        has_all(&h, "/nope", NULL, " 404 ", "<p>nothing at /nope</p>", CSP,
                NULL) &&
            has_all(&h, "/nope", "X-Requested-With: XMLHttpRequest\r\n",
                    "\r\n\r\n<title>not found", NULL),
        "no front: the app's own 404, secured, a fragment when asked");
    char *got = ask(&h, "GET", "/nope");
    CSERVE_TEST_ASSERT(got && !strstr(got, "ETag"), "and no validator");
    free(got);
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "--app hello without --cgi started");
  }
  const char *front[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--cgi",
                         g_front,    "--climb",     "front",  NULL};
  if (start(&h, stat_bin, front, &status) == 0) {
    CSERVE_TEST_ASSERT(
        replied(&h, "GET", "/a/../.htaccess", " 200 ", "front /a/../.htaccess"),
        "--climb front: a climbing path the front's");
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "--climb front started");
  }
  const char *missing[] = {"--listen", "127.0.0.1:0", "--root", g_root,
                           "--app",    "nobody",      NULL};
  CSERVE_TEST_ASSERT(start(&h, stat_bin, missing, &status) != 0 && status == 1,
                     "an app that isn't linked in: it won't start");
  const char *path[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--app",
                        so,         NULL};
  CSERVE_TEST_ASSERT(start(&h, stat_bin, path, &status) != 0 && status == 1,
                     "cserve-static loads no .so");
  const char *bad[] = {"--listen", "127.0.0.1:0", "--root",
                       g_root,     "--nope",      NULL};
  CSERVE_TEST_ASSERT(start(&h, dev, bad, &status) != 0 && status == 2,
                     "an unknown flag: usage, 2");
  char cmd[PATH_MAX + 64];
  snprintf(cmd, sizeof cmd, "nm -u '%s' | grep -q dlopen", stat_bin);
  CSERVE_TEST_ASSERT(system(cmd) != 0,
                     "cserve-static: no dlopen in its symbols");
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  if (!mkdtemp(g_dir)) {
    CSERVE_TEST_ASSERT(0, "a scratch dir");
    return cserve_test_summary();
  }
  char pub[PATH_MAX], file[PATH_MAX];
  snprintf(pub, sizeof pub, "%s/public", g_dir);
  mkdir(pub, 0700);
  if (!realpath(pub, g_root)) {
    return 1;
  }
  snprintf(file, sizeof file, "%s/hello.txt", g_root);
  put(file, "a file\n", 0600);
  snprintf(g_front, sizeof g_front, "%s/front.sh", g_dir);
  put(g_front,
      "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
      "echo \"front $REQUEST_URI\"\n",
      0700);
  test_hosts();
  char rm[PATH_MAX + 16];
  snprintf(rm, sizeof rm, "rm -rf '%s'", g_dir);
  int rc = system(rm);
  (void)rc;
  return cserve_test_summary();
}
