/* the host as built (CSERVE_BIN: build/O2/bin): cserve with the hello app
 * dlopen()ed, cserve-static with it linked in -- the order a request
 * goes through (a file, an app's routes, the app's own 404), the app's
 * security headers on what it answers and on nothing else, its pages as
 * the toolkit makes them (the language, the fragment, a 304, the
 * switch's cookie), a climbing path, an app it can't have, a clean stop
 * on SIGTERM */
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
#include <time.h>
#include <unistd.h>

static char g_dir[] = "/tmp/cserve-host-XXXXXX";
static char g_root[PATH_MAX], g_data[PATH_MAX], g_front[PATH_MAX];

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

/* the app's refuse(): a method no route takes is a 405 in the visitor's
 * words, an OPTIONS a 204 naming what they do take */
static void refusals(const HOST *h, const char *bin) {
  char *got = ask_with(h, "PUT", "/hello", "Accept-Language: de\r\n");
  CSERVE_TEST_ASSERT(
      got && strstr(got, " 405 ") &&
          strstr(got, "Cache-Control: no-store, private\r\n"
                      "Allow: GET, HEAD\r\n") &&
          strstr(got, "\r\n\r\nhallo ist schreibgesch") && strstr(got, CSP),
      "%s: the app's 405: no-store, Allow, its words, secured", bin);
  free(got);
  got = ask(h, "OPTIONS", "/hello/x");
  CSERVE_TEST_ASSERT(got && strstr(got, " 204 ") &&
                         strstr(got, "Allow: GET, HEAD, OPTIONS\r\n") &&
                         !strstr(got, "\r\nContent-Type:"),
                     "%s: OPTIONS: 204, the methods and OPTIONS", bin);
  free(got);
}

/* a file from the app's data, behind Basic, whole or in ranges */
#define OPEN "Authorization: Basic aGVsbG86b3BlbiBzZXNhbWU=\r\n"
static void files(const HOST *h, const char *bin) {
  CSERVE_TEST_ASSERT(
      has_all(h, "/hello-file/f.txt", NULL, " 401 ",
              "WWW-Authenticate: Basic realm=\"hello: f.txt\"\r\n", NULL) &&
          has_all(h, "/hello-file/x%20y",
                  "Authorization: Basic "
                  "aGVsbG86d3Jvbmc=\r\n",
                  " 401 ", "realm=\"hello: x%20y\"", NULL),
      "%s: no password, or a wrong one: 401, the realm encoded", bin);
  CSERVE_TEST_ASSERT(
      has_all(h, "/hello-file/f.txt", OPEN, " 200 ", "Content-Length: 10\r\n",
              "Accept-Ranges: bytes\r\nCache-Control: no-store, private\r\n"
              "X-Robots-Tag: noindex\r\n",
              "\r\n\r\n0123456789", NULL),
      "%s: the right one: the file, its headers in phpanta's order", bin);
  CSERVE_TEST_ASSERT(
      has_all(h, "/hello-file/f.txt", OPEN "Range: bytes=2-4\r\n", " 206 ",
              "Content-Length: 3\r\n", "Content-Range: bytes 2-4/10\r\n",
              "\r\n\r\n234", NULL) &&
          has_all(h, "/hello-file/f.txt", OPEN "Range: bytes=-3\r\n",
                  "\r\n\r\n789", NULL) &&
          has_all(h, "/hello-file/f.txt", OPEN "Range: bytes=10-\r\n", " 416 ",
                  "Content-Length: 0\r\n", "Content-Range: bytes */10\r\n",
                  NULL) &&
          has_all(h, "/hello-file/f.txt", OPEN "Range: bytes=1-2,4-5\r\n",
                  " 200 ", "Content-Length: 10\r\n", NULL),
      "%s: a range: 206, the last bytes, past the end 416, a list 200", bin);
  char *head =
      ask_with(h, "HEAD", "/hello-file/f.txt", OPEN "Range: bytes=0-1\r\n");
  CSERVE_TEST_ASSERT(head && strstr(head, " 200 ") &&
                         strstr(head, "Content-Length: 10\r\n") &&
                         strstr(head, "\r\n\r\n")[4] == '\0',
                     "%s: HEAD: told the GET's length, no Range, no body", bin);
  free(head);
  CSERVE_TEST_ASSERT(replied(h, "GET", "/hello-file/none", " 401 ", NULL),
                     "%s: a file there isn't: the same 401", bin);
  char *gone = ask_with(h, "GET", "/hello-file/none", OPEN);
  CSERVE_TEST_ASSERT(gone && strstr(gone, " 404 "),
                     "%s: and past the password, 404", bin);
  free(gone);
}

/* a raw request sent on a new connection: its fd */
static int send_raw(const HOST *h, const char *req) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)h->port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0) {
    (void)!send(fd, req, strlen(req), MSG_NOSIGNAL);
  }
  return fd;
}

/* everything on fd until it closes (8 s at most): malloc'd */
static char *read_all(int fd) {
  size_t cap = 65536, len = 0;
  char *got = calloc(1, cap);
  struct pollfd p = {.fd = fd, .events = POLLIN};
  ssize_t r;
  while (got && poll(&p, 1, 8000) > 0 &&
         (r = recv(fd, got + len, cap - 1 - len, 0)) > 0) {
    len += (size_t)r;
  }
  close(fd);
  return got;
}

static long ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define WRONG "Authorization: Basic aGVsbG86d3Jvbmc=\r\n"
#define TRY(name)                                                              \
  "GET /hello-file/" name " HTTP/1.1\r\nHost: x\r\n" WRONG                     \
  "Connection: close\r\n\r\n"

/* the tarpit through the host: a wrong password's 401 held back, a guess
 * sent alongside it told to wait; none of it with --no-tarpit */
static void tarpit(const char *bin, const char *app) {
  HOST h;
  int status;
  const char *on[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--app",
                      app,        "--data",      g_data,   NULL};
  if (start(&h, bin, on, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "%s with its tarpit started", bin);
    return;
  }
  long t = ms_now();
  char *got = read_all(send_raw(&h, TRY("slow.txt")));
  long took = ms_now() - t;
  CSERVE_TEST_ASSERT(got && strstr(got, " 401 ") && took >= 900,
                     "%s: a wrong password: its 401 held back (%ld ms)", bin,
                     took);
  free(got);
  /* the second guess must come once the first has failed (its PBKDF2
   * done, its 401 held back): one PBKDF2 is timed with the right
   * password first, so a sanitizer's slower one is waited for too */
  t = ms_now();
  free(read_all(send_raw(&h, "GET /hello-file/f.txt HTTP/1.1\r\nHost: x\r\n"
                             "Authorization: Basic "
                             "aGVsbG86b3BlbiBzZXNhbWU=\r\n"
                             "Connection: close\r\n\r\n")));
  long check = ms_now() - t;
  int first = send_raw(&h, TRY("race.txt"));
  struct timespec pause = {(2 * check + 100) / 1000,
                           (2 * check + 100) % 1000 * 1000000L};
  nanosleep(&pause, NULL);
  got = read_all(send_raw(&h, TRY("race.txt")));
  char *was = read_all(first);
  CSERVE_TEST_ASSERT(got && strstr(got, " 429 ") &&
                         strstr(got, "Retry-After: ") && was &&
                         strstr(was, " 401 "),
                     "%s: a guess alongside it: 429, Retry-After", bin);
  free(got);
  free(was);
  CSERVE_TEST_ASSERT(replied(&h, "GET", "/hello-file/slow.txt", " 401 ", NULL),
                     "%s: no credentials at all: the plain challenge", bin);
  CSERVE_TEST_ASSERT(stop(&h) == 0, "%s: and stopped", bin);

  const char *off[] = {"--listen",    "127.0.0.1:0", "--root", g_root,
                       "--app",       app,           "--data", g_data,
                       "--no-tarpit", NULL};
  if (start(&h, bin, off, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "%s --no-tarpit started", bin);
    return;
  }
  t = ms_now();
  got = read_all(send_raw(&h, TRY("slow.txt")));
  took = ms_now() - t;
  CSERVE_TEST_ASSERT(got && strstr(got, " 401 ") && took < 900,
                     "%s --no-tarpit: the 401 at once (%ld ms)", bin, took);
  free(got);
  CSERVE_TEST_ASSERT(stop(&h) == 0, "%s --no-tarpit: and stopped", bin);
}

/* the same checks for either host, app given as app */
static void serve_through(const char *bin, const char *app) {
  HOST h;
  int status;
  const char *args[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--app",
                        app,        "--data",      g_data,   NULL};
  if (start(&h, bin, args, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "%s --app %s started (%d)", bin, app, status);
    return;
  }
  pages(&h, bin);
  CSERVE_TEST_ASSERT(
      replied(&h, "POST", "/hello", " 405 ", "Allow: GET, HEAD") &&
          replied(&h, "POST", "/hello", " 405 ", CSP),
      "%s: a method the route hasn't: 405, secured", bin);
  refusals(&h, bin);
  files(&h, bin);
  CSERVE_TEST_ASSERT(replied(&h, "GET", "/hello.txt", " 200 ", "a file"),
                     "%s: a file comes first", bin);
  CSERVE_TEST_ASSERT(
      replied(&h, "GET", "/other?x=1", " 404 ", "<p>nothing at /other</p>"),
      "%s: the rest: the app's 404", bin);
  CSERVE_TEST_ASSERT(
      replied(&h, "GET", "/a/../.htaccess", " 404 ", "<p>nothing at /a/"),
      "%s: a climbing path: the app's 404 too", bin);
  CSERVE_TEST_ASSERT(stop(&h) == 0, "%s: SIGTERM: a clean exit", bin);
}

/* GET target over plain HTTP with Host: host, the whole reply */
static char *plain_get(const HOST *h, const char *host, const char *target) {
  char req[1024];
  snprintf(req, sizeof req,
           "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target,
           host);
  return read_all(send_raw(h, req));
}

static int plain_says(const HOST *h, const char *host, const char *target,
                      const char *status, const char *has) {
  char *got = plain_get(h, host, target);
  int ok = got && strstr(got, status) && (!has || strstr(got, has));
  if (!ok) {
    printf("    %s %s: %.200s\n", host, target, got ? got : "(nothing)");
  }
  free(got);
  return ok;
}

/* --certs: a plain listener says only a challenge's answer or a 308, and
 * only for the certificates' names; SIGHUP reads them again and the host
 * goes on; the flags that must come together do */
static void certs(const char *bin) {
  char names[PATH_MAX], acme[PATH_MAX], tok[PATH_MAX + 64];
  if (!realpath("tests/data/names/good", names)) {
    CSERVE_TEST_ASSERT(0, "the names fixtures");
    return;
  }
  snprintf(acme, sizeof acme, "%s/acme", g_dir);
  mkdir(acme, 0700);
  snprintf(tok, sizeof tok, "%s/tok-EN_1", acme);
  put(tok, "tok-EN_1.thumbprint", 0600);
  snprintf(tok, sizeof tok, "%s/.hidden", acme);
  put(tok, "hidden", 0600);
  const char *args[] = {"--listen",    "127.0.0.1:0", "--listen-tls",
                        "127.0.0.1:0", "--certs",     names,
                        "--acme-dir",  acme,          "--root",
                        g_root,        NULL};
  HOST h;
  int status;
  if (start(&h, bin, args, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "--certs: started (%d)", status);
    return;
  }
  CSERVE_TEST_ASSERT(
      plain_says(&h, "a.test", "/hello.txt?x=1", " 308 ",
                 "Location: https://a.test/hello.txt?x=1\r\n") &&
          plain_says(&h, "B.test:8080", "/", " 308 ",
                     "Location: https://B.test/\r\n"),
      "--certs: plain HTTP for a name: a 308 to https, the port dropped");
  CSERVE_TEST_ASSERT(plain_says(&h, "evil.test", "/hello.txt", " 404 ", NULL) &&
                         plain_says(&h, "a.test:x", "/", " 404 ", NULL) &&
                         plain_says(&h, "a.test:", "/", " 404 ", NULL) &&
                         plain_says(&h, "localhost", "/", " 404 ", NULL),
                     "--certs: any other Host: a 404, never a redirect");
  CSERVE_TEST_ASSERT(
      plain_says(&h, "a.test", "/.well-known/acme-challenge/tok-EN_1", " 200 ",
                 "\r\n\r\ntok-EN_1.thumbprint") &&
          plain_says(&h, "a.test", "/.well-known/acme-challenge/nope", " 404 ",
                     NULL) &&
          plain_says(&h, "a.test", "/.well-known/acme-challenge/.hidden",
                     " 404 ", NULL) &&
          plain_says(&h, "a.test", "/.well-known/acme-challenge/..%2fx",
                     " 404 ", NULL) &&
          plain_says(&h, "a.test", "/.well-known/acme-challenge/", " 404 ",
                     NULL) &&
          plain_says(&h, "evil.test", "/.well-known/acme-challenge/tok-EN_1",
                     " 200 ", "tok-EN_1.thumbprint"),
      "--certs: a challenge's answer for a token in --acme-dir, for any "
      "Host (it's public); a 404 for anything else");
  kill(h.proc.pid, SIGHUP);
  struct timespec ts = {0, 200 * 1000000L};
  nanosleep(&ts, NULL);
  CSERVE_TEST_ASSERT(plain_says(&h, "a.test", "/", " 308 ", NULL),
                     "--certs: SIGHUP, and the host goes on");
  CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");

  const char *no_tls[] = {"--listen", "127.0.0.1:0", "--certs", names,
                          "--root",   g_root,        NULL};
  const char *no_certs[] = {"--listen-tls", "127.0.0.1:0", "--root", g_root,
                            NULL};
  const char *old[] = {"--listen",
                       "127.0.0.1:0",
                       "--root",
                       g_root,
                       "--tls",
                       "tests/data/pki/server.crt",
                       "tests/data/pki/server.key",
                       NULL};
  CSERVE_TEST_ASSERT(start(&h, bin, no_tls, &status) != 0 && status == 2 &&
                         start(&h, bin, no_certs, &status) != 0 &&
                         status == 2 && start(&h, bin, old, &status) != 0 &&
                         status == 2,
                     "--certs and --listen-tls only together, --tls gone: "
                     "usage, 2");
  const char *broken[] = {"--listen",    "127.0.0.1:0", "--listen-tls",
                          "127.0.0.1:0", "--certs",     "tests/data/names/rsa",
                          "--root",      g_root,        NULL};
  CSERVE_TEST_ASSERT(start(&h, bin, broken, &status) != 0 && status == 1,
                     "--certs that don't load: it won't start");

  /* the box before its first certificate: challenges answered, nothing
   * else, and a --certs with no names yet starts */
  const char *acme_alone[] = {"--listen", "127.0.0.1:0", "--acme-dir", acme,
                              "--root",   g_root,        NULL};
  if (start(&h, bin, acme_alone, &status) == 0) {
    CSERVE_TEST_ASSERT(
        plain_says(&h, "a.test", "/.well-known/acme-challenge/tok-EN_1",
                   " 200 ", "tok-EN_1.thumbprint") &&
            plain_says(&h, "a.test", "/hello.txt", " 404 ", NULL),
        "--acme-dir alone: a challenge's answer, and a 404 for the rest");
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "--acme-dir alone started");
  }
  char none[PATH_MAX];
  snprintf(none, sizeof none, "%s/no-names", g_dir);
  mkdir(none, 0700);
  const char *empty[] = {"--listen",    "127.0.0.1:0", "--listen-tls",
                         "127.0.0.1:0", "--certs",     none,
                         "--acme-dir",  acme,          "--root",
                         g_root,        NULL};
  if (start(&h, bin, empty, &status) == 0) {
    CSERVE_TEST_ASSERT(
        plain_says(&h, "a.test", "/.well-known/acme-challenge/tok-EN_1",
                   " 200 ", NULL) &&
            plain_says(&h, "a.test", "/", " 404 ", NULL),
        "--certs with no names yet: starts, answers challenges, redirects "
        "nobody");
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "--certs with no names yet started");
  }
}

/* --for and --app-root: an app answers its names alone, with files of
 * its own; any other name gets the host's own 404 */
static void bound(const char *bin) {
  char root2[PATH_MAX], file[PATH_MAX + 16];
  snprintf(root2, sizeof root2, "%s/root2", g_dir);
  mkdir(root2, 0700);
  snprintf(file, sizeof file, "%s/own.txt", root2);
  put(file, "its own file\n", 0600);
  const char *args[] = {"--listen",   "127.0.0.1:0", "--root", g_root,
                        "--app",      "hello",       "--for",  "a.test",
                        "--app-root", root2,         NULL};
  HOST h;
  int status;
  if (start(&h, bin, args, &status) != 0) {
    CSERVE_TEST_ASSERT(0, "--for started (%d)", status);
    return;
  }
  CSERVE_TEST_ASSERT(
      plain_says(&h, "a.test", "/hello", " 200 ", "hello") &&
          plain_says(&h, "A.test:8080", "/own.txt", " 200 ", "its own file") &&
          plain_says(&h, "a.test", "/hello.txt", " 404 ", NULL),
      "--for a.test: its routes and its own root's files, not "
      "the host's");
  CSERVE_TEST_ASSERT(
      plain_says(&h, "b.test", "/hello", " 404 ", "not found") &&
          plain_says(&h, "b.test", "/hello.txt", " 200 ", "a file"),
      "another name: no app answers it, the host's root does");
  CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  const char *early[] = {"--listen", "127.0.0.1:0", "--root", g_root,
                         "--for",    "a.test",      NULL};
  const char *bad[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--app",
                       "hello",    "--for",       "A.Test", NULL};
  CSERVE_TEST_ASSERT(start(&h, bin, early, &status) != 0 && status == 2 &&
                         start(&h, bin, bad, &status) != 0 && status == 2,
                     "--for before any --app, or not a lowercase name: usage");
}

static void test_hosts(void) {
  char dev[PATH_MAX], stat_bin[PATH_MAX], so[PATH_MAX];
  snprintf(dev, sizeof dev, "%s/cserve", CSERVE_BIN);
  snprintf(stat_bin, sizeof stat_bin, "%s/cserve-static", CSERVE_BIN);
  snprintf(so, sizeof so, "%s/apps/hello.so", CSERVE_BIN);
  serve_through(dev, so);
  serve_through(stat_bin, "hello");
  tarpit(stat_bin, "hello");
  certs(stat_bin);
  bound(stat_bin);

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
    CSERVE_TEST_ASSERT(0, "--app hello started");
  }
  const char *bare[] = {"--listen", "127.0.0.1:0", "--root", g_root, NULL};
  if (start(&h, stat_bin, bare, &status) == 0) {
    CSERVE_TEST_ASSERT(replied(&h, "GET", "/nope", " 404 ", "not found") &&
                           replied(&h, "GET", "/hello.txt", " 200 ", "a file"),
                       "no app: files, and the host's plain 404");
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "no app started");
  }
  char front_bin[PATH_MAX];
  snprintf(front_bin, sizeof front_bin, "%s/cserve-front", CSERVE_BIN);
  const char *front[] = {"--listen", "127.0.0.1:0", "--root", g_root, "--cgi",
                         g_front,    "--climb",     "front",  NULL};
  if (start(&h, front_bin, front, &status) == 0) {
    CSERVE_TEST_ASSERT(
        replied(&h, "GET", "/hello.txt", " 200 ", "a file") &&
            replied(&h, "GET", "/other?x=1", " 200 ", "front /other?x=1") &&
            replied(&h, "GET", "/a/../.htaccess", " 200 ",
                    "front /a/../.htaccess"),
        "cserve-front: a file, else the front, a climbing path too");
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  } else {
    CSERVE_TEST_ASSERT(0, "cserve-front started");
  }
  /* cserve-precompress: a copy beside a stylesheet, served to gzip */
  char css[PATH_MAX], gz[PATH_MAX], pc[PATH_MAX * 2 + 64], text[2048];
  snprintf(css, sizeof css, "%s/big.css", g_root);
  snprintf(gz, sizeof gz, "%s/big.css.gz", g_root);
  memset(text, 0, sizeof text);
  for (size_t i = 0; i + 16 < sizeof text; i += 15) {
    memcpy(text + i, "p{color:blue;}\n", 15);
  }
  put(css, text, 0600);
  snprintf(pc, sizeof pc, "'%s/cserve-precompress' '%s' > '%s/pc.out'",
           CSERVE_BIN, g_root, g_dir);
  int made = system(pc);
  struct stat zst, cst;
  CSERVE_TEST_ASSERT(made == 0 && stat(gz, &zst) == 0 && stat(css, &cst) == 0 &&
                         zst.st_size < cst.st_size / 4,
                     "cserve-precompress: a copy beside the stylesheet, "
                     "smaller");
  int again = system(pc);
  char out[PATH_MAX + 16], line[128] = "";
  snprintf(out, sizeof out, "%s/pc.out", g_dir);
  FILE *f = fopen(out, "r");
  if (f) {
    (void)!fgets(line, sizeof line, f);
    fclose(f);
  }
  CSERVE_TEST_ASSERT(again == 0 && strstr(line, "0 written, 1 fresh"),
                     "and run again, it's left as it is (%s)", line);
  if (start(&h, stat_bin, bare, &status) == 0) {
    char *got = ask_with(&h, "GET", "/big.css", "Accept-Encoding: gzip\r\n");
    char want[64];
    snprintf(want, sizeof want, "Content-Length: %lld\r\n",
             (long long)zst.st_size);
    CSERVE_TEST_ASSERT(got && strstr(got, "Content-Encoding: gzip\r\n") &&
                           strstr(got, want) && strstr(got, "\r\n\r\n\x1f\x8b"),
                       "cserve serves the copy to gzip: a gzip body");
    free(got);
    CSERVE_TEST_ASSERT(stop(&h) == 0, "and stopped");
  }
  unlink(gz);
  unlink(css);
  const char *gone[] = {"--listen", "127.0.0.1:0", "--root", g_root,
                        "--cgi",    "php-cgi",     NULL};
  CSERVE_TEST_ASSERT(start(&h, dev, gone, &status) != 0 && status == 2,
                     "--cgi is no flag of the host's any more: usage, 2");
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
  snprintf(g_data, sizeof g_data, "%s/data", g_dir);
  mkdir(g_data, 0700);
  snprintf(file, sizeof file, "%s/f.txt", g_data);
  put(file, "0123456789", 0600);
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
