/* cserve: the host. Listens (plain or TLS) on one loop (loop.h), then
 * per request, on a worker: a static file from the root, else the first
 * app whose routes fit, else the first app's own 404 (a climbing path
 * too), else a plain 404. With --certs, TLS listeners pick a certificate
 * by SNI (tls.h) and SIGHUP reads the certificates again. With --certs or
 * --acme-dir, a plain listener answers only an ACME challenge's answer
 * (from --acme-dir, for any Host: it's public, and its token is the
 * gate) or a 308 to the https address -- for one of the certificates'
 * names alone -- and a 404 for the rest. A development build dlopen()s apps
 * given as a path (--app apps/hello.so); a production one is linked with its
 * apps (the Makefile's STATIC_APPS) and loads none. */
/* realpath, sigaction, dlopen: POSIX, not C11 */
#define _GNU_SOURCE
#include "acme.h"
#include "app.h"
#include "httpd.h"
#include "listen.h"
#include "log.h"
#include "loop.h"
#include "policy.h"
#include "route.h"
#include "static.h"
#include "tarpit.h"
#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef CSERVE_DLOPEN
#include <dlfcn.h>
#endif

/* the apps linked in (the generated apps.c), NULL-terminated */
extern const CSERVE_APP *const cserve_apps[];

#define LISTEN_MAX 8
#define APPS_MAX 16

typedef struct {
  char root[PATH_MAX];
  CSERVE_STATIC st;
  const CSERVE_APP *apps[APPS_MAX];
  char *security[APPS_MAX]; /* each app's security header lines, or NULL */
  int napps;
  CSERVE_TLS_SERVER *tls; /* --certs: the names' certificates */
  const char *acme;       /* --acme-dir: HTTP-01 answers, by token */
  int verbose;
} HOST;

static HOST H;

/* the tarpit (tarpit.h), made before the apps' init() and freed on every
 * way out, an early one too */
static CSERVE_TARPIT *g_pit;

static int bail(void) {
  cserve_tarpit_free(g_pit);
  g_pit = NULL;
  return 1;
}

static void text(CSERVE_HTTPD_REPLY *rep, int status, const char *t) {
  cserve_httpd_text(rep, status, "text/plain; charset=utf-8", t, strlen(t));
}

/* app i's security headers put before what it answered with. Headers
 * that won't fit with them are a 500: a reply never goes out without
 * them (a pulled body is let go: done() called, the 500's own body
 * sent) */
static void secure(CSERVE_HTTPD_REPLY *rep, int i) {
  const char *lines = H.security[i];
  if (!lines) {
    return;
  }
  size_t n = strlen(lines), have = strlen(rep->headers);
  if (n + have >= sizeof rep->headers) {
    cserve_logf(CSERVE_LOG_WARN,
                "%s: a reply whose headers leave no room "
                "for its security headers",
                H.apps[i]->name);
    cserve_httpd_release(rep);
    rep->stream_length = 0;
    rep->status = 500;
    rep->type = "text/plain; charset=utf-8";
    rep->body = (char *)"500 Internal Server Error\n";
    rep->len = strlen(rep->body);
    rep->headers[0] = '\0';
    have = 0;
  }
  memmove(rep->headers + n, rep->headers, have + 1);
  memcpy(rep->headers, lines, n);
}

/* app i's routes asked: 1 when one of its patterns fits (it answered, or
 * its refuse did, or the router's 405), 0 when none does */
static int route(int i, const CSERVE_HTTPD_REQ *r, const char *body,
                 CSERVE_HTTPD_REPLY *rep) {
  const CSERVE_APP *app = H.apps[i];
  const CSERVE_ROUTE *routes = CSERVE_APP_SLOT(app, routes);
  void (*refuse)(const CSERVE_HTTPD_REQ *, const char *, unsigned,
                 CSERVE_HTTPD_REPLY *) = CSERVE_APP_SLOT(app, refuse);
  if (!routes) {
    return 0;
  }
  if (!refuse) {
    return cserve_route_dispatch(routes, app->nroutes, r, body, rep);
  }
  CSERVE_ROUTE_MATCH m;
  unsigned allow;
  int k = cserve_route_find(routes, app->nroutes, r, &m, &allow);
  if (k >= 0) {
    routes[k].fn(r, body, &m, rep);
  } else if (allow) {
    refuse(r, body, allow, rep);
  } else {
    return 0;
  }
  if (!rep->status) {
    text(rep, 500, "an app's route answered nothing\n");
  }
  return 1;
}

/* an HTTP-01 challenge's answer: --acme-dir's file named token, or a 404 */
static void challenge(const char *token, CSERVE_HTTPD_REPLY *rep) {
  char path[PATH_MAX];
  int fd = -1;
  if (H.acme && cserve_acme_token_ok(token, strlen(token)) &&
      snprintf(path, sizeof path, "%s/%s", H.acme, token) < (int)sizeof path) {
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  }
  char buf[1024];
  ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf) : -1;
  if (fd >= 0) {
    close(fd);
  }
  if (n <= 0 || (size_t)n == sizeof buf) {
    text(rep, 404, "not found\n");
    return;
  }
  cserve_httpd_text(rep, 200, "application/octet-stream", buf, (size_t)n);
}

/* a request over plain HTTP to a host with certificates or challenges:
 * an ACME challenge's answer; for one of the certificates' names, a 308
 * to the same target over https; else a 404 -- never a redirect
 * somewhere a request chose */
static void plain(const CSERVE_HTTPD_REQ *r, CSERVE_HTTPD_REPLY *rep) {
  static const char PREFIX[] = "/.well-known/acme-challenge/";
  const char *host = cserve_httpd_header(r, "Host");
  size_t n = host ? strcspn(host, ":") : 0;
  int port_ok =
      host && (!host[n] || (host[n + 1] && strspn(host + n + 1, "0123456789") ==
                                               strlen(host + n + 1)));
  if (!strncmp(r->target, PREFIX, sizeof PREFIX - 1)) {
    challenge(r->target + sizeof PREFIX - 1, rep);
  } else if (!H.tls || !port_ok || !cserve_tls_names_has(H.tls, host, n)) {
    text(rep, 404, "not found\n");
  } else if (snprintf(rep->headers, sizeof rep->headers,
                      "Location: https://%.*s%s\r\n", (int)n, host,
                      r->target) >= (int)sizeof rep->headers) {
    rep->headers[0] = '\0';
    text(rep, 414, "too long a target\n");
  } else {
    text(rep, 308, "over https\n");
  }
}

static void handle(const CSERVE_HTTPD_REQ *r, const char *body,
                   CSERVE_HTTPD_REPLY *rep, void *ud) {
  (void)ud;
  if ((H.tls || H.acme) && !r->tls) {
    plain(r, rep);
    return;
  }
  CSERVE_STATIC_ROUTE rt;
  cserve_static_route(&H.st, r->path, &rt);
  if (rt.kind == CSERVE_STATIC_FILE) {
    cserve_static_serve(r, &rt, rep);
  } else if (rt.kind == CSERVE_STATIC_BAD) {
    text(rep, 400, "a path that climbs out\n");
  } else {
    for (int i = 0; i < H.napps && !rep->status; i++) {
      if (route(i, r, body, rep)) {
        secure(rep, i);
      }
    }
    for (int i = 0; i < H.napps && !rep->status; i++) {
      void (*not_found)(const CSERVE_HTTPD_REQ *, const char *,
                        CSERVE_HTTPD_REPLY *) =
          CSERVE_APP_SLOT(H.apps[i], not_found);
      if (not_found) {
        not_found(r, body, rep);
        if (!rep->status) {
          text(rep, 500, "an app's not_found answered nothing\n");
        }
        secure(rep, i);
      }
    }
    if (!rep->status) {
      text(rep, 404, "not found\n");
    }
  }
}

static void log_all(CSERVE_LOG_LEVEL level, const char *line, void *ud) {
  (void)ud;
  fprintf(stderr, "%s%s\n", level == CSERVE_LOG_WARN ? "c-serve: " : "", line);
}

static int g_stop[2] = {-1, -1}, g_hup[2] = {-1, -1};

static void on_signal(int sig) {
  int e = errno;
  (void)!write(sig == SIGHUP ? g_hup[1] : g_stop[1], "x", 1);
  errno = e;
}

/* SIGHUP, on the loop's thread: the certificates read again. What it
 * did is said on stderr, -v or not -- a renewal that didn't take must
 * not go unseen. */
static void on_hup(void *ud) {
  (void)ud;
  char drain[64];
  while (read(g_hup[0], drain, sizeof drain) > 0) {
  }
  char err[512];
  if (cserve_tls_names_reload(H.tls, err, sizeof err) != 0) {
    fprintf(stderr, "cserve: SIGHUP: %s; the certificates before stay\n", err);
  } else {
    fprintf(stderr, "cserve: SIGHUP: the certificates read again: %d names\n",
            cserve_tls_names_count(H.tls));
  }
}

static int usage(void) {
  fprintf(stderr,
          "usage: cserve --listen HOST:PORT... --root DIR\n"
          "       [--certs DIR --listen-tls HOST:PORT...] [--acme-dir DIR]\n"
          "       [--app NAME|PATH.so]... [--data DIR] [--workers N]\n"
          "       [--max-conns N] [--per-addr N] [--no-tarpit] [-v]\n");
  return 2;
}

/* argv[i] as a count from 1 to max: 0, or -1 */
static int count(const char *a, int max, int *out) {
  char *end;
  long n = strtol(a, &end, 10);
  if (*end || end == a || n < 1 || n > max) {
    return -1;
  }
  *out = (int)n;
  return 0;
}

/* "127.0.0.1:8081", "[::1]:8081" into host and port: 0, or -1 */
static int split_addr(const char *a, char *host, size_t cap, int *port) {
  const char *colon = strrchr(a, ':');
  if (!colon || colon == a) {
    return -1;
  }
  const char *h = a, *he = colon;
  if (a[0] == '[' && colon[-1] == ']') {
    h++;
    he--;
  }
  char *end;
  long p = strtol(colon + 1, &end, 10);
  if (*end || p < 0 || p > 65535 || (size_t)(he - h) >= cap || he == h) {
    return -1;
  }
  memcpy(host, h, (size_t)(he - h));
  host[he - h] = '\0';
  *port = (int)p;
  return 0;
}

/* name (in the linked table) or a path (dlopen()ed): the app, or NULL
 * with why in err */
static const CSERVE_APP *find_app(const char *name, char *err, size_t cap) {
  const CSERVE_APP *a = NULL;
  if (!strchr(name, '/')) {
    for (int i = 0; cserve_apps[i] && !a; i++) {
      if (!strcmp(cserve_apps[i]->name, name)) {
        a = cserve_apps[i];
      }
    }
    if (!a) {
      snprintf(err, cap, "no app \"%s\" is linked in", name);
      return NULL;
    }
  } else {
#ifdef CSERVE_DLOPEN
    void *h = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
      snprintf(err, cap, "%s", dlerror());
      return NULL;
    }
    /* apps/hello.so -> cserve_app_hello */
    const char *base = strrchr(name, '/') + 1;
    char sym[128];
    int n = snprintf(sym, sizeof sym, "cserve_app_%.*s",
                     (int)strcspn(base, "."), base);
    a = n > 0 && (size_t)n < sizeof sym ? dlsym(h, sym) : NULL;
    if (!a) {
      snprintf(err, cap, "%s has no %s", name, sym);
      return NULL;
    }
#else
    snprintf(err, cap, "%s: this build loads no apps (STATIC_APPS)", name);
    return NULL;
#endif
  }
  if (a->abi != CSERVE_APP_ABI || a->size < offsetof(CSERVE_APP, init)) {
    snprintf(err, cap, "%s: ABI %d, not %d", name, a->abi, CSERVE_APP_ABI);
    return NULL;
  }
  return a;
}

int main(int argc, char **argv) {
  const char *listen[LISTEN_MAX], *root = NULL, *certs = NULL;
  const char *app_names[APPS_MAX], *data = NULL;
  int nlisten = 0, napp = 0, tarpit = 1, secure_from = 0;
  int is_tls[LISTEN_MAX] = {0};
  CSERVE_LOOP_CONFIG cfg = {.handler = handle, .server = "c-serve"};
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    int more = i + 1 < argc;
    if ((!strcmp(a, "--listen") || !strcmp(a, "--listen-tls")) && more &&
        nlisten < LISTEN_MAX) {
      is_tls[nlisten] = a[8] == '-';
      secure_from += is_tls[nlisten];
      listen[nlisten++] = argv[++i];
    } else if (!strcmp(a, "--root") && more) {
      root = argv[++i];
    } else if (!strcmp(a, "--certs") && more) {
      certs = argv[++i];
    } else if (!strcmp(a, "--acme-dir") && more) {
      H.acme = argv[++i];
    } else if (!strcmp(a, "--app") && more && napp < APPS_MAX) {
      app_names[napp++] = argv[++i];
    } else if (!strcmp(a, "--data") && more) {
      data = argv[++i];
    } else if (!strcmp(a, "--workers") && more &&
               count(argv[i + 1], 256, &cfg.workers) == 0) {
      i++;
    } else if (!strcmp(a, "--max-conns") && more &&
               count(argv[i + 1], 1 << 20, &cfg.max_conns) == 0) {
      i++;
    } else if (!strcmp(a, "--per-addr") && more &&
               count(argv[i + 1], 1 << 20, &cfg.per_addr) == 0) {
      i++;
    } else if (!strcmp(a, "--no-tarpit")) {
      tarpit = 0;
    } else if (!strcmp(a, "-v")) {
      H.verbose = 1;
    } else {
      return usage();
    }
  }
  /* certificates and a TLS listener come together */
  if (!nlisten || !root || !certs != !secure_from) {
    return usage();
  }
  if (!realpath(root, H.root)) {
    fprintf(stderr, "cserve: %s: %s\n", root, strerror(errno));
    return 1;
  }
  if (H.verbose) {
    cserve_log_set(log_all, NULL);
  }
  H.st.root = H.root;
  /* with no front behind it, a path that climbs is the app's 404 too: an
   * address that isn't there, said as every other is */
  H.st.climb_front = 1;
  char err[512];
  /* the brake on guessing (tarpit.h): on unless asked otherwise, and said
   * when it's off, since nothing else would show it */
  g_pit = tarpit ? cserve_tarpit_new(4096, NULL, err, sizeof err) : NULL;
  CSERVE_TARPIT_API pit_api = cserve_tarpit_api(g_pit);
  if (tarpit && !g_pit) {
    fprintf(stderr, "cserve: %s\n", err);
    return 1;
  }
  if (!tarpit) {
    cserve_logf(CSERVE_LOG_WARN,
                "--no-tarpit: failed logins are not slowed down");
  }
  CSERVE_APP_ENV env = {
      .root = H.root, .data = data, .tarpit = g_pit ? &pit_api : NULL};
  for (int i = 0; i < napp; i++) {
    const CSERVE_APP *a = find_app(app_names[i], err, sizeof err);
    int (*init)(const CSERVE_APP_ENV *, char *, size_t) =
        a ? CSERVE_APP_SLOT(a, init) : NULL;
    if (!a || (init && init(&env, err, sizeof err) != 0)) {
      fprintf(stderr, "cserve: app %s: %s\n", app_names[i], err);
      return bail();
    }
    const CSERVE_SECURITY *policy = CSERVE_APP_SLOT(a, security);
    char lines[2048];
    if (policy && (cserve_security_headers(policy, lines, sizeof lines, err,
                                           sizeof err) != 0 ||
                   !(H.security[H.napps] = strdup(lines)))) {
      fprintf(stderr, "cserve: app %s: its security headers: %s\n",
              app_names[i], err);
      return bail();
    }
    H.apps[H.napps++] = a;
  }
  if (certs && !(H.tls = cserve_tls_names_new(certs, err, sizeof err))) {
    fprintf(stderr, "cserve: TLS: %s\n", err);
    return bail();
  }
  if (H.tls && cserve_tls_names_count(H.tls) == 0) {
    fprintf(stderr,
            "cserve: %s has no names yet: every handshake is "
            "refused until a SIGHUP finds some\n",
            certs);
  }
  CSERVE_LOOP *loop = cserve_loop_new(&cfg, err, sizeof err);
  if (!loop) {
    fprintf(stderr, "cserve: %s\n", err);
    return bail();
  }
  for (int i = 0; i < nlisten; i++) {
    char host[256];
    int port, fd;
    if (split_addr(listen[i], host, sizeof host, &port) != 0) {
      fprintf(stderr, "cserve: --listen %s: not HOST:PORT\n", listen[i]);
      return bail();
    }
    if ((fd = cserve_listen_socket(host, port, &port, err, sizeof err)) < 0 ||
        cserve_loop_listen(loop, fd, is_tls[i] ? H.tls : NULL, err,
                           sizeof err) != 0) {
      fprintf(stderr, "cserve: %s: %s\n", listen[i], err);
      return bail();
    }
    /* the line a script waits for (asked for port 0: the kernel's) */
    printf("listening on %s%s%s:%d\n", strchr(host, ':') ? "[" : "", host,
           strchr(host, ':') ? "]" : "", port);
  }
  fflush(stdout);
  if (pipe2(g_stop, O_CLOEXEC) != 0 ||
      pipe2(g_hup, O_CLOEXEC | O_NONBLOCK) != 0) {
    return bail();
  }
  if (H.tls &&
      cserve_loop_watch(loop, g_hup[0], on_hup, NULL, err, sizeof err) != 0) {
    fprintf(stderr, "cserve: %s\n", err);
    return bail();
  }
  struct sigaction sa = {.sa_handler = on_signal};
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  if (H.tls) {
    sigaction(SIGHUP, &sa, NULL);
  }
  signal(SIGPIPE, SIG_IGN);
  int rc = cserve_loop_run(loop, g_stop[0], 5000, err, sizeof err);
  if (rc != 0) {
    fprintf(stderr, "cserve: %s\n", err);
  }
  cserve_loop_free(loop);
  for (int i = 0; i < H.napps; i++) {
    void (*fini)(void) = CSERVE_APP_SLOT(H.apps[i], fini);
    if (fini) {
      fini();
    }
    free(H.security[i]);
  }
  cserve_tls_server_free(H.tls);
  cserve_tarpit_free(g_pit);
  return rc ? 1 : 0;
}
