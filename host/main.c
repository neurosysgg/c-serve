/* cserve: the host. Listens (plain, TLS, or mutual TLS), then per
 * request: a static file from the root, else the first app whose routes
 * fit, else the front controller as CGI, else 404. A development build
 * dlopen()s apps given as a path (--app apps/hello.so); a production one
 * is linked with its apps (the Makefile's STATIC_APPS) and loads none. */
/* realpath, sigaction, dlopen: POSIX, not C11 */
#define _GNU_SOURCE
#include "app.h"
#include "cgi.h"
#include "conn.h"
#include "httpd.h"
#include "listen.h"
#include "log.h"
#include "policy.h"
#include "route.h"
#include "static.h"
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
#define ENV_MAX 32

typedef struct {
  char root[PATH_MAX];
  CSERVE_STATIC st;
  const char *cgi_argv[2];
  CSERVE_CGI cgi; /* port and https set per request */
  int have_cgi;
  const char *env[ENV_MAX + 1];
  const CSERVE_APP *apps[APPS_MAX];
  char *security[APPS_MAX]; /* each app's security header lines, or NULL */
  int napps;
  CSERVE_TLS_SERVER *tls;
  int verbose;
} HOST;

static HOST H;

/* a connection's: which listener it came in on, whether it's TLS */
typedef struct {
  int port;
  int https;
} CONN_CTX;

static void text(CSERVE_HTTPD_REPLY *rep, int status, const char *t) {
  cserve_httpd_text(rep, status, "text/plain; charset=utf-8", t, strlen(t));
}

/* app i's security headers put before what it answered with. Headers
 * that won't fit with them are a 500: a reply never goes out without
 * them (a streamed one keeps its stream, whose bytes become the 500's) */
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
    if (rep->owned) {
      free(rep->body);
      rep->owned = 0;
    }
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

static void handle(const CSERVE_HTTPD_REQ *r, const char *body,
                   CSERVE_HTTPD_REPLY *rep, void *ud) {
  const CONN_CTX *cc = ud;
  CSERVE_STATIC_ROUTE rt;
  cserve_static_route(&H.st, r->path, &rt);
  const char *by = "404";
  if (rt.kind == CSERVE_STATIC_FILE) {
    cserve_static_serve(r, &rt, rep);
    by = "file";
  } else if (rt.kind == CSERVE_STATIC_BAD) {
    text(rep, 400, "a path that climbs out\n");
    by = "refused";
  } else {
    for (int i = 0; i < H.napps && !rep->status; i++) {
      if (route(i, r, body, rep)) {
        by = H.apps[i]->name;
        secure(rep, i);
      }
    }
    for (int i = 0; i < H.napps && !rep->status && !H.have_cgi; i++) {
      void (*not_found)(const CSERVE_HTTPD_REQ *, const char *,
                        CSERVE_HTTPD_REPLY *) =
          CSERVE_APP_SLOT(H.apps[i], not_found);
      if (not_found) {
        not_found(r, body, rep);
        if (!rep->status) {
          text(rep, 500, "an app's not_found answered nothing\n");
        }
        by = H.apps[i]->name;
        secure(rep, i);
      }
    }
    if (!rep->status && H.have_cgi) {
      CSERVE_CGI c = H.cgi;
      c.port = cc->port;
      c.https = cc->https;
      cserve_cgi(&c, r, body, NULL, rep);
      by = "cgi";
    } else if (!rep->status) {
      text(rep, 404, "not found\n");
    }
  }
  cserve_logf(CSERVE_LOG_INFO, "%s %s %s -> %d (%s)", r->peer ? r->peer : "?",
              r->method, r->target, rep->status, by);
}

static void on_conn(CSERVE_CONN *c, const char *peer, void *ud) {
  CONN_CTX cc = {.port = *(const int *)ud};
  char err[256];
  if (H.tls) {
    if (cserve_conn_accept_tls(c, H.tls, err, sizeof err) != 0) {
      cserve_logf(CSERVE_LOG_WARN, "%s: handshake refused: %s", peer, err);
      cserve_conn_close(c);
      return;
    }
    cc.https = 1;
  }
  CSERVE_HTTPD h = {.handler = handle, .ud = &cc, .server = "c-serve"};
  cserve_httpd_serve(&h, c, peer);
}

static void log_all(CSERVE_LOG_LEVEL level, const char *line, void *ud) {
  (void)ud;
  fprintf(stderr, "%s%s\n", level == CSERVE_LOG_WARN ? "c-serve: " : "", line);
}

static int g_stop[2] = {-1, -1};

static void on_signal(int sig) {
  (void)sig;
  int e = errno;
  (void)!write(g_stop[1], "x", 1);
  errno = e;
}

static int usage(void) {
  fprintf(stderr,
          "usage: cserve --listen HOST:PORT... --root DIR [--front FILE]\n"
          "       [--cgi PROGRAM] [--env K=V]... [--climb 400|front]\n"
          "       [--tls CERT KEY [--client-ca CA]] [--app NAME|PATH.so]...\n"
          "       [--data DIR] [-v]\n");
  return 2;
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
  const char *listen[LISTEN_MAX], *root = NULL, *front = "index.php";
  const char *cgi = NULL, *cert = NULL, *key = NULL, *client_ca = NULL;
  const char *app_names[APPS_MAX], *data = NULL;
  int nlisten = 0, nenv = 0, napp = 0;
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    int more = i + 1 < argc;
    if (!strcmp(a, "--listen") && more && nlisten < LISTEN_MAX) {
      listen[nlisten++] = argv[++i];
    } else if (!strcmp(a, "--root") && more) {
      root = argv[++i];
    } else if (!strcmp(a, "--front") && more) {
      front = argv[++i];
    } else if (!strcmp(a, "--cgi") && more) {
      cgi = argv[++i];
    } else if (!strcmp(a, "--env") && more && nenv < ENV_MAX &&
               strchr(argv[i + 1], '=')) {
      H.env[nenv++] = argv[++i];
    } else if (!strcmp(a, "--climb") && more &&
               (!strcmp(argv[i + 1], "400") || !strcmp(argv[i + 1], "front"))) {
      H.st.climb_front = !strcmp(argv[++i], "front");
    } else if (!strcmp(a, "--tls") && i + 2 < argc) {
      cert = argv[++i];
      key = argv[++i];
    } else if (!strcmp(a, "--client-ca") && more) {
      client_ca = argv[++i];
    } else if (!strcmp(a, "--app") && more && napp < APPS_MAX) {
      app_names[napp++] = argv[++i];
    } else if (!strcmp(a, "--data") && more) {
      data = argv[++i];
    } else if (!strcmp(a, "-v")) {
      H.verbose = 1;
    } else {
      return usage();
    }
  }
  if (!nlisten || !root || (client_ca && !cert) || strchr(front, '/')) {
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
  if (cgi) {
    H.cgi_argv[0] = cgi;
    H.cgi = (CSERVE_CGI){
        .argv = H.cgi_argv, .root = H.root, .script = front, .env = H.env};
    H.have_cgi = 1;
  }
  char err[512];
  CSERVE_APP_ENV env = {.root = H.root, .data = data};
  for (int i = 0; i < napp; i++) {
    const CSERVE_APP *a = find_app(app_names[i], err, sizeof err);
    int (*init)(const CSERVE_APP_ENV *, char *, size_t) =
        a ? CSERVE_APP_SLOT(a, init) : NULL;
    if (!a || (init && init(&env, err, sizeof err) != 0)) {
      fprintf(stderr, "cserve: app %s: %s\n", app_names[i], err);
      return 1;
    }
    const CSERVE_SECURITY *policy = CSERVE_APP_SLOT(a, security);
    char lines[2048];
    if (policy && (cserve_security_headers(policy, lines, sizeof lines, err,
                                           sizeof err) != 0 ||
                   !(H.security[H.napps] = strdup(lines)))) {
      fprintf(stderr, "cserve: app %s: its security headers: %s\n",
              app_names[i], err);
      return 1;
    }
    H.apps[H.napps++] = a;
  }
  if (cert &&
      !(H.tls = cserve_tls_server_new(cert, key, client_ca, err, sizeof err))) {
    fprintf(stderr, "cserve: TLS: %s\n", err);
    return 1;
  }
  CSERVE_LISTEN *ls[LISTEN_MAX];
  int ports[LISTEN_MAX];
  for (int i = 0; i < nlisten; i++) {
    char host[256];
    if (split_addr(listen[i], host, sizeof host, &ports[i]) != 0) {
      fprintf(stderr, "cserve: --listen %s: not HOST:PORT\n", listen[i]);
      return 1;
    }
    if (!(ls[i] = cserve_listen_new(host, ports[i], on_conn, &ports[i], err,
                                    sizeof err))) {
      fprintf(stderr, "cserve: %s: %s\n", listen[i], err);
      return 1;
    }
    ports[i] = ls[i]->port; /* asked for 0: the kernel's */
    /* the line a script waits for */
    printf("listening on %s%s%s:%d\n", strchr(host, ':') ? "[" : "", host,
           strchr(host, ':') ? "]" : "", ports[i]);
  }
  fflush(stdout);
  if (pipe2(g_stop, O_CLOEXEC) != 0) {
    return 1;
  }
  struct sigaction sa = {.sa_handler = on_signal};
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);
  int rc = cserve_listen_serve(ls, nlisten, g_stop[0], err, sizeof err);
  if (rc != 0) {
    fprintf(stderr, "cserve: %s\n", err);
  }
  for (int i = 0; i < nlisten; i++) {
    cserve_listen_free(ls[i]);
  }
  for (int i = 0; i < H.napps; i++) {
    void (*fini)(void) = CSERVE_APP_SLOT(H.apps[i], fini);
    if (fini) {
      fini();
    }
    free(H.security[i]);
  }
  cserve_tls_server_free(H.tls);
  return rc ? 1 : 0;
}
