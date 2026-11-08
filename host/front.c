/* cserve-front: a PHP site's web root served the way Apache serves it,
 * with its front controller as CGI -- the reference a native app is
 * diffed against (neurosys's test/cserve/diff.sh), and nothing more. It
 * is the threaded server (listen.h, httpd.h's serve()), whose CGI pull
 * may wait (cgi.h); it is never deployed: the box runs cserve, on the
 * loop. Per request: a static file from the root, else the front. */
/* realpath, sigaction: POSIX, not C11 */
#define _GNU_SOURCE
#include "cgi.h"
#include "conn.h"
#include "httpd.h"
#include "listen.h"
#include "log.h"
#include "static.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LISTEN_MAX 8
#define ENV_MAX 32

static struct {
  char root[PATH_MAX];
  CSERVE_STATIC st;
  const char *cgi_argv[2];
  CSERVE_CGI cgi; /* port set per request */
  const char *env[ENV_MAX + 1];
} H;

static void text(CSERVE_HTTPD_REPLY *rep, int status, const char *t) {
  cserve_httpd_text(rep, status, "text/plain; charset=utf-8", t, strlen(t));
}

static void handle(const CSERVE_HTTPD_REQ *r, const char *body,
                   CSERVE_HTTPD_REPLY *rep, void *ud) {
  CSERVE_STATIC_ROUTE rt;
  cserve_static_route(&H.st, r->path, &rt);
  if (rt.kind == CSERVE_STATIC_FILE) {
    cserve_static_serve(r, &rt, rep);
  } else if (rt.kind == CSERVE_STATIC_BAD) {
    text(rep, 400, "a path that climbs out\n");
  } else {
    CSERVE_CGI c = H.cgi;
    c.port = *(const int *)ud;
    cserve_cgi(&c, r, body, NULL, rep);
  }
  cserve_logf(CSERVE_LOG_INFO, "%s %s -> %d", r->method, r->target,
              rep->status);
}

static void on_conn(CSERVE_CONN *c, const char *peer, void *ud) {
  CSERVE_HTTPD h = {.handler = handle, .ud = ud, .server = "c-serve"};
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
          "usage: cserve-front --listen HOST:PORT... --root DIR --cgi PROGRAM\n"
          "       [--front FILE] [--env K=V]... [--climb 400|front] [-v]\n");
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

int main(int argc, char **argv) {
  const char *listen[LISTEN_MAX], *root = NULL, *front = "index.php";
  const char *cgi = NULL;
  int nlisten = 0, nenv = 0, verbose = 0;
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
    } else if (!strcmp(a, "-v")) {
      verbose = 1;
    } else {
      return usage();
    }
  }
  if (!nlisten || !root || !cgi || strchr(front, '/')) {
    return usage();
  }
  if (!realpath(root, H.root)) {
    fprintf(stderr, "cserve-front: %s: %s\n", root, strerror(errno));
    return 1;
  }
  if (verbose) {
    cserve_log_set(log_all, NULL);
  }
  H.st.root = H.root;
  H.cgi_argv[0] = cgi;
  H.cgi = (CSERVE_CGI){
      .argv = H.cgi_argv, .root = H.root, .script = front, .env = H.env};
  char err[512];
  CSERVE_LISTEN *ls[LISTEN_MAX];
  int ports[LISTEN_MAX];
  for (int i = 0; i < nlisten; i++) {
    char host[256];
    if (split_addr(listen[i], host, sizeof host, &ports[i]) != 0) {
      fprintf(stderr, "cserve-front: --listen %s: not HOST:PORT\n", listen[i]);
      return 1;
    }
    if (!(ls[i] = cserve_listen_new(host, ports[i], on_conn, &ports[i], err,
                                    sizeof err))) {
      fprintf(stderr, "cserve-front: %s: %s\n", listen[i], err);
      return 1;
    }
    ports[i] = ls[i]->port; /* asked for 0: the kernel's */
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
    fprintf(stderr, "cserve-front: %s\n", err);
  }
  for (int i = 0; i < nlisten; i++) {
    cserve_listen_free(ls[i]);
  }
  return rc ? 1 : 0;
}
