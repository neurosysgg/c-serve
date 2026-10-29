/* a front controller run per request (php-cgi), its environment as
 * Apache names it, the body on its stdin, its reply head parsed and the
 * rest streamed */
/* vasprintf, asprintf, pipes and poll: POSIX + GNU, not C11 */
#define _GNU_SOURCE
#include "cgi.h"

#include "log.h"
#include "process.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define CGI_HEAD_MAX 16384

/* ours that the CGI keeps: who and where the user is (ctui-remote's hub
 * socket lives in XDG_RUNTIME_DIR), the locale, PHP's own ini */
static const char *const KEEP[] = {"HOME",
                                   "USER",
                                   "LOGNAME",
                                   "PATH",
                                   "LANG",
                                   "LC_ALL",
                                   "LC_CTYPE",
                                   "TZ",
                                   "XDG_RUNTIME_DIR",
                                   "XDG_CONFIG_HOME",
                                   "XDG_STATE_HOME",
                                   "XDG_DATA_HOME",
                                   "XDG_CACHE_HOME",
                                   "PHPRC"};

typedef struct {
  char **v;
  int n, cap;
} ENV;

static void env_add(ENV *e, const char *fmt, ...) {
  if (e->n + 2 > e->cap) {
    int cap = e->cap ? e->cap * 2 : 64;
    char **v = realloc(e->v, (size_t)cap * sizeof *v);
    if (!v) {
      return;
    }
    e->v = v;
    e->cap = cap;
  }
  va_list ap;
  va_start(ap, fmt);
  int k = vasprintf(&e->v[e->n], fmt, ap);
  va_end(ap);
  if (k >= 0) {
    e->v[++e->n] = NULL;
  }
}

/* a header's CGI name ("X-Thing" -> "HTTP_X_THING") into out: 0, or -1
 * for one that isn't passed: a name with '_' (it would pass for the '-'
 * one: Apache drops them too), Proxy (httpoxy), the two CONTENT_ ones */
static int header_var(const char *name, char *out, size_t cap) {
  if (strchr(name, '_') || !strcasecmp(name, "Proxy") ||
      !strcasecmp(name, "Content-Type") ||
      !strcasecmp(name, "Content-Length") || strlen(name) + 6 > cap) {
    return -1;
  }
  size_t n = (size_t)snprintf(out, cap, "HTTP_");
  for (const char *p = name; *p; p++) {
    out[n++] = *p == '-' ? '_' : (char)toupper((unsigned char)*p);
  }
  out[n] = '\0';
  return 0;
}

char **cserve_cgi_env(const CSERVE_CGI *c, const CSERVE_HTTPD_REQ *r,
                      const char *const *extra) {
  ENV e = {0};
  for (size_t i = 0; i < sizeof KEEP / sizeof *KEEP; i++) {
    const char *v = getenv(KEEP[i]);
    if (v) {
      env_add(&e, "%s=%s", KEEP[i], v);
    }
  }
  env_add(&e, "GATEWAY_INTERFACE=CGI/1.1");
  env_add(&e, "SERVER_SOFTWARE=%s", c->software ? c->software : "c-serve");
  env_add(&e, "SERVER_PROTOCOL=HTTP/1.%d", r->minor);
  /* Host without its port ([v6] keeps its brackets) */
  const char *host = cserve_httpd_header(r, "Host");
  if (host && *host) {
    const char *end = host[0] == '[' ? strchr(host, ']') : NULL;
    const char *colon = strchr(end ? end : host, ':');
    env_add(&e, "SERVER_NAME=%.*s",
            (int)(colon ? (size_t)(colon - host) : strlen(host)), host);
  } else {
    env_add(&e, "SERVER_NAME=localhost");
  }
  env_add(&e, "SERVER_PORT=%d", c->port);
  env_add(&e, "REQUEST_METHOD=%s", r->method);
  env_add(&e, "REQUEST_URI=%s", r->target);
  env_add(&e, "QUERY_STRING=%s", r->query ? r->query : "");
  env_add(&e, "SCRIPT_NAME=/%s", c->script);
  env_add(&e, "SCRIPT_FILENAME=%s/%s", c->root, c->script);
  env_add(&e, "DOCUMENT_ROOT=%s", c->root);
  env_add(&e, "REDIRECT_STATUS=200"); /* php-cgi's force-cgi-redirect */
  /* "1.2.3.4:5678", "[::1]:5678" */
  if (r->peer) {
    const char *colon = strrchr(r->peer, ':');
    const char *a = r->peer;
    size_t al = colon ? (size_t)(colon - a) : strlen(a);
    if (al >= 2 && a[0] == '[' && a[al - 1] == ']') {
      a++;
      al -= 2;
    }
    env_add(&e, "REMOTE_ADDR=%.*s", (int)al, a);
    if (colon) {
      env_add(&e, "REMOTE_PORT=%s", colon + 1);
    }
  }
  if (r->length >= 0) {
    env_add(&e, "CONTENT_LENGTH=%lld", r->length);
  }
  const char *ct = cserve_httpd_header(r, "Content-Type");
  if (ct) {
    env_add(&e, "CONTENT_TYPE=%s", ct);
  }
  if (c->https) {
    env_add(&e, "HTTPS=on");
  }
  env_add(&e, "REQUEST_SCHEME=%s", c->https ? "https" : "http");
  /* the headers: repeats joined (Cookie by "; ", the rest by ", ") */
  for (int i = 0; i < r->n; i++) {
    char var[128];
    if (header_var(r->h[i].name, var, sizeof var) != 0) {
      continue;
    }
    size_t vl = strlen(var);
    int seen = 0;
    for (int j = 0; j < e.n && !seen; j++) {
      if (!strncmp(e.v[j], var, vl) && e.v[j][vl] == '=') {
        char *joined;
        if (asprintf(&joined, "%s%s%s", e.v[j],
                     strcmp(var, "HTTP_COOKIE") ? ", " : "; ",
                     r->h[i].value) >= 0) {
          free(e.v[j]);
          e.v[j] = joined;
        }
        seen = 1;
      }
    }
    if (!seen) {
      env_add(&e, "%s=%s", var, r->h[i].value);
    }
  }
  /* the host's, then the request's own (a client certificate's) */
  for (int i = 0; c->env && c->env[i]; i++) {
    env_add(&e, "%s", c->env[i]);
  }
  for (int i = 0; extra && extra[i]; i++) {
    env_add(&e, "%s", extra[i]);
  }
  return e.v;
}

void cserve_cgi_env_free(char **env) {
  for (int i = 0; env && env[i]; i++) {
    free(env[i]);
  }
  free(env);
}

/* --- the reply's head --- */

static int tchar(unsigned char c) {
  return isalnum(c) || (c && strchr("!#$%&'*+-.^_`|~", c));
}

/* what isn't the CGI's to say: the connection's, the framing's */
static const char *const DROP[] = {
    "Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length", "TE",
    "Trailer",    "Upgrade",    "Proxy-Connection",  "Server"};

static long head_bad(char *err, size_t err_cap, const char *why) {
  snprintf(err, err_cap, "the CGI's reply head: %s", why);
  return -1;
}

long cserve_cgi_head(const char *buf, size_t len, CSERVE_HTTPD_REPLY *rep,
                     char *type, size_t type_cap, char *err, size_t err_cap) {
  /* the blank line ending it ("\n\n" or "\r\n\r\n", or mixed) */
  size_t end = 0, body = 0;
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != '\n') {
      continue;
    }
    size_t next = i + 1;
    if (next < len && buf[next] == '\r') {
      next++;
    }
    if (next < len && buf[next] == '\n') {
      end = i + 1;
      body = next + 1;
      break;
    }
    if (next >= len) {
      break;
    }
  }
  if (!end) {
    return len >= CGI_HEAD_MAX ? head_bad(err, err_cap, "too long") : 0;
  }
  if (end > CGI_HEAD_MAX) {
    return head_bad(err, err_cap, "too long");
  }
  rep->status = 0;
  rep->headers[0] = '\0';
  type[0] = '\0';
  size_t hl = 0;
  int location = 0;
  for (size_t p = 0; p < end;) {
    size_t q = p;
    while (q < end && buf[q] != '\n') {
      q++;
    }
    size_t ll = q - p;
    if (ll && buf[p + ll - 1] == '\r') {
      ll--;
    }
    const char *line = buf + p;
    p = q + 1;
    size_t nl = 0;
    while (nl < ll && tchar((unsigned char)line[nl])) {
      nl++;
    }
    if (nl == 0 || nl == ll || line[nl] != ':') {
      return head_bad(err, err_cap, "a line that isn't a header");
    }
    const char *v = line + nl + 1, *ve = line + ll;
    while (v < ve && (*v == ' ' || *v == '\t')) {
      v++;
    }
    while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) {
      ve--;
    }
    for (const char *k = v; k < ve; k++) {
      if ((unsigned char)*k < 0x20 && *k != '\t') {
        return head_bad(err, err_cap, "a control character in a value");
      }
    }
    int vl = (int)(ve - v);
    if (nl == 6 && !strncasecmp(line, "Status", 6)) {
      if (vl < 3 || !isdigit((unsigned char)v[0]) ||
          !isdigit((unsigned char)v[1]) || !isdigit((unsigned char)v[2]) ||
          (vl > 3 && v[3] != ' ')) {
        return head_bad(err, err_cap, "a Status that isn't one");
      }
      rep->status = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
      if (rep->status < 200 || rep->status > 599) {
        return head_bad(err, err_cap, "a Status out of range");
      }
      continue;
    }
    if (nl == 12 && !strncasecmp(line, "Content-Type", 12)) {
      if ((size_t)vl >= type_cap) {
        return head_bad(err, err_cap, "a Content-Type too long");
      }
      memcpy(type, v, (size_t)vl);
      type[vl] = '\0';
      continue;
    }
    int drop = 0;
    for (size_t i = 0; i < sizeof DROP / sizeof *DROP && !drop; i++) {
      drop = strlen(DROP[i]) == nl && !strncasecmp(line, DROP[i], nl);
    }
    if (drop) {
      continue;
    }
    location |= nl == 8 && !strncasecmp(line, "Location", 8);
    int k = snprintf(rep->headers + hl, sizeof rep->headers - hl,
                     "%.*s: %.*s\r\n", (int)nl, line, vl, v);
    if (k < 0 || (size_t)k >= sizeof rep->headers - hl) {
      rep->headers[hl] = '\0';
      return head_bad(err, err_cap, "its headers are too long");
    }
    hl += (size_t)k;
  }
  if (!rep->status) {
    rep->status = location ? 302 : 200;
  }
  return (long)body;
}

/* --- running it --- */

typedef struct {
  CSERVE_PROC proc;
  char *body; /* ours: the request's, copied (the handler's goes) */
  size_t body_len, body_off;
  int idle_ms;
  char type[256];
  char buf[CGI_HEAD_MAX + 4096];
  size_t len;
  long head;
} CGI;

static long now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* the body fed to its stdin while its stdout is read: up to cap bytes of
 * stdout into out (how many), 0 at its end, -1 at the deadline or on an
 * error */
static ssize_t pump(CGI *g, char *out, size_t cap, long deadline) {
  for (;;) {
    struct pollfd p[2] = {{.fd = g->proc.out, .events = POLLIN},
                          {.fd = g->proc.in, .events = POLLOUT}};
    int n = g->proc.in >= 0 ? 2 : 1;
    long left = deadline - now_ms();
    if (left <= 0) {
      return -1;
    }
    int r = poll(p, (nfds_t)n, (int)left);
    if (r < 0 && errno == EINTR) {
      continue;
    }
    if (r <= 0) {
      return -1;
    }
    if (n == 2 && p[1].revents) {
      ssize_t w = (p[1].revents & POLLOUT)
                      ? write(g->proc.in, g->body + g->body_off,
                              g->body_len - g->body_off)
                      : -1;
      if (w > 0) {
        g->body_off += (size_t)w;
      }
      /* all of it, or it stopped reading (gone, EPIPE): stdin closed */
      if ((w < 0 && errno != EAGAIN) || g->body_off == g->body_len) {
        close(g->proc.in);
        g->proc.in = -1;
      }
    }
    if (p[0].revents) {
      ssize_t got = read(g->proc.out, out, cap);
      if (got >= 0) {
        return got;
      }
      if (errno != EAGAIN && errno != EINTR) {
        return -1;
      }
    }
  }
}

static void cgi_end(CGI *g, int kill_now) {
  int status = cserve_spawn_wait(&g->proc, kill_now ? 0 : 5000);
  if (status != 0 && !kill_now) {
    cserve_logf(CSERVE_LOG_WARN, "the CGI ended with %d", status);
  }
  free(g->body);
  free(g);
}

static int stream(CSERVE_HTTPD_OUT *o, void *ud) {
  CGI *g = ud;
  int ok = cserve_httpd_out(o, g->buf + g->head, g->len - (size_t)g->head) == 0;
  char chunk[16384];
  while (ok) {
    ssize_t n = pump(g, chunk, sizeof chunk, now_ms() + g->idle_ms);
    if (n == 0) {
      cgi_end(g, 0);
      return 0;
    }
    ok = n > 0 && cserve_httpd_out(o, chunk, (size_t)n) == 0;
  }
  /* the client gone, or the CGI quiet too long: it goes */
  cgi_end(g, 1);
  return -1;
}

static void fail(CSERVE_HTTPD_REPLY *rep, int status, const char *fmt, ...) {
  char text[400];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(text, sizeof text, fmt, ap);
  va_end(ap);
  if (n < 0) {
    n = 0;
  } else if ((size_t)n >= sizeof text) {
    n = sizeof text - 1;
  }
  cserve_logf(CSERVE_LOG_WARN, "%d: %s", status, text);
  rep->headers[0] = '\0';
  cserve_httpd_text(rep, status, "text/plain; charset=utf-8", text, (size_t)n);
}

void cserve_cgi(const CSERVE_CGI *c, const CSERVE_HTTPD_REQ *r,
                const char *body, const char *const *extra,
                CSERVE_HTTPD_REPLY *rep) {
  CGI *g = calloc(1, sizeof *g);
  char **env = cserve_cgi_env(c, r, extra);
  if (!g || !env) {
    free(g);
    cserve_cgi_env_free(env);
    fail(rep, 500, "out of memory\n");
    return;
  }
  g->idle_ms = c->idle_ms > 0 ? c->idle_ms : 120000;
  if (body && r->length > 0) {
    g->body_len = (size_t)r->length;
    g->body = malloc(g->body_len);
    if (g->body) {
      memcpy(g->body, body, g->body_len);
    } else {
      g->body_len = 0;
    }
  }
  CSERVE_SPAWN s = {.argv = c->argv,
                    .cwd = c->root,
                    .envp = (const char *const *)env,
                    .in_pipe = g->body_len > 0};
  int spawned = cserve_spawn(&s, &g->proc);
  int why = errno;
  cserve_cgi_env_free(env);
  if (spawned != 0) {
    fail(rep, 502, "the CGI (%s): %s\n", c->argv[0], strerror(why));
    free(g->body);
    free(g);
    return;
  }
  if (g->proc.in >= 0) {
    fcntl(g->proc.in, F_SETFL, fcntl(g->proc.in, F_GETFL) | O_NONBLOCK);
  }
  /* its head, within head_ms */
  long deadline = now_ms() + (c->head_ms > 0 ? c->head_ms : 30000);
  char err[160];
  for (;;) {
    ssize_t n = pump(g, g->buf + g->len, sizeof g->buf - g->len, deadline);
    if (n <= 0) {
      fail(rep, n == 0 ? 502 : 504, "the CGI %s\n",
           n < 0    ? "didn't answer in time"
           : g->len ? "ended in its reply head"
                    : "ended without a reply");
      cgi_end(g, n != 0);
      return;
    }
    g->len += (size_t)n;
    g->head = cserve_cgi_head(g->buf, g->len, rep, g->type, sizeof g->type, err,
                              sizeof err);
    if (g->head < 0) {
      fail(rep, 502, "%s\n", err);
      cgi_end(g, 1);
      return;
    }
    if (g->head > 0) {
      break;
    }
  }
  rep->type = g->type[0] ? g->type : NULL;
  rep->stream = stream;
  rep->stream_ud = g;
}
