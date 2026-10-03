/* strcasecmp() is POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "net.h"

#include "coding.h"
#include "conn.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define NET_REDIRECTS 5
#define NET_TIMEOUT_MS 30000
#define NET_MAX (8u << 20)
/* what a redirect's body may be before it's given up on (it's dropped) */
#define NET_REDIRECT_BODY 65536
/* the most a Cookie header's value may be */
#define NET_COOKIE_MAX 16384

/* --- connections kept open between requests (keep-alive) --- */

/* at most this many idle ones per process, each for at most this long
 * (servers close theirs after 5-75 s; a stale one costs a retry) */
#define POOL_MAX 8
#define POOL_IDLE_MS 30000

typedef struct {
  CTUI_WM_CONN *c;
  int tls;
  char host[256], port[8];
  long since;
} IDLE;

static pthread_mutex_t g_pool_mu = PTHREAD_MUTEX_INITIALIZER;
static IDLE g_pool[POOL_MAX];
static int g_npool;
static pid_t g_pool_pid;

/* under the lock: a forked child leaves its parent's connections alone
 * (their TLS state is the parent's), forgetting them */
static void pool_own(void) {
  pid_t pid = getpid();
  if (g_pool_pid != pid) {
    g_npool = 0;
    g_pool_pid = pid;
  }
}

static void pool_drop(int i) {
  memmove(g_pool + i, g_pool + i + 1,
          (size_t)(g_npool - i - 1) * sizeof *g_pool);
  g_npool--;
}

/* an idle connection to u's host, or NULL; the expired ones closed */
static CTUI_WM_CONN *pool_take(const CTUI_WM_URL *u) {
  CTUI_WM_CONN *got = NULL, *old[POOL_MAX];
  int nold = 0;
  long now = ctui_wm_net_now();
  pthread_mutex_lock(&g_pool_mu);
  pool_own();
  /* the newest first: the likeliest to be open still */
  for (int i = g_npool - 1; i >= 0; i--) {
    IDLE *e = &g_pool[i];
    if (now - e->since > POOL_IDLE_MS) {
      old[nold++] = e->c;
      pool_drop(i);
    } else if (!got && e->tls == u->tls && !strcasecmp(e->host, u->host) &&
               !strcmp(e->port, u->port)) {
      got = e->c;
      pool_drop(i);
    }
  }
  pthread_mutex_unlock(&g_pool_mu);
  for (int i = 0; i < nold; i++) {
    ctui_wm_conn_close(old[i]);
  }
  if (got && !ctui_wm_conn_idle_ok(got)) {
    ctui_wm_conn_close(got);
    got = NULL;
  }
  return got;
}

/* c kept for u's host's next request (the oldest one closed when full) */
static void pool_put(const CTUI_WM_URL *u, CTUI_WM_CONN *c) {
  CTUI_WM_CONN *old = NULL;
  pthread_mutex_lock(&g_pool_mu);
  pool_own();
  if (g_npool == POOL_MAX) {
    old = g_pool[0].c;
    pool_drop(0);
  }
  IDLE *e = &g_pool[g_npool++];
  e->c = c;
  e->tls = u->tls;
  snprintf(e->host, sizeof e->host, "%s", u->host);
  snprintf(e->port, sizeof e->port, "%s", u->port);
  e->since = ctui_wm_net_now();
  pthread_mutex_unlock(&g_pool_mu);
  ctui_wm_conn_close(old);
}

void ctui_wm_net_idle_close(void) {
  CTUI_WM_CONN *all[POOL_MAX];
  pthread_mutex_lock(&g_pool_mu);
  pool_own();
  int n = g_npool;
  for (int i = 0; i < n; i++) {
    all[i] = g_pool[i].c;
  }
  g_npool = 0;
  pthread_mutex_unlock(&g_pool_mu);
  for (int i = 0; i < n; i++) {
    ctui_wm_conn_close(all[i]);
  }
}

int ctui_wm_net_idle_count(void) {
  pthread_mutex_lock(&g_pool_mu);
  pool_own();
  int n = g_npool;
  pthread_mutex_unlock(&g_pool_mu);
  return n;
}

/* --- one request --- */

/* one exchange's reply, as the decoder hands it over */
typedef struct {
  CTUI_WM_HTTP_DEC d;
  const CTUI_WM_HTTP_REQ *req;
  const CTUI_WM_HTTP_SINK *sink; /* NULL: the body gathered */
  CTUI_WM_HTTP_REPLY *rep;       /* the sink's, filled at the head */
  char *body;                    /* gathered: malloc'd */
  size_t len, cap, max;
  size_t total; /* the Content-Length, for req->progress; 0: not said */
  size_t raw;   /* the body's bytes as they came (before decoding) */
  int over, oom;
  int coded;                   /* gzip/deflate were offered */
  CTUI_WM_HTTP_CODING *coding; /* and one came: undone into body */
  char cerr[128];              /* why the coding was refused */
  char *hdr;                   /* the head's header lines (malloc'd), for rep */
  const char *url;             /* where a redirect led, NULL: the first URL */
  int redirect;
  int again; /* the redirect a POST's 307 / 308: sent again as it was */
  char loc[4096 + 256 + 16];
} EX;

/* the header lines h[0..n) without Content-Encoding and Content-Length:
 * the new length (NUL-terminated) */
static size_t strip(char *h, size_t n) {
  size_t w = 0;
  for (size_t r = 0; r < n;) {
    const char *nl = memchr(h + r, '\n', n - r);
    size_t ll = nl ? (size_t)(nl - (h + r)) + 1 : n - r;
    if (strncasecmp(h + r, "Content-Encoding:", 17) &&
        strncasecmp(h + r, "Content-Length:", 15)) {
      memmove(h + w, h + r, ll);
      w += ll;
    }
    r += ll;
  }
  h[w] = '\0';
  return w;
}

static int ex_head(CTUI_WM_HTTP_DEC *d) {
  EX *ex = d->ctx;
  const char *method = ex->req->method ? ex->req->method : "GET";
  CTUI_WM_HTTP_PARSED p = {.status = d->status,
                           .headers = d->headers,
                           .headers_len = d->headers_len};
  if (ex->req->replied) {
    ex->req->replied(ex->req->cookie_ctx, ex->url ? ex->url : ex->req->url,
                     d->headers, d->headers_len);
  }
  /* a POST's 301 / 302 / 303 goes on as a GET (what browsers do: the
   * page after a sign-in), its 307 / 308 as the same POST again */
  int get = !strcasecmp(method, "GET"), post = !strcasecmp(method, "POST"),
      moved = p.status == 301 || p.status == 302 || p.status == 303,
      again = p.status == 307 || p.status == 308;
  if ((get || post) && (moved || again) &&
      ctui_wm_http_header(&p, "Location", ex->loc, sizeof ex->loc)) {
    ex->again = post && again;
    /* its body read and dropped, so the connection can go on */
    ex->redirect = 1;
    return 0;
  }
  ex->hdr = malloc(d->headers_len + 1);
  if (!ex->hdr) {
    ex->oom = 1;
    return 1;
  }
  memcpy(ex->hdr, d->headers, d->headers_len);
  ex->hdr[d->headers_len] = '\0';
  char ce[128];
  if (ex->coded && ctui_wm_http_header(&p, "Content-Encoding", ce, sizeof ce)) {
    int r =
        ctui_wm_http_coding_open(ce, &ex->coding, ex->cerr, sizeof ex->cerr);
    if (r < 0) {
      return 1;
    }
    if (r > 0) {
      /* the body handed back is the decoded one: its coding and length
       * go */
      d->headers_len = strip(ex->hdr, d->headers_len);
    }
  }
  if (!ex->sink) {
    char v[32];
    if (ex->req->progress &&
        ctui_wm_http_header(&p, "Content-Length", v, sizeof v)) {
      ex->total = (size_t)strtoull(v, NULL, 10);
    }
    return 0;
  }
  /* the sink's rep: body "" with the headers (and the URL) after it */
  size_t ul = ex->url ? strlen(ex->url) + 1 : 0;
  char *b = malloc(d->headers_len + 2 + ul);
  if (!b) {
    ex->oom = 1;
    return 1;
  }
  b[0] = '\0';
  memcpy(b + 1, ex->hdr, d->headers_len + 1);
  ex->rep->status = d->status;
  ex->rep->body = b;
  ex->rep->headers = b + 1;
  ex->rep->headers_len = d->headers_len;
  if (ex->url) {
    memcpy(b + d->headers_len + 2, ex->url, ul);
    ex->rep->url = b + d->headers_len + 2;
  }
  return ex->sink->head && ex->sink->head(ex->sink->ctx, ex->rep);
}

/* decoded body bytes gathered */
static int gather(void *ctx, const char *buf, size_t n) {
  EX *ex = ctx;
  if (n > ex->max - ex->len) {
    ex->over = 1;
    return 1;
  }
  if (ex->len + n > ex->cap) {
    size_t cap = ex->cap ? ex->cap : 16384;
    while (cap < ex->len + n) {
      cap *= 2;
    }
    char *b = realloc(ex->body, cap);
    if (!b) {
      ex->oom = 1;
      return 1;
    }
    ex->body = b;
    ex->cap = cap;
  }
  memcpy(ex->body + ex->len, buf, n);
  ex->len += n;
  return 0;
}

static int ex_body(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n) {
  EX *ex = d->ctx;
  ex->raw += n;
  if (ex->redirect) {
    return ex->raw > NET_REDIRECT_BODY;
  }
  if (ex->sink) {
    return ex->sink->body(ex->sink->ctx, buf, n);
  }
  int r = ex->coding ? ctui_wm_http_coding_feed(ex->coding, buf, n, gather, ex,
                                                ex->cerr, sizeof ex->cerr)
                     : gather(ex, buf, n);
  if (r == 0 && ex->req->progress) {
    ex->req->progress(ex->req->progress_ctx, ex->raw, ex->total);
  }
  return r != 0;
}

/* req sent on c, the reply fed to ex's decoder until it's complete,
 * stopped or the server closes; *keep: c can take the next request. A
 * sink's body waits at most idle_ms for each read once the head is in. */
static int talk(EX *ex, CTUI_WM_CONN *c, const char *req, size_t req_len,
                int idle_ms, int *keep, char *err, size_t err_cap) {
  *keep = 0;
  if (ctui_wm_conn_write(c, req, req_len, err, err_cap) != 0) {
    return -1;
  }
  char buf[16384];
  size_t given = 0;
  int rc;
  for (;;) {
    if (ex->sink && ex->rep->body) {
      ctui_wm_conn_deadline(c, ctui_wm_net_now() + idle_ms);
    }
    ssize_t r = ctui_wm_conn_read(c, buf, sizeof buf, err, err_cap);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      rc = ctui_wm_http_dec_end(&ex->d, err, err_cap);
      break;
    }
    given += (size_t)r;
    rc = ctui_wm_http_dec_feed(&ex->d, buf, (size_t)r, err, err_cap);
    if (rc != 0) {
      rc = rc < 0 ? -1 : 0;
      break;
    }
  }
  /* nothing after the reply (the next one would start inside it) */
  *keep = rc == 0 && ctui_wm_http_dec_reusable(&ex->d) && given == ex->d.fed &&
          !ctui_wm_conn_pending(c);
  return rc;
}

/* one exchange with u, on a kept connection if reuse and there is one
 * (once more on a new one if that turns out closed), else a new one */
static int exchange(EX *ex, const CTUI_WM_URL *u, int reuse, const char *req,
                    size_t req_len, long deadline, int idle_ms, char *err,
                    size_t err_cap) {
  CTUI_WM_CONN *c = reuse ? pool_take(u) : NULL;
  int keep = 0, rc = -1;
  if (c) {
    ctui_wm_conn_deadline(c, deadline);
    rc = talk(ex, c, req, req_len, idle_ms, &keep, err, err_cap);
    if (rc != 0 && ex->d.fed == 0) {
      /* the server had closed it meanwhile: nothing came */
      ctui_wm_conn_close(c);
      c = NULL;
    }
  }
  if (!c) {
    c = ctui_wm_conn_open(u, deadline, err, err_cap);
    if (!c) {
      return -1;
    }
    rc = talk(ex, c, req, req_len, idle_ms, &keep, err, err_cap);
  }
  if (rc == 0 && ex->oom) {
    snprintf(err, err_cap, "out of memory");
    rc = -1;
  } else if (rc == 0 && ex->over) {
    snprintf(err, err_cap, "the reply is over %zu bytes", ex->max);
    rc = -1;
  } else if (rc == 0 && ex->cerr[0]) {
    snprintf(err, err_cap, "%s", ex->cerr);
    rc = -1;
  } else if (rc == 0 && ex->coding && !ex->d.stopped &&
             ctui_wm_http_coding_end(ex->coding, err, err_cap) != 0) {
    rc = -1;
  }
  if (rc == 0 && keep) {
    pool_put(u, c);
  } else {
    ctui_wm_conn_close(c);
  }
  return rc;
}

static void ex_free(EX *ex) {
  ctui_wm_http_dec_free(&ex->d);
  ctui_wm_http_coding_free(ex->coding);
  free(ex->body);
  free(ex->hdr);
}

/* h's headers: req's, with a Cookie line when req->cookie gives one for
 * url (malloc'd: cookies_free() gives back what to free). 0, or -1 */
static int cookies(CTUI_WM_HTTP_REQ *h, const CTUI_WM_HTTP_REQ *req,
                   const char *url) {
  h->headers = req->headers;
  if (!req->cookie) {
    return 0;
  }
  char v[NET_COOKIE_MAX];
  size_t vl = req->cookie(req->cookie_ctx, url, v, sizeof v);
  if (!vl) {
    return 0;
  }
  size_t n = 0;
  while (req->headers && req->headers[n]) {
    n++;
  }
  /* the lines, then the Cookie line's text after them: one allocation */
  char **hs = malloc((n + 2) * sizeof *hs + vl + 9);
  if (!hs) {
    return -1;
  }
  char *line = (char *)(hs + n + 2);
  memcpy(line, "Cookie: ", 8);
  memcpy(line + 8, v, vl + 1);
  for (size_t i = 0; i < n; i++) {
    hs[i] = (char *)req->headers[i];
  }
  hs[n] = line;
  hs[n + 1] = NULL;
  h->headers = (const char *const *)hs;
  return 0;
}

/* what cookies() allocated for h, if anything (h's headers back to req's) */
static void *cookies_free(CTUI_WM_HTTP_REQ *h, const CTUI_WM_HTTP_REQ *req) {
  void *p = h->headers != req->headers ? (void *)h->headers : NULL;
  h->headers = req->headers;
  return p;
}

/* req, redirects followed: the body gathered into rep, or handed to sink */
static int request(const CTUI_WM_HTTP_REQ *req, const CTUI_WM_HTTP_SINK *sink,
                   CTUI_WM_HTTP_REPLY *rep, char *err, size_t err_cap) {
  memset(rep, 0, sizeof *rep);
  int timeout = req->timeout_ms > 0 ? req->timeout_ms : NET_TIMEOUT_MS;
  long deadline = ctui_wm_net_now() + timeout;
  CTUI_WM_URL u;
  if (ctui_wm_url_parse(req->url, &u, err, err_cap) != 0) {
    return -1;
  }
  char url[sizeof u.path + sizeof u.host + 32];
  /* this hop's request: req, a GET of it after a POST's redirect, with
   * its cookies */
  CTUI_WM_HTTP_REQ hreq = *req;
  for (int hop = 0;; hop++) {
    if (hop > 0 && ctui_wm_url_format(&u, url, sizeof url) != 0) {
      snprintf(err, err_cap, "the redirect is too long");
      return -1;
    }
    /* a gathered body may come compressed (undone here), unless the
     * caller says what it takes; a stream comes as it is (a download
     * resumed by Range, its progress by Content-Length) */
    int coded = !sink && !ctui_wm_http_req_has(req, "Accept-Encoding");
    char *out = NULL;
    size_t out_len = 0;
    if (cookies(&hreq, req, hop > 0 ? url : req->url) != 0 ||
        ctui_wm_http_format(&hreq, &u, coded, &out, &out_len) != 0) {
      free(cookies_free(&hreq, req));
      snprintf(err, err_cap, "a header with a line break, or out of memory");
      return -1;
    }
    free(cookies_free(&hreq, req));
    EX ex = {.req = &hreq,
             .sink = sink,
             .rep = rep,
             .max = req->max ? req->max : NET_MAX,
             .url = hop > 0 ? url : NULL,
             .coded = coded};
    ctui_wm_http_dec_init(&ex.d);
    ex.d.on_head = ex_head;
    ex.d.on_body = ex_body;
    ex.d.ctx = &ex;
    const char *m = hreq.method ? hreq.method : "GET";
    ex.d.no_body = !strcasecmp(m, "HEAD");
    /* a request that changes something isn't sent twice: never on a kept
     * connection that may turn out closed */
    int reuse = ex.d.no_body || !strcasecmp(m, "GET");
    int rc =
        exchange(&ex, &u, reuse, out, out_len, deadline, timeout, err, err_cap);
    free(out);
    if (rc != 0) {
      ex_free(&ex);
      free(rep->body);
      memset(rep, 0, sizeof *rep);
      return -1;
    }
    if (!ex.redirect) {
      if (!sink) {
        /* body, its NUL, the headers, then where it came from: one
         * allocation */
        size_t hl = ex.d.headers_len;
        size_t ul = hop > 0 ? strlen(url) + 1 : 0;
        char *b = realloc(ex.body, ex.len + hl + 2 + ul);
        if (!b) {
          ex_free(&ex);
          snprintf(err, err_cap, "out of memory");
          return -1;
        }
        b[ex.len] = '\0';
        memcpy(b + ex.len + 1, ex.hdr, hl + 1);
        rep->status = ex.d.status;
        rep->body = b;
        rep->len = ex.len;
        rep->headers = b + ex.len + 1;
        rep->headers_len = hl;
        if (ul) {
          memcpy(b + ex.len + hl + 2, url, ul);
          rep->url = b + ex.len + hl + 2;
        }
        ex.body = NULL;
      }
      ex_free(&ex);
      return 0;
    }
    char loc[sizeof ex.loc];
    memcpy(loc, ex.loc, sizeof loc);
    int ex_again = ex.again;
    ex_free(&ex);
    if (hop == NET_REDIRECTS) {
      snprintf(err, err_cap, "more than %d redirects", NET_REDIRECTS);
      return -1;
    }
    CTUI_WM_URL next;
    if (ctui_wm_url_resolve(&u, loc, &next, err, err_cap) != 0) {
      return -1;
    }
    if (ex_again && u.tls && !next.tls) {
      /* the form's body won't go on in the clear */
      snprintf(err, err_cap, "a form sent on to an http:// page: not sent");
      return -1;
    }
    u = next;
    if (!ex_again && strcasecmp(m, "GET") && strcasecmp(m, "HEAD")) {
      /* a POST redirected: what follows is a GET */
      hreq.method = "GET";
      hreq.body = NULL;
      hreq.body_len = 0;
      hreq.content_type = NULL;
    }
  }
}

int ctui_wm_net_http(const CTUI_WM_HTTP_REQ *req, CTUI_WM_HTTP_REPLY *rep,
                     char *err, size_t err_cap) {
  return request(req, NULL, rep, err, err_cap);
}

int ctui_wm_net_http_stream(const CTUI_WM_HTTP_REQ *req,
                            const CTUI_WM_HTTP_SINK *sink,
                            CTUI_WM_HTTP_REPLY *rep, char *err,
                            size_t err_cap) {
  return request(req, sink, rep, err, err_cap);
}
