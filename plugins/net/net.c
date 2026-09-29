/* strcasecmp() is POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "net.h"

#include "conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define NET_REDIRECTS 5
#define NET_TIMEOUT_MS 30000
#define NET_MAX (8u << 20)

/* one exchange's reply, as the decoder hands it over */
typedef struct {
  CTUI_WM_HTTP_DEC d;
  const CTUI_WM_HTTP_REQ *req;
  const CTUI_WM_HTTP_SINK *sink; /* NULL: the body gathered */
  CTUI_WM_HTTP_REPLY *rep;       /* the sink's, filled at the head */
  char *body;                    /* gathered: malloc'd */
  size_t len, cap, max;
  int over, oom;
  char *hdr; /* the head's header lines (malloc'd), for rep */
  int redirect;
  char loc[4096 + 256 + 16];
} EX;

static int ex_head(CTUI_WM_HTTP_DEC *d) {
  EX *ex = d->ctx;
  const char *method = ex->req->method ? ex->req->method : "GET";
  CTUI_WM_HTTP_PARSED p = {.status = d->status,
                           .headers = d->headers,
                           .headers_len = d->headers_len};
  if (!strcasecmp(method, "GET") &&
      (p.status == 301 || p.status == 302 || p.status == 303 ||
       p.status == 307 || p.status == 308) &&
      ctui_wm_http_header(&p, "Location", ex->loc, sizeof ex->loc)) {
    ex->redirect = 1;
    return 1;
  }
  ex->hdr = malloc(d->headers_len + 1);
  if (!ex->hdr) {
    ex->oom = 1;
    return 1;
  }
  memcpy(ex->hdr, d->headers, d->headers_len);
  ex->hdr[d->headers_len] = '\0';
  if (!ex->sink) {
    return 0;
  }
  /* the sink's rep: body "" with the headers after it */
  char *b = malloc(d->headers_len + 2);
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
  return ex->sink->head && ex->sink->head(ex->sink->ctx, ex->rep);
}

static int ex_body(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n) {
  EX *ex = d->ctx;
  if (ex->sink) {
    return ex->sink->body(ex->sink->ctx, buf, n);
  }
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

/* one exchange with u: req sent, the reply fed to ex's decoder until it's
 * complete, stopped or the server closes. A sink's body waits at most
 * idle_ms for each read once the head is in. */
static int exchange(EX *ex, const CTUI_WM_URL *u, const char *req,
                    size_t req_len, long deadline, int idle_ms, char *err,
                    size_t err_cap) {
  CTUI_WM_CONN *c = ctui_wm_conn_open(u, deadline, err, err_cap);
  if (!c) {
    return -1;
  }
  if (ctui_wm_conn_write(c, req, req_len, err, err_cap) != 0) {
    ctui_wm_conn_close(c);
    return -1;
  }
  char buf[16384];
  int rc;
  for (;;) {
    if (ex->sink && ex->rep->body) {
      ctui_wm_conn_deadline(c, ctui_wm_net_now() + idle_ms);
    }
    ssize_t r = ctui_wm_conn_read(c, buf, sizeof buf, err, err_cap);
    if (r < 0) {
      rc = -1;
      break;
    }
    if (r == 0) {
      rc = ctui_wm_http_dec_end(&ex->d, err, err_cap);
      break;
    }
    rc = ctui_wm_http_dec_feed(&ex->d, buf, (size_t)r, err, err_cap);
    if (rc != 0) {
      rc = rc < 0 ? -1 : 0;
      break;
    }
  }
  ctui_wm_conn_close(c);
  if (rc == 0 && ex->oom) {
    snprintf(err, err_cap, "out of memory");
    rc = -1;
  } else if (rc == 0 && ex->over) {
    snprintf(err, err_cap, "the reply is over %zu bytes", ex->max);
    rc = -1;
  }
  return rc;
}

static void ex_free(EX *ex) {
  ctui_wm_http_dec_free(&ex->d);
  free(ex->body);
  free(ex->hdr);
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
  for (int hop = 0;; hop++) {
    char *out = NULL;
    size_t out_len = 0;
    if (ctui_wm_http_format(req, &u, &out, &out_len) != 0) {
      snprintf(err, err_cap, "a header with a line break, or out of memory");
      return -1;
    }
    EX ex = {.req = req,
             .sink = sink,
             .rep = rep,
             .max = req->max ? req->max : NET_MAX};
    ctui_wm_http_dec_init(&ex.d);
    ex.d.on_head = ex_head;
    ex.d.on_body = ex_body;
    ex.d.ctx = &ex;
    int rc = exchange(&ex, &u, out, out_len, deadline, timeout, err, err_cap);
    free(out);
    if (rc != 0) {
      ex_free(&ex);
      free(rep->body);
      memset(rep, 0, sizeof *rep);
      return -1;
    }
    if (!ex.redirect) {
      if (!sink) {
        /* body, its NUL, then the headers: one allocation */
        size_t hl = ex.d.headers_len;
        char *b = realloc(ex.body, ex.len + hl + 2);
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
        ex.body = NULL;
      }
      ex_free(&ex);
      return 0;
    }
    char loc[sizeof ex.loc];
    memcpy(loc, ex.loc, sizeof loc);
    ex_free(&ex);
    if (hop == NET_REDIRECTS) {
      snprintf(err, err_cap, "more than %d redirects", NET_REDIRECTS);
      return -1;
    }
    CTUI_WM_URL next;
    if (ctui_wm_url_resolve(&u, loc, &next, err, err_cap) != 0) {
      return -1;
    }
    u = next;
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
