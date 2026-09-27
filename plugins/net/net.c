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

/* one exchange with u: the whole reply read into *buf, its length *n */
static int exchange(const CTUI_WM_URL *u, const char *req, size_t req_len,
                    size_t max, long deadline, char **buf, size_t *n, char *err,
                    size_t err_cap) {
  CTUI_WM_CONN *c = ctui_wm_conn_open(u, deadline, err, err_cap);
  if (!c) {
    return -1;
  }
  if (ctui_wm_conn_write(c, req, req_len, err, err_cap) != 0) {
    ctui_wm_conn_close(c);
    return -1;
  }
  /* max for the body, and room for the status line and headers */
  size_t limit = max + 65536, len = 0, cap = 16384;
  char *b = malloc(cap);
  if (!b) {
    snprintf(err, err_cap, "out of memory");
    ctui_wm_conn_close(c);
    return -1;
  }
  for (;;) {
    if (len == cap) {
      if (cap >= limit) {
        snprintf(err, err_cap, "the reply is over %zu bytes", max);
        goto fail;
      }
      size_t ncap = cap * 2 < limit ? cap * 2 : limit;
      char *nb = realloc(b, ncap);
      if (!nb) {
        snprintf(err, err_cap, "out of memory");
        goto fail;
      }
      b = nb;
      cap = ncap;
    }
    ssize_t r = ctui_wm_conn_read(c, b + len, cap - len, err, err_cap);
    if (r < 0) {
      goto fail;
    }
    if (r == 0) {
      break;
    }
    len += (size_t)r;
  }
  ctui_wm_conn_close(c);
  *buf = b;
  *n = len;
  return 0;
fail:
  free(b);
  ctui_wm_conn_close(c);
  return -1;
}

int ctui_wm_net_http(const CTUI_WM_HTTP_REQ *req, CTUI_WM_HTTP_REPLY *rep,
                     char *err, size_t err_cap) {
  memset(rep, 0, sizeof *rep);
  const char *method = req->method ? req->method : "GET";
  long deadline = ctui_wm_net_now() +
                  (req->timeout_ms > 0 ? req->timeout_ms : NET_TIMEOUT_MS);
  size_t max = req->max ? req->max : NET_MAX;
  CTUI_WM_URL u;
  if (ctui_wm_url_parse(req->url, &u, err, err_cap) != 0) {
    return -1;
  }
  for (int hop = 0;; hop++) {
    char *out = NULL, *buf = NULL;
    size_t out_len = 0, n = 0;
    if (ctui_wm_http_format(req, &u, &out, &out_len) != 0) {
      snprintf(err, err_cap, "a header with a line break, or out of memory");
      return -1;
    }
    int ex = exchange(&u, out, out_len, max, deadline, &buf, &n, err, err_cap);
    free(out);
    if (ex != 0) {
      return -1;
    }
    CTUI_WM_HTTP_PARSED p;
    int parsed = ctui_wm_http_parse(buf, n, &p, err, err_cap);
    char loc[sizeof u.path + sizeof u.host + 16];
    int redirect = parsed == 0 && !strcasecmp(method, "GET") &&
                   (p.status == 301 || p.status == 302 || p.status == 303 ||
                    p.status == 307 || p.status == 308) &&
                   ctui_wm_http_header(&p, "Location", loc, sizeof loc);
    free(buf); /* p.headers pointed into it: read above */
    if (parsed != 0) {
      return -1;
    }
    if (p.len > max) {
      free(p.body);
      snprintf(err, err_cap, "the reply is over %zu bytes", max);
      return -1;
    }
    if (!redirect) {
      rep->status = p.status;
      rep->body = p.body;
      rep->len = p.len;
      return 0;
    }
    free(p.body);
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
