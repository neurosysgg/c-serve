/* strncasecmp() is POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "http.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* --- URLs --- */

/* what may stand in a URL we send: printable ASCII, no space (the caller
 * percent-encodes the rest) */
static int url_char_ok(unsigned char c) { return c > 0x20 && c < 0x7f; }

int ctui_wm_url_parse(const char *url, CTUI_WM_URL *u, char *err,
                      size_t err_cap) {
  memset(u, 0, sizeof *u);
  const char *p;
  if (!strncasecmp(url, "https://", 8)) {
    u->tls = 1;
    p = url + 8;
  } else if (!strncasecmp(url, "http://", 7)) {
    p = url + 7;
  } else {
    snprintf(err, err_cap, "not an http(s) URL");
    return -1;
  }
  for (const char *c = p; *c; c++) {
    if (!url_char_ok((unsigned char)*c)) {
      snprintf(err, err_cap, "a space or non-ASCII byte in the URL");
      return -1;
    }
  }
  size_t alen = strcspn(p, "/?#");
  const char *host = p, *port = NULL;
  size_t hlen;
  if (memchr(p, '@', alen)) {
    snprintf(err, err_cap, "a user in the URL");
    return -1;
  }
  if (*p == '[') {
    const char *close = memchr(p, ']', alen);
    if (!close) {
      snprintf(err, err_cap, "an unclosed [ in the URL's host");
      return -1;
    }
    host = p + 1;
    hlen = (size_t)(close - host);
    if (close + 1 < p + alen) {
      if (close[1] != ':') {
        snprintf(err, err_cap, "junk after the URL's ]");
        return -1;
      }
      port = close + 2;
    }
  } else {
    const char *colon = memchr(p, ':', alen);
    hlen = colon ? (size_t)(colon - p) : alen;
    port = colon ? colon + 1 : NULL;
  }
  if (hlen == 0 || hlen >= sizeof u->host) {
    snprintf(err, err_cap, hlen ? "the URL's host is too long"
                                : "no host in the URL");
    return -1;
  }
  memcpy(u->host, host, hlen);
  if (port) {
    size_t plen = (size_t)(p + alen - port);
    long v = 0;
    for (size_t i = 0; i < plen; i++) {
      if (port[i] < '0' || port[i] > '9' || (v = v * 10 + (port[i] - '0')) >
                                                 65535) {
        snprintf(err, err_cap, "a bad port in the URL");
        return -1;
      }
    }
    if (plen == 0 || v == 0) {
      snprintf(err, err_cap, "a bad port in the URL");
      return -1;
    }
    snprintf(u->port, sizeof u->port, "%hu", (unsigned short)v);
  } else {
    snprintf(u->port, sizeof u->port, "%s", u->tls ? "443" : "80");
  }
  const char *path = p + alen;
  size_t plen = strcspn(path, "#");
  if (plen + 2 > sizeof u->path) {
    snprintf(err, err_cap, "the URL is too long");
    return -1;
  }
  if (*path != '/') {
    u->path[0] = '/';
    memcpy(u->path + 1, path, plen);
  } else {
    memcpy(u->path, path, plen);
  }
  return 0;
}

int ctui_wm_url_resolve(const CTUI_WM_URL *base, const char *loc,
                        CTUI_WM_URL *u, char *err, size_t err_cap) {
  if (!strncasecmp(loc, "https://", 8) || !strncasecmp(loc, "http://", 7)) {
    return ctui_wm_url_parse(loc, u, err, err_cap);
  }
  char url[sizeof u->path + sizeof u->host + 64];
  const char *scheme = base->tls ? "https" : "http";
  if (loc[0] == '/' && loc[1] == '/') {
    snprintf(url, sizeof url, "%s:%s", scheme, loc);
    return ctui_wm_url_parse(url, u, err, err_cap);
  }
  int n = snprintf(url, sizeof url, "%s://%s%s%s:%s", scheme,
                   strchr(base->host, ':') ? "[" : "", base->host,
                   strchr(base->host, ':') ? "]" : "", base->port);
  size_t at = (size_t)n;
  if (loc[0] != '/') {
    /* relative: from the base path's folder */
    size_t dir = strcspn(base->path, "?");
    while (dir > 0 && base->path[dir - 1] != '/') {
      dir--;
    }
    if (at + dir >= sizeof url) {
      snprintf(err, err_cap, "the redirect is too long");
      return -1;
    }
    memcpy(url + at, base->path, dir);
    at += dir;
  }
  if (at + strlen(loc) >= sizeof url) {
    snprintf(err, err_cap, "the redirect is too long");
    return -1;
  }
  strcpy(url + at, loc);
  return ctui_wm_url_parse(url, u, err, err_cap);
}

/* --- the request --- */

typedef struct {
  char *s;
  size_t len, cap;
  int oom;
} OUT;

static void out_add(OUT *o, const char *s, size_t n) {
  if (o->oom) {
    return;
  }
  if (o->len + n + 1 > o->cap) {
    size_t cap = o->cap ? o->cap : 512;
    while (cap < o->len + n + 1) {
      cap *= 2;
    }
    char *ns = realloc(o->s, cap);
    if (!ns) {
      o->oom = 1;
      return;
    }
    o->s = ns;
    o->cap = cap;
  }
  memcpy(o->s + o->len, s, n);
  o->len += n;
  o->s[o->len] = '\0';
}

static void out_str(OUT *o, const char *s) { out_add(o, s, strlen(s)); }

static int has_crlf(const char *s) { return s && strpbrk(s, "\r\n"); }

int ctui_wm_http_format(const CTUI_WM_HTTP_REQ *req, const CTUI_WM_URL *u,
                        char **out, size_t *len) {
  const char *method = req->method ? req->method : "GET";
  if (has_crlf(method) || strchr(method, ' ') || has_crlf(req->content_type)) {
    return -1;
  }
  for (const char *const *h = req->headers; h && *h; h++) {
    if (has_crlf(*h)) {
      return -1;
    }
  }
  OUT o = {0};
  out_str(&o, method);
  out_str(&o, " ");
  out_str(&o, u->path);
  out_str(&o, " HTTP/1.1\r\nHost: ");
  int v6 = strchr(u->host, ':') != NULL;
  out_str(&o, v6 ? "[" : "");
  out_str(&o, u->host);
  out_str(&o, v6 ? "]" : "");
  if (strcmp(u->port, u->tls ? "443" : "80")) {
    out_str(&o, ":");
    out_str(&o, u->port);
  }
  out_str(&o, "\r\nUser-Agent: ctui-wm\r\nAccept: */*\r\n"
              "Accept-Encoding: identity\r\nConnection: close\r\n");
  for (const char *const *h = req->headers; h && *h; h++) {
    out_str(&o, *h);
    out_str(&o, "\r\n");
  }
  if (req->body || strcmp(method, "GET")) {
    char cl[64];
    if (req->content_type) {
      out_str(&o, "Content-Type: ");
      out_str(&o, req->content_type);
      out_str(&o, "\r\n");
    }
    snprintf(cl, sizeof cl, "Content-Length: %zu\r\n",
             req->body ? req->body_len : 0);
    out_str(&o, cl);
  }
  out_str(&o, "\r\n");
  if (req->body) {
    out_add(&o, req->body, req->body_len);
  }
  if (o.oom) {
    free(o.s);
    return -1;
  }
  *out = o.s;
  *len = o.len;
  return 0;
}

/* --- the reply --- */

/* the end of the line starting at p (its '\n', CR before it or not), or
 * NULL if there's none before end */
static const char *line_end(const char *p, const char *end) {
  return memchr(p, '\n', (size_t)(end - p));
}

/* the length of the line p..nl without its CR */
static size_t line_len(const char *p, const char *nl) {
  size_t n = (size_t)(nl - p);
  return n && p[n - 1] == '\r' ? n - 1 : n;
}

static int header_in(const char *h, size_t hlen, const char *name, char *val,
                     size_t cap) {
  size_t nlen = strlen(name);
  const char *p = h, *end = h + hlen;
  while (p < end) {
    const char *nl = line_end(p, end);
    const char *le = nl ? nl : end;
    size_t n = nl ? line_len(p, nl) : (size_t)(end - p);
    if (n > nlen && p[nlen] == ':' && !strncasecmp(p, name, nlen)) {
      const char *v = p + nlen + 1, *ve = p + n;
      while (v < ve && (*v == ' ' || *v == '\t')) {
        v++;
      }
      while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) {
        ve--;
      }
      if ((size_t)(ve - v) >= cap) {
        return 0;
      }
      memcpy(val, v, (size_t)(ve - v));
      val[ve - v] = '\0';
      return 1;
    }
    p = le + 1;
  }
  return 0;
}

int ctui_wm_http_header(const CTUI_WM_HTTP_PARSED *p, const char *name,
                        char *val, size_t cap) {
  return header_in(p->headers, p->headers_len, name, val, cap);
}

/* a chunked body from p..end, decoded into *out */
static int dechunk(const char *p, const char *end, char **out, size_t *len,
                   char *err, size_t err_cap) {
  OUT o = {0};
  out_add(&o, "", 0);
  for (;;) {
    const char *nl = line_end(p, end);
    if (!nl) {
      break;
    }
    size_t size = 0;
    const char *c = p;
    int digits = 0;
    for (; c < nl; c++, digits++) {
      int d = *c >= '0' && *c <= '9'   ? *c - '0'
              : *c >= 'a' && *c <= 'f' ? *c - 'a' + 10
              : *c >= 'A' && *c <= 'F' ? *c - 'A' + 10
                                       : -1;
      if (d < 0) {
        break;
      }
      if (size > (((size_t)-1) >> 4)) {
        free(o.s);
        snprintf(err, err_cap, "a chunk too big");
        return -1;
      }
      size = size * 16 + (size_t)d;
    }
    /* after the size: an extension (";..."), spaces, the CR */
    if (!digits || (c < nl && *c != ';' && *c != ' ' && *c != '\t' &&
                    *c != '\r')) {
      free(o.s);
      snprintf(err, err_cap, "a bad chunk size");
      return -1;
    }
    p = nl + 1;
    if (size == 0) {
      /* the last chunk (trailers after it ignored) */
      if (o.oom) {
        free(o.s);
        snprintf(err, err_cap, "out of memory");
        return -1;
      }
      *out = o.s;
      *len = o.len;
      return 0;
    }
    if (size > (size_t)(end - p)) {
      break;
    }
    out_add(&o, p, size);
    p += size;
    /* the chunk's CRLF */
    if (p < end && *p == '\r') {
      p++;
    }
    if (p < end && *p == '\n') {
      p++;
    } else {
      break;
    }
  }
  free(o.s);
  snprintf(err, err_cap, "the reply ended inside its body");
  return -1;
}

int ctui_wm_http_parse(const char *buf, size_t n, CTUI_WM_HTTP_PARSED *out,
                       char *err, size_t err_cap) {
  memset(out, 0, sizeof *out);
  const char *p = buf, *end = buf + n;
  for (;;) {
    const char *nl = line_end(p, end);
    size_t ll = nl ? line_len(p, nl) : 0;
    /* HTTP/1.x NNN[ reason] */
    if (!nl || ll < 12 || strncmp(p, "HTTP/1.", 7) || p[7] < '0' ||
        p[7] > '9' || p[8] != ' ' ||
        p[9] < '1' || p[9] > '9' || p[10] < '0' || p[10] > '9' ||
        p[11] < '0' || p[11] > '9' || (ll > 12 && p[12] != ' ')) {
      snprintf(err, err_cap, n ? "not an HTTP reply" : "an empty reply");
      return -1;
    }
    out->status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
    p = nl + 1;
    /* the headers, up to the blank line */
    const char *h = p;
    for (;;) {
      nl = line_end(p, end);
      if (!nl) {
        snprintf(err, err_cap, "the reply ended inside its headers");
        return -1;
      }
      int blank = line_len(p, nl) == 0;
      p = nl + 1;
      if (blank) {
        break;
      }
    }
    out->headers = h;
    out->headers_len = (size_t)(p - h);
    /* an interim reply (100 Continue, ...): the real one follows */
    if (out->status >= 100 && out->status < 200 && out->status != 101) {
      continue;
    }
    break;
  }
  if (out->status < 200 || out->status == 204 || out->status == 304) {
    out->body = calloc(1, 1);
    if (!out->body) {
      snprintf(err, err_cap, "out of memory");
      return -1;
    }
    return 0;
  }
  char v[64];
  size_t have = (size_t)(end - p), take = have;
  if (header_in(out->headers, out->headers_len, "Transfer-Encoding", v,
                sizeof v)) {
    for (char *c = v; *c; c++) {
      *c = (char)(*c >= 'A' && *c <= 'Z' ? *c + 32 : *c);
    }
    if (strstr(v, "chunked")) {
      return dechunk(p, end, &out->body, &out->len, err, err_cap);
    }
  } else if (header_in(out->headers, out->headers_len, "Content-Length", v,
                       sizeof v)) {
    char *e;
    errno = 0;
    unsigned long long cl = strtoull(v, &e, 10);
    if (v[0] < '0' || v[0] > '9' || *e || errno) {
      snprintf(err, err_cap, "a bad Content-Length");
      return -1;
    }
    if (cl > have) {
      snprintf(err, err_cap, "the reply ended inside its body");
      return -1;
    }
    take = (size_t)cl;
  }
  out->body = malloc(take + 1);
  if (!out->body) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  memcpy(out->body, p, take);
  out->body[take] = '\0';
  out->len = take;
  return 0;
}
