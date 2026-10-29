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

int cserve_url_parse(const char *url, CSERVE_URL *u, char *err,
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
    snprintf(err, err_cap,
             hlen ? "the URL's host is too long" : "no host in the URL");
    return -1;
  }
  memcpy(u->host, host, hlen);
  if (port) {
    size_t plen = (size_t)(p + alen - port);
    long v = 0;
    for (size_t i = 0; i < plen; i++) {
      if (port[i] < '0' || port[i] > '9' ||
          (v = v * 10 + (port[i] - '0')) > 65535) {
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

int cserve_url_resolve(const CSERVE_URL *base, const char *loc, CSERVE_URL *u,
                       char *err, size_t err_cap) {
  if (!strncasecmp(loc, "https://", 8) || !strncasecmp(loc, "http://", 7)) {
    return cserve_url_parse(loc, u, err, err_cap);
  }
  char url[sizeof u->path + sizeof u->host + 64];
  const char *scheme = base->tls ? "https" : "http";
  if (loc[0] == '/' && loc[1] == '/') {
    snprintf(url, sizeof url, "%s:%s", scheme, loc);
    return cserve_url_parse(url, u, err, err_cap);
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
  return cserve_url_parse(url, u, err, err_cap);
}

int cserve_url_format(const CSERVE_URL *u, char *out, size_t cap) {
  int v6 = strchr(u->host, ':') != NULL;
  int own = !strcmp(u->port, u->tls ? "443" : "80");
  int n = snprintf(out, cap, "%s://%s%s%s%s%s%s", u->tls ? "https" : "http",
                   v6 ? "[" : "", u->host, v6 ? "]" : "", own ? "" : ":",
                   own ? "" : u->port, u->path);
  return n > 0 && (size_t)n < cap ? 0 : -1;
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

int cserve_http_req_has(const CSERVE_HTTP_REQ *req, const char *name) {
  size_t n = strlen(name);
  for (const char *const *h = req->headers; h && *h; h++) {
    if (!strncasecmp(*h, name, n) && (*h)[n] == ':') {
      return 1;
    }
  }
  return 0;
}

int cserve_http_format(const CSERVE_HTTP_REQ *req, const CSERVE_URL *u,
                       int coded, char **out, size_t *len) {
  const char *method = req->method ? req->method : "GET";
  if (has_crlf(method) || strchr(method, ' ') || has_crlf(req->content_type) ||
      has_crlf(req->agent)) {
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
  out_str(&o, "\r\nUser-Agent: ");
  out_str(&o, req->agent ? req->agent : CSERVE_HTTP_AGENT);
  out_str(&o, "\r\n");
  if (!cserve_http_req_has(req, "Accept")) {
    out_str(&o, "Accept: */*\r\n");
  }
  if (!cserve_http_req_has(req, "Accept-Encoding")) {
    out_str(&o, coded ? "Accept-Encoding: gzip, deflate\r\n"
                      : "Accept-Encoding: identity\r\n");
  }
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

int cserve_http_header(const CSERVE_HTTP_PARSED *p, const char *name, char *val,
                       size_t cap) {
  return header_in(p->headers, p->headers_len, name, val, cap);
}

int cserve_http_reply_header(const CSERVE_HTTP_REPLY *rep, const char *name,
                             char *val, size_t cap) {
  return rep->headers &&
         header_in(rep->headers, rep->headers_len, name, val, cap);
}

/* --- decoding a reply as it arrives --- */

#define HEAD_MAX 65536

enum {
  D_HEAD,
  D_LEN,
  D_CLOSE,
  D_CSIZE,
  D_CDATA,
  D_CCR,
  D_CLF,
  D_TRAIL,
  D_DONE
};

void cserve_http_dec_init(CSERVE_HTTP_DEC *d) {
  memset(d, 0, sizeof *d);
  d->state = D_HEAD;
}

void cserve_http_dec_free(CSERVE_HTTP_DEC *d) {
  free(d->head);
  d->head = NULL;
}

/* whether the comma-separated list v holds token (case-insensitive) */
static int has_token(const char *v, const char *token) {
  size_t n = strlen(token);
  for (const char *p = v; *p;) {
    p += strspn(p, " \t,");
    size_t k = strcspn(p, " \t,");
    if (k == n && !strncasecmp(p, token, n)) {
      return 1;
    }
    p += k;
  }
  return 0;
}

/* HTTP/1.x NNN[ reason] */
static int status_line(const char *p, size_t ll) {
  if (ll < 12 || strncmp(p, "HTTP/1.", 7) || p[7] < '0' || p[7] > '9' ||
      p[8] != ' ' || p[9] < '1' || p[9] > '9' || p[10] < '0' || p[10] > '9' ||
      p[11] < '0' || p[11] > '9' || (ll > 12 && p[12] != ' ')) {
    return -1;
  }
  return (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
}

/* the head is complete: an interim reply dropped (0, more head wanted),
 * or the body's framing chosen (0), or -1 with why in err */
static int head_done(CSERVE_HTTP_DEC *d, char *err, size_t err_cap) {
  if (d->status >= 100 && d->status < 200 && d->status != 101) {
    d->head_len = 0;
    d->status = 0;
    d->head_at = d->fed;
    return 0;
  }
  const char *nl = memchr(d->head, '\n', d->head_len);
  d->headers = nl + 1;
  d->headers_len = (size_t)(d->head + d->head_len - d->headers);
  char v[64];
  /* the connection stays open for the next request: HTTP/1.1's default,
   * HTTP/1.0's only when it says so */
  d->keep = d->head[7] != '0';
  if (header_in(d->headers, d->headers_len, "Connection", v, sizeof v)) {
    if (has_token(v, "close")) {
      d->keep = 0;
    } else if (has_token(v, "keep-alive")) {
      d->keep = 1;
    }
  }
  if (d->no_body || d->status < 200 || d->status == 204 || d->status == 304) {
    d->state = D_DONE;
  } else if (header_in(d->headers, d->headers_len, "Transfer-Encoding", v,
                       sizeof v)) {
    for (char *c = v; *c; c++) {
      *c = (char)(*c >= 'A' && *c <= 'Z' ? *c + 32 : *c);
    }
    d->state = strstr(v, "chunked") ? D_CSIZE : D_CLOSE;
  } else if (header_in(d->headers, d->headers_len, "Content-Length", v,
                       sizeof v)) {
    char *e;
    errno = 0;
    unsigned long long cl = strtoull(v, &e, 10);
    if (v[0] < '0' || v[0] > '9' || *e || errno) {
      snprintf(err, err_cap, "a bad Content-Length");
      return -1;
    }
    d->left = cl;
    d->state = cl ? D_LEN : D_DONE;
  } else {
    d->state = D_CLOSE;
  }
  if (d->on_head && d->on_head(d)) {
    d->stopped = 1;
  }
  return 0;
}

/* one byte of the head (it's small: a byte at a time keeps the line
 * bookkeeping simple): 0, or -1 with why in err */
static int head_byte(CSERVE_HTTP_DEC *d, char c, char *err, size_t err_cap) {
  if (d->head_len == d->head_cap) {
    if (d->head_cap >= HEAD_MAX) {
      snprintf(err, err_cap, "the reply's headers are over %d bytes", HEAD_MAX);
      return -1;
    }
    size_t cap = d->head_cap ? d->head_cap * 2 : 1024;
    char *h = realloc(d->head, cap);
    if (!h) {
      snprintf(err, err_cap, "out of memory");
      return -1;
    }
    d->head = h;
    d->head_cap = cap;
  }
  d->head[d->head_len++] = c;
  d->fed++;
  if (c != '\n') {
    return 0;
  }
  /* a line ended: the one from after the previous '\n' */
  size_t at = d->head_len - 1;
  while (at > 0 && d->head[at - 1] != '\n') {
    at--;
  }
  const char *line = d->head + at;
  size_t ll = line_len(line, d->head + d->head_len - 1);
  if (at == 0) {
    d->status = status_line(line, ll);
    if (d->status < 0) {
      d->status = 0;
      snprintf(err, err_cap, "not an HTTP reply");
      return -1;
    }
    return 0;
  }
  return ll == 0 ? head_done(d, err, err_cap) : 0;
}

/* a chunk's size line (without its LF): 0, or -1 with why in err */
static int chunk_size(CSERVE_HTTP_DEC *d, char *err, size_t err_cap) {
  unsigned long long size = 0;
  size_t i = 0;
  for (; i < d->line_len; i++) {
    char c = d->line[i];
    int v = c >= '0' && c <= '9'   ? c - '0'
            : c >= 'a' && c <= 'f' ? c - 'a' + 10
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                   : -1;
    if (v < 0) {
      break;
    }
    if (size > (~0ULL >> 4)) {
      snprintf(err, err_cap, "a chunk too big");
      return -1;
    }
    size = size * 16 + (unsigned)v;
  }
  /* after the size: an extension (";..."), spaces, the CR */
  char c = i < d->line_len ? d->line[i] : '\0';
  if (i == 0 || (c && c != ';' && c != ' ' && c != '\t' && c != '\r')) {
    snprintf(err, err_cap, "a bad chunk size");
    return -1;
  }
  d->line_len = 0;
  d->left = size;
  /* the last chunk: then its trailers, up to a blank line */
  d->state = size ? D_CDATA : D_TRAIL;
  return 0;
}

/* n bytes of the body to on_body(): 1 if it stopped the reply */
static int deliver(CSERVE_HTTP_DEC *d, const char *p, size_t n) {
  if (n && d->on_body(d, p, n)) {
    d->stopped = 1;
  }
  return d->stopped;
}

int cserve_http_dec_feed(CSERVE_HTTP_DEC *d, const char *buf, size_t n,
                         char *err, size_t err_cap) {
  const char *p = buf, *end = buf + n;
  while (!d->stopped && d->state != D_DONE && p < end) {
    size_t have = (size_t)(end - p), k;
    switch (d->state) {
    case D_HEAD:
      if (head_byte(d, *p++, err, err_cap) != 0) {
        return -1;
      }
      continue;
    case D_LEN:
    case D_CDATA:
      k = have < d->left ? have : (size_t)d->left;
      d->left -= k;
      if (deliver(d, p, k)) {
        return 1;
      }
      p += k;
      if (d->left == 0) {
        d->state = d->state == D_LEN ? D_DONE : D_CCR;
      }
      break;
    case D_CLOSE:
      p = end;
      if (deliver(d, end - have, have)) {
        return 1;
      }
      break;
    case D_CSIZE:
      if (*p == '\n') {
        p++;
        if (chunk_size(d, err, err_cap) != 0) {
          return -1;
        }
      } else {
        /* a long extension: only its start is kept, the size is in it */
        if (d->line_len < sizeof d->line - 1) {
          d->line[d->line_len++] = *p;
        }
        p++;
      }
      break;
    case D_TRAIL:
      /* trailer lines (dropped), up to the blank one: line_len counts
       * what a line has besides its CR */
      if (*p == '\n') {
        if (d->line_len == 0) {
          d->state = D_DONE;
        }
        d->line_len = 0;
      } else if (*p != '\r') {
        d->line_len = 1;
      }
      p++;
      break;
    case D_CCR:
    case D_CLF:
      if (*p == '\r' && d->state == D_CCR) {
        d->state = D_CLF;
      } else if (*p == '\n') {
        d->state = D_CSIZE;
      } else {
        snprintf(err, err_cap, "a chunk without its line end");
        return -1;
      }
      p++;
      break;
    }
    d->fed += (size_t)(p - (end - have));
  }
  return d->stopped || d->state == D_DONE;
}

int cserve_http_dec_end(CSERVE_HTTP_DEC *d, char *err, size_t err_cap) {
  switch (d->state) {
  case D_CLOSE:
  case D_TRAIL: /* the last chunk came: its trailers cut short */
  case D_DONE:
    return 0;
  case D_HEAD:
    snprintf(err, err_cap,
             d->fed == 0  ? "an empty reply"
             : !d->status ? "not an HTTP reply"
                          : "the reply ended inside its headers");
    return -1;
  default:
    snprintf(err, err_cap, "the reply ended inside its body");
    return -1;
  }
}

int cserve_http_dec_reusable(const CSERVE_HTTP_DEC *d) {
  return d->state == D_DONE && !d->stopped && d->keep;
}

static int parse_body(CSERVE_HTTP_DEC *d, const char *buf, size_t n) {
  OUT *o = d->ctx;
  out_add(o, buf, n);
  return o->oom;
}

int cserve_http_parse(const char *buf, size_t n, CSERVE_HTTP_PARSED *out,
                      char *err, size_t err_cap) {
  memset(out, 0, sizeof *out);
  OUT o = {0};
  out_add(&o, "", 0);
  CSERVE_HTTP_DEC d;
  cserve_http_dec_init(&d);
  d.on_body = parse_body;
  d.ctx = &o;
  int r = cserve_http_dec_feed(&d, buf, n, err, err_cap);
  if (r == 0) {
    r = cserve_http_dec_end(&d, err, err_cap) == 0 ? 1 : -1;
  }
  if (r > 0 && o.oom) {
    snprintf(err, err_cap, "out of memory");
    r = -1;
  }
  if (r < 0) {
    free(o.s);
    cserve_http_dec_free(&d);
    return -1;
  }
  out->status = d.status;
  /* the decoder's copy of the head is the same bytes as buf's */
  out->headers = buf + d.head_at + (size_t)(d.headers - d.head);
  out->headers_len = d.headers_len;
  out->body = o.s;
  out->len = o.len;
  cserve_http_dec_free(&d);
  return 0;
}
