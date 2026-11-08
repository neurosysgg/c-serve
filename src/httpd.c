#define _DEFAULT_SOURCE /* strncasecmp() */
#include "httpd.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* RFC 9110's tchar */
static int tchar(unsigned char c) {
  return isalnum(c) || (c && strchr("!#$%&'*+-.^_`|~", c));
}

static int hexval(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  c = (unsigned char)tolower(c);
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static int refuse(int status, char *err, size_t err_cap, const char *why) {
  snprintf(err, err_cap, "%s", why);
  return status;
}

/* whether a Connection header's token list has tok */
static int has_token(const char *list, const char *tok) {
  size_t n = strlen(tok);
  for (const char *p = list; *p;) {
    p += strspn(p, " \t,");
    size_t k = strcspn(p, ",");
    size_t e = k;
    while (e > 0 && (p[e - 1] == ' ' || p[e - 1] == '\t')) {
      e--;
    }
    if (e == n && strncasecmp(p, tok, n) == 0) {
      return 1;
    }
    p += k;
  }
  return 0;
}

static int request_line(char *line, CSERVE_HTTPD_REQ *r, char *err,
                        size_t err_cap) {
  char *sp1 = strchr(line, ' ');
  if (!sp1 || sp1 == line || (size_t)(sp1 - line) >= sizeof r->method) {
    return refuse(sp1 && sp1 != line ? 501 : 400, err, err_cap,
                  "a bad request line");
  }
  for (char *p = line; p < sp1; p++) {
    if (!tchar((unsigned char)*p)) {
      return refuse(400, err, err_cap, "a bad method");
    }
  }
  memcpy(r->method, line, (size_t)(sp1 - line));
  r->method[sp1 - line] = '\0';
  char *target = sp1 + 1;
  char *sp2 = strchr(target, ' ');
  if (!sp2 || sp2 == target) {
    return refuse(400, err, err_cap, "a bad request line");
  }
  if ((size_t)(sp2 - target) >= sizeof r->target) {
    return refuse(414, err, err_cap, "the target is too long");
  }
  for (char *p = target; p < sp2; p++) {
    if ((unsigned char)*p <= ' ' || *p == 0x7f) {
      return refuse(400, err, err_cap, "a control byte in the target");
    }
  }
  memcpy(r->target, target, (size_t)(sp2 - target));
  r->target[sp2 - target] = '\0';
  const char *ver = sp2 + 1;
  if (strncmp(ver, "HTTP/", 5) != 0) {
    return refuse(400, err, err_cap, "not HTTP");
  }
  if (strcmp(ver + 5, "1.1") == 0) {
    r->minor = 1;
  } else if (strcmp(ver + 5, "1.0") == 0) {
    r->minor = 0;
  } else {
    return refuse(505, err, err_cap, "only HTTP/1.x");
  }
  if (r->target[0] != '/') {
    return refuse(400, err, err_cap, "only origin-form targets");
  }
  char *q = strchr(r->target, '?');
  size_t plen = q ? (size_t)(q - r->target) : strlen(r->target);
  r->query = q ? q + 1 : r->target + strlen(r->target);
  size_t o = 0;
  for (size_t i = 0; i < plen; i++) {
    unsigned char c = (unsigned char)r->target[i];
    if (c == '%') {
      int hi = i + 2 < plen ? hexval((unsigned char)r->target[i + 1]) : -1;
      int lo = hi >= 0 ? hexval((unsigned char)r->target[i + 2]) : -1;
      if (lo < 0) {
        return refuse(400, err, err_cap, "a bad %-escape");
      }
      c = (unsigned char)(hi << 4 | lo);
      if (c == 0) {
        return refuse(400, err, err_cap, "a NUL in the path");
      }
      i += 2;
    }
    r->path[o++] = (char)c;
  }
  r->path[o] = '\0';
  return 0;
}

int cserve_httpd_parse(char *buf, CSERVE_HTTPD_REQ *r, char *err,
                       size_t err_cap) {
  memset(r, 0, sizeof *r);
  r->length = -1;
  r->query = "";
  /* lines end in LF (a CR before it dropped); the request line first */
  char *line = buf;
  char *next = strchr(line, '\n');
  if (next) {
    *next++ = '\0';
  }
  size_t l = strlen(line);
  if (l && line[l - 1] == '\r') {
    line[--l] = '\0';
  }
  int st = request_line(line, r, err, err_cap);
  if (st) {
    return st;
  }
  int te = 0;
  while (next && *next) {
    line = next;
    next = strchr(line, '\n');
    if (next) {
      *next++ = '\0';
    }
    l = strlen(line);
    if (l && line[l - 1] == '\r') {
      line[--l] = '\0';
    }
    if (l == 0) {
      break;
    }
    if (line[0] == ' ' || line[0] == '\t') {
      return refuse(400, err, err_cap, "a folded header line");
    }
    char *colon = strchr(line, ':');
    if (!colon || colon == line) {
      return refuse(400, err, err_cap, "a header line without a name");
    }
    for (char *p = line; p < colon; p++) {
      if (!tchar((unsigned char)*p)) {
        return refuse(400, err, err_cap, "a bad header name");
      }
    }
    if (r->n == CSERVE_HTTPD_HEADERS) {
      return refuse(431, err, err_cap, "too many header lines");
    }
    *colon = '\0';
    char *v = colon + 1;
    v += strspn(v, " \t");
    char *e = v + strlen(v);
    while (e > v && (e[-1] == ' ' || e[-1] == '\t')) {
      *--e = '\0';
    }
    for (char *p = v; *p; p++) {
      if (((unsigned char)*p < ' ' && *p != '\t') || *p == 0x7f) {
        return refuse(400, err, err_cap, "a control byte in a header");
      }
    }
    r->h[r->n].name = line;
    r->h[r->n].value = v;
    r->n++;
    if (strcasecmp(line, "Content-Length") == 0) {
      if (!*v || strspn(v, "0123456789") != strlen(v) || strlen(v) > 18) {
        return refuse(400, err, err_cap, "a bad Content-Length");
      }
      long long len = strtoll(v, NULL, 10);
      if (r->length >= 0 && r->length != len) {
        return refuse(400, err, err_cap, "two Content-Lengths");
      }
      r->length = len;
    } else if (strcasecmp(line, "Transfer-Encoding") == 0) {
      te = 1;
    }
  }
  /* both would be a request smuggled past a proxy; a chunked body alone
   * is simply not taken */
  if (te) {
    return refuse(r->length >= 0 ? 400 : 411, err, err_cap,
                  "a Transfer-Encoding (only Content-Length is taken)");
  }
  if (r->minor == 1 && !cserve_httpd_header(r, "Host")) {
    return refuse(400, err, err_cap, "no Host");
  }
  const char *conn = cserve_httpd_header(r, "Connection");
  r->keep_alive = r->minor == 1 ? !(conn && has_token(conn, "close"))
                                : conn && has_token(conn, "keep-alive");
  return 0;
}

int cserve_httpd_frame(CSERVE_HTTPD_FRAME *f, const char *buf, size_t n,
                       char *out, size_t cap, int *status, char *err,
                       size_t err_cap) {
  while (f->pos < n) {
    const char *start = buf + f->pos;
    const char *lf = memchr(start, '\n', n - f->pos);
    /* a line over cap (read_head()'s line reader's limit), decided on
     * its length alone -- whether its end has come yet or not -- so the
     * answer doesn't hang on how the bytes arrived; the first one is not
     * a request at all */
    size_t raw = lf ? (size_t)(lf - start) : n - f->pos;
    if (raw > cap) {
      snprintf(err, err_cap, "a line over %zu bytes", cap);
      *status = f->len == 0 ? 0 : 431;
      return -1;
    }
    if (!lf) {
      return 0;
    }
    size_t k = raw;
    f->pos += k + 1;
    if (k > 0 && start[k - 1] == '\r') {
      k--;
    }
    if (k == 0 && f->lines == 0) {
      if (++f->blanks > 4) {
        snprintf(err, err_cap, "blank lines only");
        *status = 400;
        return -1;
      }
      continue;
    }
    if (k == 0) {
      out[f->len] = '\0';
      return 1;
    }
    if (f->len + k + 2 > cap) {
      snprintf(err, err_cap, "the head is too long");
      *status = 431;
      return -1;
    }
    memcpy(out + f->len, start, k);
    f->len += k;
    out[f->len++] = '\n';
    f->lines++;
  }
  return 0;
}

const char *cserve_httpd_header(const CSERVE_HTTPD_REQ *r, const char *name) {
  for (int i = 0; i < r->n; i++) {
    if (strcasecmp(r->h[i].name, name) == 0) {
      return r->h[i].value;
    }
  }
  return NULL;
}

const char *cserve_httpd_reason(int status) {
  static const struct {
    int status;
    const char *text;
  } T[] = {{200, "OK"},
           {201, "Created"},
           {204, "No Content"},
           {301, "Moved Permanently"},
           {302, "Found"},
           {303, "See Other"},
           {304, "Not Modified"},
           {307, "Temporary Redirect"},
           {308, "Permanent Redirect"},
           {400, "Bad Request"},
           {401, "Unauthorized"},
           {403, "Forbidden"},
           {404, "Not Found"},
           {405, "Method Not Allowed"},
           {408, "Request Timeout"},
           {411, "Length Required"},
           {413, "Content Too Large"},
           {429, "Too Many Requests"},
           {414, "URI Too Long"},
           {431, "Request Header Fields Too Large"},
           {500, "Internal Server Error"},
           {501, "Not Implemented"},
           {503, "Service Unavailable"},
           {505, "HTTP Version Not Supported"}};
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    if (T[i].status == status) {
      return T[i].text;
    }
  }
  return "";
}

void cserve_httpd_text(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       const char *body, size_t len) {
  char *copy = malloc(len + 1);
  if (!copy) {
    rep->status = 500;
    rep->type = "text/plain; charset=utf-8";
    rep->body = (char *)"out of memory\n";
    rep->len = strlen(rep->body);
    rep->owned = 0;
    return;
  }
  memcpy(copy, body, len);
  copy[len] = '\0';
  rep->status = status;
  rep->type = type;
  rep->body = copy;
  rep->len = len;
  rep->owned = 1;
}

void cserve_httpd_take(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       char *body, size_t len) {
  rep->status = status;
  rep->type = type;
  rep->body = body ? body : (char *)"";
  rep->len = body ? len : 0;
  rep->owned = body != NULL;
}

void cserve_httpd_escape(void (*add)(void *ctx, const char *s, size_t n),
                         void *ctx, const char *s) {
  for (const char *p = s; *p;) {
    size_t k = strcspn(p, "&<>\"'");
    add(ctx, p, k);
    p += k;
    if (!*p) {
      break;
    }
    switch (*p++) {
    case '&':
      add(ctx, "&amp;", 5);
      break;
    case '<':
      add(ctx, "&lt;", 4);
      break;
    case '>':
      add(ctx, "&gt;", 4);
      break;
    case '"':
      add(ctx, "&quot;", 6);
      break;
    default:
      add(ctx, "&#39;", 5);
      break;
    }
  }
}

/* --- over a connection --- */

/* the next request's head into buf (cap bytes): its length; 0 when the
 * client closed or went quiet before sending anything (just close); -1
 * with a status to refuse it with in *status */
static long read_head(CSERVE_CONN *c, char *buf, size_t cap, int *status,
                      char *err, size_t err_cap) {
  size_t len = 0;
  int lines = 0, blanks = 0;
  for (;;) {
    const char *line;
    ssize_t n = cserve_conn_line(c, &line, cap, err, err_cap);
    if (n < 0) {
      if (len == 0) {
        return 0;
      }
      *status = strstr(err, "over") ? 431 : 400;
      return -1;
    }
    /* an empty line before the request line is allowed (RFC 9112 2.2) */
    if (n == 0 && lines == 0) {
      if (++blanks > 4) {
        snprintf(err, err_cap, "blank lines only");
        *status = 400;
        return -1;
      }
      continue;
    }
    if (n == 0) {
      buf[len] = '\0';
      return (long)len;
    }
    if (len + (size_t)n + 2 > cap) {
      snprintf(err, err_cap, "the head is too long");
      *status = 431;
      return -1;
    }
    memcpy(buf + len, line, (size_t)n);
    len += (size_t)n;
    buf[len++] = '\n';
    lines++;
  }
}

void cserve_httpd_release(CSERVE_HTTPD_REPLY *rep) {
  if (rep->owned) {
    free(rep->body);
    rep->owned = 0;
  }
  rep->body = NULL;
  rep->len = 0;
  if (rep->pull) {
    rep->pull = NULL;
    if (rep->done) {
      rep->done(rep->pull_ud);
    }
  }
  rep->done = NULL;
  rep->pull_ud = NULL;
}

int cserve_httpd_head(const char *server, const CSERVE_HTTPD_REQ *r,
                      const CSERVE_HTTPD_REPLY *rep, int keep, char *buf,
                      size_t cap, int *chunked, int *body) {
  char length[48];
  int has_body = rep->status >= 200 && rep->status != 204 && rep->status != 304;
  int head_only = r && strcmp(r->method, "HEAD") == 0;
  /* HEAD of a pulled body: no framing at all (none of it follows) and
   * the connection closed after (cserve_httpd_keep()), so a client that
   * reads the reply as a GET's -- curl -X HEAD -- isn't left waiting */
  int sized = rep->pull && rep->stream_length > 0;
  int chunks = rep->pull && !sized && r && r->minor >= 1 && !head_only;
  if (!rep->pull) {
    snprintf(length, sizeof length, "Content-Length: %zu\r\n",
             has_body ? rep->len : 0);
  } else if (sized) {
    snprintf(length, sizeof length, "Content-Length: %lld\r\n",
             has_body ? rep->stream_length : 0);
  } else {
    snprintf(length, sizeof length, "%s",
             chunks && has_body ? "Transfer-Encoding: chunked\r\n" : "");
  }
  int named = server && *server, typed = rep->type && has_body;
  int n = snprintf(buf, cap,
                   "HTTP/1.1 %d %s\r\n%s%s%s"
                   "%s%s%s%sConnection: %s\r\n%s\r\n",
                   rep->status, cserve_httpd_reason(rep->status),
                   named ? "Server: " : "", named ? server : "",
                   named ? "\r\n" : "", length, typed ? "Content-Type: " : "",
                   typed ? rep->type : "", typed ? "\r\n" : "",
                   keep ? "keep-alive" : "close", rep->headers);
  *chunked = chunks && has_body;
  *body = has_body && !head_only;
  return n < 0 || (size_t)n >= cap ? -1 : n;
}

int cserve_httpd_keep(const CSERVE_HTTPD_REQ *r, const CSERVE_HTTPD_REPLY *rep,
                      int more) {
  return r->keep_alive && more &&
         !(rep->pull && rep->stream_length <= 0 &&
           (r->minor < 1 || !strcmp(r->method, "HEAD")));
}

/* the reply's head, then its body: 0, or -1 with why in err. A pulled
 * body's done() runs here (release()), whatever happens to the head. */
static int send_reply(CSERVE_CONN *c, const CSERVE_HTTPD *h,
                      const CSERVE_HTTPD_REQ *r, CSERVE_HTTPD_REPLY *rep,
                      int keep, char *err, size_t err_cap) {
  char head[5120];
  int chunked, body;
  int n = cserve_httpd_head(h->server, r, rep, keep, head, sizeof head,
                            &chunked, &body);
  int ret = 0;
  if (n < 0) {
    snprintf(err, err_cap, "the reply's head is too long");
    ret = -1;
  } else if (cserve_conn_write(c, head, (size_t)n, err, err_cap) != 0) {
    ret = -1;
  }
  if (rep->pull) {
    char *buf = ret == 0 && body ? malloc(65536) : NULL;
    long long sent = 0;
    if (ret == 0 && body && !buf) {
      snprintf(err, err_cap, "out of memory");
      ret = -1;
    }
    while (buf && ret == 0) {
      long got = rep->pull(rep->pull_ud, buf, 65536);
      char size[24];
      int k = chunked && got > 0
                  ? snprintf(size, sizeof size, "%lx\r\n", (unsigned long)got)
                  : 0;
      if (got == 0) {
        break;
      }
      sent += got;
      if (got < 0 || (rep->stream_length > 0 && sent > rep->stream_length)) {
        snprintf(err, err_cap, "the pulled body failed");
        ret = -1;
      } else if ((k > 0 &&
                  cserve_conn_write(c, size, (size_t)k, err, err_cap)) ||
                 cserve_conn_write(c, buf, (size_t)got, err, err_cap) ||
                 (chunked && cserve_conn_write(c, "\r\n", 2, err, err_cap))) {
        ret = -1;
      }
    }
    free(buf);
    if (ret == 0 && body && rep->stream_length > 0 &&
        sent != rep->stream_length) {
      snprintf(err, err_cap, "the pulled body came out short");
      ret = -1;
    }
    if (ret == 0 && chunked) {
      ret = cserve_conn_write(c, "0\r\n\r\n", 5, err, err_cap);
    }
    cserve_httpd_release(rep);
    return ret;
  }
  if (ret == 0 && body && rep->len) {
    return cserve_conn_write(c, rep->body, rep->len, err, err_cap);
  }
  return ret;
}

static void refuse_reply(CSERVE_CONN *c, const CSERVE_HTTPD *h, int status,
                         const char *why) {
  CSERVE_HTTPD_REPLY rep = {0};
  char text[300];
  int n = snprintf(text, sizeof text, "%d %s: %s\n", status,
                   cserve_httpd_reason(status), why);
  rep.status = status;
  rep.type = "text/plain; charset=utf-8";
  rep.body = text;
  rep.len = n > 0 ? (size_t)n : 0;
  char err[200];
  send_reply(c, h, NULL, &rep, 0, err, sizeof err);
}

void cserve_httpd_serve(const CSERVE_HTTPD *h, CSERVE_CONN *c,
                        const char *peer) {
  int idle = h->idle_ms > 0 ? h->idle_ms : 10000;
  int timeout = h->timeout_ms > 0 ? h->timeout_ms : 30000;
  long long body_max = h->body_max > 0 ? h->body_max : 1 << 20;
  int max_req = h->max_requests > 0 ? h->max_requests : 100;
  char *head = malloc(CSERVE_HTTPD_HEAD_MAX);
  CSERVE_HTTPD_REQ *r = malloc(sizeof *r);
  char err[256];
  for (int k = 0; head && r && k < max_req; k++) {
    cserve_conn_deadline(c, cserve_net_now() + (k ? idle : timeout));
    int status = 0;
    long hl =
        read_head(c, head, CSERVE_HTTPD_HEAD_MAX, &status, err, sizeof err);
    if (hl == 0) {
      break;
    }
    cserve_conn_deadline(c, cserve_net_now() + timeout);
    if (hl < 0 || (status = cserve_httpd_parse(head, r, err, sizeof err))) {
      refuse_reply(c, h, status, err);
      break;
    }
    r->peer = peer;
    r->conn = c;
    char *body = NULL;
    if (r->length > body_max) {
      refuse_reply(c, h, 413, "the body is too large");
      break;
    }
    if (r->length > 0) {
      body = malloc((size_t)r->length + 1);
      if (!body ||
          cserve_conn_bytes(c, body, (size_t)r->length, err, sizeof err) != 0) {
        free(body);
        break;
      }
      body[r->length] = '\0';
    }
    CSERVE_HTTPD_REPLY rep = {0};
    h->handler(r, body, &rep, h->ud);
    free(body);
    if (rep.status == 0 || rep.stream) {
      /* a stream waits for news, and only the loop can wait without a
       * thread: here it's a 500 */
      cserve_httpd_release(&rep);
      memset(&rep, 0, sizeof rep);
      cserve_httpd_text(&rep, 500, "text/plain; charset=utf-8", "no answer\n",
                        10);
    }
    int keep = cserve_httpd_keep(r, &rep, k + 1 < max_req);
    int sent = send_reply(c, h, r, &rep, keep, err, sizeof err);
    cserve_httpd_release(&rep);
    if (sent != 0 || !keep) {
      break;
    }
  }
  free(r);
  free(head);
  cserve_conn_close(c);
}
