/* plugins/net: URLs, the request, replies (Content-Length, chunked, to the
 * end, interim 1xx, cut off; whole and a byte at a time), then whole
 * exchanges over plain HTTP with a server forked on 127.0.0.1 -- a
 * redirect, a chunked reply, a POST, a server that never answers (the
 * deadline), one too big, the reply's headers -- and streamed ones (split
 * chunks, an endless body, a cut one, one that stalls); gzip'd and
 * deflated bodies undone, connections kept between requests. TLS itself runs
 * live only (HISTORY.md, session 77: open-meteo, badssl.com's bad
 * certificates refused); here only its start from many threads at once
 * (the CA bundle, ClientHello key shares: ctui-mail's parallel checks
 * crashed there). The server side: request heads parsed and refused,
 * then listen.c + httpd.c answering our own client, plain and over TLS
 * (tests/data/pki: a test CA, a localhost certificate to 2126; the
 * client trusts that CA through SSL_CERT_FILE, set before any TLS). */
#define _POSIX_C_SOURCE 200809L

#include "coding.h"
#include "conn.h"
#include "http.h"
#include "httpd.h"
#include "listen.h"
#include "net.h"
#include "tls.h"

#include "ctui.h"
#include "ctui_test.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

static char g_err[256];

/* s[0..n) compressed: wbits 31 gzip, 15 zlib, -15 raw deflate (malloc'd,
 * its length in *len) */
static char *squeeze(const char *s, size_t n, int wbits, size_t *len) {
  z_stream z = {0};
  deflateInit2(&z, 9, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY);
  uLong cap = deflateBound(&z, (uLong)n);
  char *out = malloc(cap);
  z.next_in = (Bytef *)(uintptr_t)s;
  z.avail_in = (uInt)n;
  z.next_out = (Bytef *)out;
  z.avail_out = (uInt)cap;
  deflate(&z, Z_FINISH);
  *len = z.total_out;
  deflateEnd(&z);
  return out;
}

/* 1000 bytes that compress well */
static const char *text(void) {
  static char t[1001];
  if (!t[0]) {
    for (int i = 0; i < 50; i++) {
      memcpy(t + i * 20, "the quick brown fox ", 20);
    }
  }
  return t;
}

static int parse(const char *s, CTUI_WM_HTTP_PARSED *p) {
  return ctui_wm_http_parse(s, strlen(s), p, g_err, sizeof g_err);
}

static void test_urls(void) {
  CTUI_WM_URL u;
  CTUI_TEST_ASSERT(ctui_wm_url_parse("https://api.open-meteo.com/v1/forecast"
                                     "?latitude=1&x=%20#frag",
                                     &u, g_err, sizeof g_err) == 0 &&
                       u.tls && !strcmp(u.host, "api.open-meteo.com") &&
                       !strcmp(u.port, "443") &&
                       !strcmp(u.path, "/v1/forecast?latitude=1&x=%20"),
                   "https URL: host, port 443, path with the query, no "
                   "fragment");
  CTUI_TEST_ASSERT(
      ctui_wm_url_parse("HTTP://h:8080?q=1", &u, g_err, sizeof g_err) == 0 &&
          !u.tls && !strcmp(u.port, "8080") && !strcmp(u.path, "/?q=1"),
      "http URL: its port, a query without a path gets '/'");
  CTUI_TEST_ASSERT(
      ctui_wm_url_parse("http://[::1]:81/x", &u, g_err, sizeof g_err) == 0 &&
          !strcmp(u.host, "::1") && !strcmp(u.port, "81"),
      "an IPv6 literal without its brackets");
  const char *bad[] = {
      "ftp://h/",     "https://u:pw@h/",  "https://h/a b",
      "https://h:0/", "https://h:70000/", "https:///x",
      "https://h:/",  "https://[::1/",    "https://h/\xc3\xa4"};
  for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
    g_err[0] = '\0';
    CTUI_TEST_ASSERT(ctui_wm_url_parse(bad[i], &u, g_err, sizeof g_err) != 0 &&
                         g_err[0],
                     "a bad URL refused, with why");
  }

  CTUI_WM_URL base, r;
  ctui_wm_url_parse("https://a.example:444/dir/page?x=1", &base, g_err,
                    sizeof g_err);
  CTUI_TEST_ASSERT(
      ctui_wm_url_resolve(&base, "http://b/", &r, g_err, sizeof g_err) == 0 &&
          !r.tls && !strcmp(r.host, "b"),
      "an absolute Location");
  CTUI_TEST_ASSERT(
      ctui_wm_url_resolve(&base, "//c/p", &r, g_err, sizeof g_err) == 0 &&
          r.tls && !strcmp(r.host, "c") && !strcmp(r.path, "/p"),
      "a scheme-relative Location keeps https");
  CTUI_TEST_ASSERT(
      ctui_wm_url_resolve(&base, "/top?y", &r, g_err, sizeof g_err) == 0 &&
          !strcmp(r.host, "a.example") && !strcmp(r.port, "444") &&
          !strcmp(r.path, "/top?y"),
      "an absolute path: same host and port");
  CTUI_TEST_ASSERT(
      ctui_wm_url_resolve(&base, "other", &r, g_err, sizeof g_err) == 0 &&
          !strcmp(r.path, "/dir/other"),
      "a relative path: from the page's folder");
}

static void test_format(void) {
  CTUI_WM_URL u;
  char *out;
  size_t len;
  ctui_wm_url_parse("https://h.example/p?q", &u, g_err, sizeof g_err);
  CTUI_WM_HTTP_REQ get = {.url = "unused"};
  CTUI_TEST_ASSERT(
      ctui_wm_http_format(&get, &u, 1, &out, &len) == 0 &&
          !strncmp(out, "GET /p?q HTTP/1.1\r\nHost: h.example\r\n", 36) &&
          strstr(out, "Accept-Encoding: gzip, deflate\r\n") &&
          strstr(out, "User-Agent: ctui-wm\r\n") &&
          !strstr(out, "Connection:") && !strstr(out, "Content-Length") &&
          len > 4 && !strcmp(out + len - 4, "\r\n\r\n"),
      "a GET: Host without the default port, gzip offered, our own agent, "
      "kept alive, no body");
  free(out);
  out = NULL;

  ctui_wm_url_parse("http://h:8080/t", &u, g_err, sizeof g_err);
  const char *hdrs[] = {"Authorization: Bearer x", NULL};
  CTUI_WM_HTTP_REQ post = {.method = "POST",
                           .content_type = "application/x-www-form-urlencoded",
                           .body = "a=1&b=2",
                           .body_len = 7,
                           .headers = hdrs};
  CTUI_TEST_ASSERT(
      ctui_wm_http_format(&post, &u, 0, &out, &len) == 0 &&
          strstr(out, "Host: h:8080\r\n") &&
          strstr(out, "Authorization: Bearer x\r\n") &&
          strstr(out, "Content-Type: application/x-www-form-urlencoded\r\n") &&
          strstr(out, "Content-Length: 7\r\n") &&
          strstr(out, "Accept-Encoding: identity\r\n") &&
          !strcmp(out + len - 11, "\r\n\r\na=1&b=2"),
      "a POST: the port in Host, extra headers, its type, length and body");
  free(out);
  out = NULL;

  const char *own[] = {"accept-encoding: br", NULL};
  CTUI_WM_HTTP_REQ mine = {.headers = own};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&mine, &u, 1, &out, &len) == 0 &&
                       strstr(out, "accept-encoding: br\r\n") &&
                       !strstr(out, "Accept-Encoding"),
                   "the caller's own Accept-Encoding says it alone");
  free(out);
  out = NULL;
  const char *acc[] = {"Accept: text/css", NULL};
  CTUI_WM_HTTP_REQ mine_acc = {.headers = acc};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&mine_acc, &u, 1, &out, &len) == 0 &&
                       strstr(out, "Accept: text/css\r\n") &&
                       !strstr(out, "Accept: */*"),
                   "the caller's own Accept says it alone");
  free(out);
  out = NULL;

  CTUI_WM_HTTP_REQ as = {.agent = CTUI_WM_HTTP_BROWSER};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&as, &u, 0, &out, &len) == 0 &&
                       strstr(out, "\r\nUser-Agent: Mozilla/5.0 (X11; Linux "
                                   "x86_64; rv:") &&
                       !strstr(out, "ctui-wm"),
                   "a browser's agent said instead of ours");
  free(out);
  out = NULL;
  CTUI_WM_HTTP_REQ bad_as = {.agent = "x\r\nY: b"};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&bad_as, &u, 0, &out, &len) != 0,
                   "an agent with a line break in it refused");

  const char *evil[] = {"X: a\r\nY: b", NULL};
  CTUI_WM_HTTP_REQ inj = {.headers = evil};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&inj, &u, 0, &out, &len) != 0,
                   "a header with a line break in it refused");
}

static void test_replies(void) {
  CTUI_WM_HTTP_PARSED p;
  char v[64];
  CTUI_TEST_ASSERT(parse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         "content-length: 5\r\n\r\nhelloEXTRA",
                         &p) == 0 &&
                       p.status == 200 && p.len == 5 &&
                       !strcmp(p.body, "hello"),
                   "Content-Length: that many bytes");
  CTUI_TEST_ASSERT(ctui_wm_http_header(&p, "CONTENT-TYPE", v, sizeof v) &&
                       !strcmp(v, "text/plain") &&
                       !ctui_wm_http_header(&p, "Location", v, sizeof v),
                   "headers by name, any case");
  free(p.body);

  CTUI_TEST_ASSERT(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
                         "4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\n"
                         "chunks.\r\n0\r\nTrailer: x\r\n\r\n",
                         &p) == 0 &&
                       p.len == 23 &&
                       !strcmp(p.body, "Wikipedia in\r\n\r\nchunks."),
                   "chunked: decoded, extensions and trailers skipped");
  free(p.body);

  CTUI_TEST_ASSERT(parse("HTTP/1.0 200 OK\nServer: old\n\nto the end", &p) ==
                           0 &&
                       !strcmp(p.body, "to the end"),
                   "no length: to the end (and bare LF lines)");
  free(p.body);

  CTUI_TEST_ASSERT(parse("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n"
                         "Content-Length: 2\r\n\r\nok",
                         &p) == 0 &&
                       p.status == 201 && !strcmp(p.body, "ok"),
                   "an interim 100 skipped");
  free(p.body);

  CTUI_TEST_ASSERT(
      parse("HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n", &p) == 0 &&
          p.len == 0 && p.body && !p.body[0],
      "204: no body whatever it says");
  free(p.body);

  const char *bad[] = {
      "",
      "SSH-2.0-OpenSSH\r\n",
      "HTTP/1.1 20 OK\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
      "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nx",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
      ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
       "ffffffffffffffffff\r\n"),
  };
  for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
    g_err[0] = '\0';
    CTUI_TEST_ASSERT(parse(bad[i], &p) != 0 && g_err[0] && !p.body,
                     "a bad or cut-off reply refused, with why");
  }
}

/* --- the decoder fed in pieces --- */

typedef struct {
  char body[256];
  size_t len;
  int heads, stop_at_head;
  size_t stop_after;
} SINKED;

static int dec_head(CTUI_WM_HTTP_DEC *d) {
  SINKED *s = d->ctx;
  s->heads++;
  return s->stop_at_head;
}

static int dec_body(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n) {
  SINKED *s = d->ctx;
  if (s->len + n < sizeof s->body) {
    memcpy(s->body + s->len, buf, n);
  }
  s->len += n;
  s->body[s->len < sizeof s->body ? s->len : 0] = '\0';
  return s->stop_after && s->len >= s->stop_after;
}

/* reply fed a byte at a time: 1 complete, -1 refused */
static int dec_bytes(const char *reply, SINKED *s, CTUI_WM_HTTP_DEC *d) {
  memset(s, 0, sizeof *s);
  ctui_wm_http_dec_init(d);
  d->on_head = dec_head;
  d->on_body = dec_body;
  d->ctx = s;
  size_t n = strlen(reply);
  for (size_t i = 0; i < n; i++) {
    int r = ctui_wm_http_dec_feed(d, reply + i, 1, g_err, sizeof g_err);
    if (r != 0) {
      return r;
    }
  }
  return ctui_wm_http_dec_end(d, g_err, sizeof g_err) == 0 ? 1 : -1;
}

static void test_decoder(void) {
  const char *good[] = {
      "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhelloEXTRA",
      ("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
       "4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\n"
       "chunks.\r\n0\r\nTrailer: x\r\n\r\n"),
      "HTTP/1.0 200 OK\nServer: old\n\nto the end",
      ("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n"
       "Content-Length: 2\r\n\r\nok"),
      "HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n",
  };
  for (size_t i = 0; i < sizeof good / sizeof *good; i++) {
    CTUI_WM_HTTP_PARSED p;
    SINKED s;
    CTUI_WM_HTTP_DEC d;
    int whole = parse(good[i], &p);
    int bytes = dec_bytes(good[i], &s, &d);
    CTUI_TEST_ASSERT(whole == 0 && bytes == 1 && d.status == p.status &&
                         s.heads == 1 && s.len == p.len &&
                         !memcmp(s.body, p.body, p.len) &&
                         d.headers_len == p.headers_len &&
                         !memcmp(d.headers, p.headers, p.headers_len),
                     "a byte at a time decodes as the whole reply (%zu)", i);
    free(p.body);
    ctui_wm_http_dec_free(&d);
  }

  const char *bad[] = {
      "",
      "SSH-2.0-OpenSSH\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX",
  };
  for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
    SINKED s;
    CTUI_WM_HTTP_DEC d;
    g_err[0] = '\0';
    CTUI_TEST_ASSERT(dec_bytes(bad[i], &s, &d) < 0 && g_err[0],
                     "a bad reply refused a byte at a time too (%zu)", i);
    ctui_wm_http_dec_free(&d);
  }

  SINKED s = {.stop_after = 3};
  CTUI_WM_HTTP_DEC d;
  ctui_wm_http_dec_init(&d);
  d.on_body = dec_body;
  d.ctx = &s;
  const char *r = "HTTP/1.1 200 OK\r\n\r\nabcdef";
  CTUI_TEST_ASSERT(
      ctui_wm_http_dec_feed(&d, r, strlen(r), g_err, sizeof g_err) == 1 &&
          d.stopped && !strcmp(s.body, "abcdef"),
      "on_body stops the reply (the piece it had is all given)");
  ctui_wm_http_dec_free(&d);

  memset(&s, 0, sizeof s);
  s.stop_at_head = 1;
  ctui_wm_http_dec_init(&d);
  d.on_head = dec_head;
  d.on_body = dec_body;
  d.ctx = &s;
  CTUI_TEST_ASSERT(
      ctui_wm_http_dec_feed(&d, r, strlen(r), g_err, sizeof g_err) == 1 &&
          d.stopped && s.heads == 1 && s.len == 0,
      "on_head stops it before any of the body");
  ctui_wm_http_dec_free(&d);
}

/* --- Content-Encoding undone --- */

typedef struct {
  char *buf;
  size_t len;
  size_t stop_after;
} UNZ;

static int unz_out(void *ctx, const char *buf, size_t n) {
  UNZ *u = ctx;
  char *b = realloc(u->buf, u->len + n + 1);
  if (!b) {
    return 1;
  }
  u->buf = b;
  memcpy(u->buf + u->len, buf, n);
  u->len += n;
  u->buf[u->len] = '\0';
  return u->stop_after && u->len >= u->stop_after;
}

/* data[0..n) under coding fed step bytes at a time: 0 decoded into u, 1
 * stopped, -1 refused (g_err says why) */
static int unz(const char *coding, const char *data, size_t n, size_t step,
               UNZ *u) {
  CTUI_WM_HTTP_CODING *c;
  if (ctui_wm_http_coding_open(coding, &c, g_err, sizeof g_err) != 1) {
    return -1;
  }
  int r = 0;
  for (size_t at = 0; at < n && r == 0; at += step) {
    size_t k = n - at < step ? n - at : step;
    r = ctui_wm_http_coding_feed(c, data + at, k, unz_out, u, g_err,
                                 sizeof g_err);
  }
  if (r == 0) {
    r = ctui_wm_http_coding_end(c, g_err, sizeof g_err);
  }
  ctui_wm_http_coding_free(c);
  return r;
}

static void test_coding(void) {
  const char *t = text();
  size_t tl = strlen(t);
  struct {
    const char *coding;
    int wbits;
  } kinds[] = {{"gzip", 31},
               {" X-GZIP ", 31},
               {"deflate", 15},
               {"Deflate", -15},
               {"gzip", 15}};
  for (size_t i = 0; i < sizeof kinds / sizeof *kinds; i++) {
    size_t zl;
    char *z = squeeze(t, tl, kinds[i].wbits, &zl);
    UNZ whole = {0}, bytes = {0};
    int a = unz(kinds[i].coding, z, zl, zl, &whole);
    int b = unz(kinds[i].coding, z, zl, 1, &bytes);
    CTUI_TEST_ASSERT(a == 0 && b == 0 && zl < tl / 4 && whole.len == tl &&
                         !strcmp(whole.buf, t) && bytes.len == tl &&
                         !strcmp(bytes.buf, t),
                     "%s (%d) undone, whole and a byte at a time (%s)",
                     kinds[i].coding, kinds[i].wbits, a || b ? g_err : "");
    free(whole.buf);
    free(bytes.buf);
    free(z);
  }

  CTUI_WM_HTTP_CODING *c = NULL;
  CTUI_TEST_ASSERT(
      ctui_wm_http_coding_open("identity", &c, g_err, sizeof g_err) == 0 &&
          !c && ctui_wm_http_coding_open("", &c, g_err, sizeof g_err) == 0,
      "identity (or nothing) needs nothing undone");
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(
      ctui_wm_http_coding_open("br", &c, g_err, sizeof g_err) < 0 &&
          strstr(g_err, "br") &&
          ctui_wm_http_coding_open("gzip, gzip", &c, g_err, sizeof g_err) < 0 &&
          !c,
      "a coding we don't read refused, named; two of them too");

  size_t zl;
  char *z = squeeze(t, tl, 31, &zl);
  UNZ u = {0};
  CTUI_TEST_ASSERT(unz("gzip", z, zl - 3, 7, &u) < 0 &&
                       strstr(g_err, "ended early"),
                   "a gzip stream cut short: refused at the end");
  free(u.buf);
  memset(&u, 0, sizeof u);
  char *more = malloc(zl + 9);
  memcpy(more, z, zl);
  memcpy(more + zl, "trailing!", 9);
  CTUI_TEST_ASSERT(unz("gzip", more, zl + 9, 5, &u) == 0 && u.len == tl,
                   "what follows the stream's end dropped");
  free(u.buf);
  free(more);
  memset(&u, 0, sizeof u);
  u.stop_after = 100;
  CTUI_TEST_ASSERT(unz("gzip", z, zl, zl, &u) == 1 && u.len >= 100,
                   "the output's taker stops it");
  free(u.buf);
  free(z);
  memset(&u, 0, sizeof u);
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(unz("gzip", "not gzip at all", 15, 4, &u) < 0 &&
                       strstr(g_err, "broken") && !u.len,
                   "not gzip: refused as broken");
  CTUI_TEST_ASSERT(unz("deflate", "", 0, 1, &u) == 0 && !u.len,
                   "an empty body labelled compressed is empty");
  free(u.buf);
}

/* --- whether the connection can take the next request --- */

static void test_reuse(void) {
  struct {
    const char *reply;
    int reusable;
    const char *what;
  } cases[] = {
      {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 1,
       "HTTP/1.1 by its length"},
      {"HTTP/1.1 200 OK\r\nConnection: Upgrade, close\r\n"
       "Content-Length: 2\r\n\r\nok",
       0, "Connection: close"},
      {"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", 0,
       "HTTP/1.0 without keep-alive"},
      {"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\n"
       "Content-Length: 2\r\n\r\nok",
       1, "HTTP/1.0 with keep-alive"},
      {"HTTP/1.1 200 OK\r\n\r\nto the end", 0, "a body to the end"},
      {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
       "2\r\nok\r\n0\r\nA: 1\r\nB: 2\r\n\r\n",
       1, "chunked, its trailers read"},
      {"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n", 1,
       "a 304, no body whatever its length"},
  };
  for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
    SINKED s;
    CTUI_WM_HTTP_DEC d;
    int r = dec_bytes(cases[i].reply, &s, &d);
    CTUI_TEST_ASSERT(r == 1 &&
                         ctui_wm_http_dec_reusable(&d) == cases[i].reusable &&
                         d.fed == strlen(cases[i].reply),
                     "kept for the next request or not: %s", cases[i].what);
    ctui_wm_http_dec_free(&d);
  }

  SINKED s = {0};
  CTUI_WM_HTTP_DEC d;
  ctui_wm_http_dec_init(&d);
  d.on_body = dec_body;
  d.ctx = &s;
  d.no_body = 1;
  const char *h = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
  CTUI_TEST_ASSERT(
      ctui_wm_http_dec_feed(&d, h, strlen(h), g_err, sizeof g_err) == 1 &&
          ctui_wm_http_dec_reusable(&d) && s.len == 0,
      "a HEAD's reply ends with its headers");
  ctui_wm_http_dec_free(&d);

  memset(&s, 0, sizeof s);
  ctui_wm_http_dec_init(&d);
  d.on_body = dec_body;
  d.ctx = &s;
  const char *t = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                  "2\r\nok\r\n0\r\n";
  CTUI_TEST_ASSERT(
      ctui_wm_http_dec_feed(&d, t, strlen(t), g_err, sizeof g_err) == 0 &&
          ctui_wm_http_dec_end(&d, g_err, sizeof g_err) == 0 &&
          !ctui_wm_http_dec_reusable(&d) && !strcmp(s.body, "ok"),
      "the last chunk, then the server closed: whole, not kept");
  ctui_wm_http_dec_free(&d);
}

/* --- a server on 127.0.0.1, one reply per request by its path --- */

/* the /gz... replies: compressed if gzip was offered, else "not offered" */
static void gz_reply(int c, const char *req) {
  const char *t = text();
  if (!strstr(req, "Accept-Encoding: gzip")) {
    const char *r = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"
                    "not offered";
    send(c, r, strlen(r), MSG_NOSIGNAL);
    return;
  }
  char head[256];
  size_t zl = 0;
  char *z = NULL;
  const char *coding = "gzip";
  int chunked = 0;
  if (!strncmp(req, "GET /gz-raw ", 12)) {
    z = squeeze(t, strlen(t), -15, &zl);
    coding = "deflate";
  } else if (!strncmp(req, "GET /gz-bomb ", 13)) {
    char *zeros = calloc(1, 1 << 20);
    z = squeeze(zeros, 1 << 20, 31, &zl);
    free(zeros);
  } else if (!strncmp(req, "GET /gz-bad ", 12)) {
    z = strdup("not gzip at all");
    zl = strlen(z);
  } else if (!strncmp(req, "GET /gz-br ", 11)) {
    z = strdup("whatever");
    zl = strlen(z);
    coding = "br";
  } else {
    chunked = !strncmp(req, "GET /gz-chunked ", 16);
    z = squeeze(t, strlen(t), 31, &zl);
  }
  if (chunked) {
    size_t half = zl / 2;
    snprintf(head, sizeof head,
             "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\n"
             "Transfer-Encoding: chunked\r\n\r\n%zx\r\n",
             coding, half);
    send(c, head, strlen(head), MSG_NOSIGNAL);
    send(c, z, half, MSG_NOSIGNAL);
    snprintf(head, sizeof head, "\r\n%zx\r\n", zl - half);
    send(c, head, strlen(head), MSG_NOSIGNAL);
    send(c, z + half, zl - half, MSG_NOSIGNAL);
    send(c, "\r\n0\r\n\r\n", 7, MSG_NOSIGNAL);
  } else {
    snprintf(head, sizeof head,
             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
             "Content-Encoding: %s\r\nContent-Length: %zu\r\n\r\n",
             coding, zl);
    send(c, head, strlen(head), MSG_NOSIGNAL);
    send(c, z, zl, MSG_NOSIGNAL);
  }
  free(z);
}

static const char *reply_for(const char *req) {
  if (!strncmp(req, "GET /redirect ", 14)) {
    return "HTTP/1.1 302 Found\r\nLocation: /chunked\r\n"
           "Content-Length: 0\r\n\r\n";
  }
  if (!strncmp(req, "GET /loop ", 10)) {
    return "HTTP/1.1 301 Moved\r\nLocation: /loop\r\n\r\n";
  }
  if (!strncmp(req, "GET /chunked ", 13)) {
    return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           "6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n";
  }
  if (!strncmp(req, "POST /echo ", 11)) {
    return strstr(req, "\r\n\r\nk=v") && strstr(req, "Content-Length: 3\r\n")
               ? "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngot!"
               : "HTTP/1.1 400 Bad\r\nContent-Length: 0\r\n\r\n";
  }
  if (!strncmp(req, "POST /moved7 ", 13)) {
    return "HTTP/1.1 307 Temporary\r\nLocation: /echo\r\n"
           "Content-Length: 0\r\n\r\n";
  }
  if (!strncmp(req, "POST /moved8 ", 13)) {
    return "HTTP/1.1 308 Permanent\r\nLocation: /echo\r\n"
           "Content-Length: 0\r\n\r\n";
  }
  if (!strncmp(req, "POST /login ", 12)) {
    return "HTTP/1.1 303 See Other\r\nSet-Cookie: s=1; Path=/\r\n"
           "Location: /home\r\nContent-Length: 0\r\n\r\n";
  }
  if (!strncmp(req, "GET /home ", 10)) {
    /* signed in: the cookie came, the form's body didn't */
    return strstr(req, "\r\nCookie: s=1\r\n") && !strstr(req, "u=me")
               ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin"
               : "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nout";
  }
  if (!strncmp(req, "GET /big ", 9)) {
    return "HTTP/1.1 200 OK\r\n\r\n"
           "0123456789012345678901234567890123456789";
  }
  if (!strncmp(req, "GET /cut ", 9)) {
    return "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly this";
  }
  if (!strncmp(req, "GET /to-pieces ", 15)) {
    return "HTTP/1.1 307 Temporary\r\nLocation: /pieces\r\n\r\n";
  }
  if (!strncmp(req, "GET /missing ", 13)) {
    return "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope";
  }
  return NULL; /* /silent: never answers */
}

static void serve(int ls) {
  for (;;) {
    int c = accept(ls, NULL, NULL);
    if (c < 0) {
      _exit(0);
    }
    char req[8192];
    size_t n = 0;
    ssize_t r;
    /* the request, its body included (they're small) */
    while (n < sizeof req - 1 &&
           (r = recv(c, req + n, sizeof req - 1 - n, 0)) > 0) {
      n += (size_t)r;
      req[n] = '\0';
      char *hend = strstr(req, "\r\n\r\n");
      if (hend && (strncmp(req, "POST", 4) || strlen(hend) >= 4 + 3)) {
        break;
      }
    }
    if (!strncmp(req, "GET /gz", 7)) {
      gz_reply(c, req);
      close(c);
      continue;
    }
    if (!strncmp(req, "GET /pieces ", 12)) {
      /* chunked, a chunk's size and data split across writes */
      const char *part[] = {"HTTP/1.1 200 OK\r\nTransfer-Enc",
                            "oding: chunked\r\n\r\n6\r", "\nhello \r\n5",
                            "\r\nwor", "ld\r\n0\r\n\r\n"};
      for (size_t i = 0; i < sizeof part / sizeof *part; i++) {
        send(c, part[i], strlen(part[i]), MSG_NOSIGNAL);
        nanosleep(&(struct timespec){0, 20000000}, NULL);
      }
      close(c);
      continue;
    }
    if (!strncmp(req, "GET /endless ", 13)) {
      const char *h = "HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\n\r\n";
      char blk[4096];
      memset(blk, 'x', sizeof blk);
      if (send(c, h, strlen(h), MSG_NOSIGNAL) > 0) {
        while (send(c, blk, sizeof blk, MSG_NOSIGNAL) > 0) {
        }
      }
      close(c);
      continue;
    }
    if (!strncmp(req, "GET /stall ", 11)) {
      const char *h = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nsome";
      send(c, h, strlen(h), MSG_NOSIGNAL);
      sleep(5);
      close(c);
      continue;
    }
    const char *rep = reply_for(req);
    if (!rep) {
      sleep(5);
    } else {
      send(c, rep, strlen(rep), MSG_NOSIGNAL);
    }
    close(c);
  }
}

typedef struct {
  char buf[64];
  size_t len;
  int heads, status;
  size_t stop_after;
  char type[32];
} STREAMED;

static int st_head(void *ctx, const CTUI_WM_HTTP_REPLY *rep) {
  STREAMED *s = ctx;
  s->heads++;
  s->status = rep->status;
  ctui_wm_http_reply_header(rep, "Content-Type", s->type, sizeof s->type);
  return 0;
}

static int st_body(void *ctx, const char *buf, size_t n) {
  STREAMED *s = ctx;
  size_t k = s->len < sizeof s->buf - 1 ? sizeof s->buf - 1 - s->len : 0;
  memcpy(s->buf + s->len, buf, n < k ? n : k);
  s->len += n;
  s->buf[s->len < sizeof s->buf ? s->len : sizeof s->buf - 1] = '\0';
  return s->stop_after && s->len >= s->stop_after;
}

static void test_streams(int port) {
  char url[128];
  CTUI_WM_HTTP_REPLY rep;
  STREAMED s = {0};
  CTUI_WM_HTTP_SINK sink = {.head = st_head, .body = st_body, .ctx = &s};
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};

  snprintf(url, sizeof url, "http://127.0.0.1:%d/to-pieces", port);
  CTUI_TEST_ASSERT(
      ctui_wm_net_http_stream(&req, &sink, &rep, g_err, sizeof g_err) == 0 &&
          s.heads == 1 && s.status == 200 && rep.status == 200 &&
          !strcmp(s.buf, "hello world") && rep.body && !rep.body[0] &&
          rep.len == 0 && rep.url && strstr(rep.url, "127.0.0.1"),
      "streamed: a redirect, then chunks split across reads");
  free(rep.body);

  memset(&s, 0, sizeof s);
  s.stop_after = 1 << 20;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/endless", port);
  CTUI_TEST_ASSERT(
      ctui_wm_net_http_stream(&req, &sink, &rep, g_err, sizeof g_err) == 0 &&
          s.len >= (size_t)1 << 20 && !strcmp(s.type, "audio/mpeg"),
      "an endless body runs until the sink stops it");
  free(rep.body);

  memset(&s, 0, sizeof s);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/gzip", port);
  CTUI_TEST_ASSERT(
      ctui_wm_net_http_stream(&req, &sink, &rep, g_err, sizeof g_err) == 0 &&
          !strcmp(s.buf, "not offered"),
      "a stream doesn't offer gzip (it comes as it is: Range, progress)");
  free(rep.body);

  memset(&s, 0, sizeof s);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/cut", port);
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(
      ctui_wm_net_http_stream(&req, &sink, &rep, g_err, sizeof g_err) != 0 &&
          strstr(g_err, "inside its body") && !strcmp(s.buf, "only this") &&
          !rep.body,
      "a body cut short: -1, what came was handed on");

  memset(&s, 0, sizeof s);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/stall", port);
  CTUI_WM_HTTP_REQ stall = {.url = url, .timeout_ms = 300};
  long t0 = ctui_wm_net_now();
  CTUI_TEST_ASSERT(
      ctui_wm_net_http_stream(&stall, &sink, &rep, g_err, sizeof g_err) != 0 &&
          !strcmp(g_err, "timed out") && !strcmp(s.buf, "some") &&
          ctui_wm_net_now() - t0 < 2000,
      "a body that stops coming: timed out after the idle time");
}

/* a hop judge: with a buffer, refuses (the address into it); without,
 * sends /chunked on to /missing */
static int hop_judge(void *ctx, const char *url, char *out, size_t cap,
                     char *why, size_t why_cap) {
  if (ctx) {
    snprintf(ctx, 160, "%s", url);
    snprintf(why, why_cap, "no: %s", strrchr(url, '/'));
    return -1;
  }
  snprintf(out, cap, "%.*s/missing", (int)(strrchr(url, '/') - url), url);
  return 0;
}

static void test_gzipped(int port) {
  char url[128], v[64];
  CTUI_WM_HTTP_REPLY rep;
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};
  const char *paths[] = {"/gzip", "/gz-chunked", "/gz-raw"};
  for (size_t i = 0; i < sizeof paths / sizeof *paths; i++) {
    snprintf(url, sizeof url, "http://127.0.0.1:%d%s", port, paths[i]);
    int r = ctui_wm_net_http(&req, &rep, g_err, sizeof g_err);
    CTUI_TEST_ASSERT(
        r == 0 && rep.status == 200 && rep.len == strlen(text()) &&
            !strcmp(rep.body, text()) &&
            !ctui_wm_http_reply_header(&rep, "Content-Encoding", v, sizeof v) &&
            !ctui_wm_http_reply_header(&rep, "Content-Length", v, sizeof v) &&
            ctui_wm_http_reply_header(&rep, "Content-Type", v, sizeof v) ==
                (i != 1),
        "%s: the body decoded, its coding and length gone from the headers "
        "(%s)",
        paths[i], r ? g_err : "");
    free(r == 0 ? rep.body : NULL);
  }

  const char *own[] = {"Accept-Encoding: gzip", NULL};
  snprintf(url, sizeof url, "http://127.0.0.1:%d/gzip", port);
  CTUI_WM_HTTP_REQ mine = {.url = url, .timeout_ms = 3000, .headers = own};
  CTUI_TEST_ASSERT(
      ctui_wm_net_http(&mine, &rep, g_err, sizeof g_err) == 0 && rep.len > 2 &&
          (unsigned char)rep.body[0] == 0x1f &&
          (unsigned char)rep.body[1] == 0x8b &&
          ctui_wm_http_reply_header(&rep, "Content-Encoding", v, sizeof v),
      "asked for by the caller: handed over as it came");
  free(rep.body);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/gz-bomb", port);
  CTUI_WM_HTTP_REQ bomb = {.url = url, .timeout_ms = 3000, .max = 65536};
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(ctui_wm_net_http(&bomb, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "over 65536 bytes"),
                   "max counts the decoded bytes (1 MB of zeros in ~1 KB)");
  snprintf(url, sizeof url, "http://127.0.0.1:%d/gz-bad", port);
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "broken"),
                   "a body that isn't what its coding says: refused");
  snprintf(url, sizeof url, "http://127.0.0.1:%d/gz-br", port);
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "don't read: br"),
                   "a coding not offered: refused, named");
}

/* a jar of one cookie, for the hooks */
typedef struct {
  char cookie[64];
  int replies;
  char last[160];
} JAR;

static size_t jar_cookie(void *ctx, const char *url, char *out, size_t cap) {
  (void)url;
  JAR *j = ctx;
  return (size_t)snprintf(out, cap, "%s", j->cookie);
}

static void jar_replied(void *ctx, const char *url, const char *h, size_t n) {
  JAR *j = ctx;
  j->replies++;
  snprintf(j->last, sizeof j->last, "%s", url);
  char hs[512];
  snprintf(hs, sizeof hs, "%.*s", (int)n, h);
  const char *sc = strstr(hs, "Set-Cookie: ");
  if (sc) {
    snprintf(j->cookie, sizeof j->cookie, "%.*s", (int)strcspn(sc + 12, ";\r"),
             sc + 12);
  }
}

/* a sign-in: a POST answered 303 with a cookie, the page it names asked
 * for by GET, the cookie with it */
static void test_signin(int port) {
  char url[128], home[128];
  snprintf(url, sizeof url, "http://127.0.0.1:%d/login", port);
  snprintf(home, sizeof home, "http://127.0.0.1:%d/home", port);
  JAR jar = {0};
  CTUI_WM_HTTP_REQ req = {.method = "POST",
                          .url = url,
                          .content_type = "application/x-www-form-urlencoded",
                          .body = "u=me",
                          .body_len = 4,
                          .timeout_ms = 3000,
                          .cookie = jar_cookie,
                          .replied = jar_replied,
                          .cookie_ctx = &jar};
  CTUI_WM_HTTP_REPLY rep;
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "in"),
                   "a POST's 303 followed by GET, its cookie sent");
  CTUI_TEST_ASSERT(jar.replies == 2 && !strcmp(jar.last, home) && rep.url &&
                       !strcmp(rep.url, home),
                   "both replies' headers handed over, each with its URL");
  free(rep.body);
  /* a 307 / 308: the same POST again, its body and type with it (the
   * echo answers 400 without them) */
  const char *codes[] = {"moved7", "moved8"};
  for (int i = 0; i < 2; i++) {
    snprintf(url, sizeof url, "http://127.0.0.1:%d/%s", port, codes[i]);
    CTUI_WM_HTTP_REQ again = {.method = "POST",
                              .url = url,
                              .content_type = "text/plain",
                              .body = "k=v",
                              .body_len = 3,
                              .timeout_ms = 3000};
    CTUI_TEST_ASSERT(ctui_wm_net_http(&again, &rep, g_err, sizeof g_err) == 0 &&
                         rep.status == 200 && !strcmp(rep.body, "got!"),
                     "a POST's %s: sent again as a POST, with its body (%d %s)",
                     i ? "308" : "307", rep.status, g_err);
    free(rep.body);
  }
}

static void test_exchanges(void) {
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t alen = sizeof a;
  CTUI_TEST_ASSERT(ls >= 0 && bind(ls, (struct sockaddr *)&a, sizeof a) == 0 &&
                       listen(ls, 8) == 0 &&
                       getsockname(ls, (struct sockaddr *)&a, &alen) == 0,
                   "a local server");
  if (ls < 0) {
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    serve(ls);
  }
  close(ls);
  char url[128];
  int port = ntohs(a.sin_port);
  CTUI_WM_HTTP_REPLY rep;

  snprintf(url, sizeof url, "http://127.0.0.1:%d/redirect", port);
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "hello world"),
                   "a redirect followed to a chunked reply");
  char where[160];
  snprintf(where, sizeof where, "http://127.0.0.1:%d/chunked", port);
  CTUI_TEST_ASSERT(rep.url && !strcmp(rep.url, where),
                   "the reply says where the redirect led");
  free(rep.body);

  /* each hop asked of the caller first: refused, or sent elsewhere */
  CTUI_WM_HTTP_REQ judged = req;
  judged.hop = hop_judge;
  char seen[160] = "";
  judged.hop_ctx = seen;
  CTUI_TEST_ASSERT(ctui_wm_net_http(&judged, &rep, g_err, sizeof g_err) != 0 &&
                       !strcmp(seen, where) && !strcmp(g_err, "no: /chunked"),
                   "a hop refused: the request fails with the caller's why");
  judged.hop_ctx = NULL;
  snprintf(where, sizeof where, "http://127.0.0.1:%d/missing", port);
  CTUI_TEST_ASSERT(ctui_wm_net_http(&judged, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 404 && rep.url && !strcmp(rep.url, where),
                   "a hop rewritten: asked as the caller said");
  free(rep.body);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/missing", port);
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 404 && !strcmp(rep.body, "nope") &&
                       !rep.url,
                   "a 404 is a reply: its status and body");
  char v[32];
  CTUI_TEST_ASSERT(
      ctui_wm_http_reply_header(&rep, "content-length", v, sizeof v) &&
          !strcmp(v, "4") && rep.headers == rep.body + 5 &&
          !ctui_wm_http_reply_header(&rep, "Location", v, sizeof v),
      "the reply's headers, after its body, looked up by name");
  free(rep.body);

  test_gzipped(port);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/echo", port);
  CTUI_WM_HTTP_REQ post = {.method = "POST",
                           .url = url,
                           .content_type = "application/x-www-form-urlencoded",
                           .body = "k=v",
                           .body_len = 3,
                           .timeout_ms = 3000};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&post, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "got!"),
                   "a POST with its body");
  free(rep.body);

  test_signin(port);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/loop", port);
  g_err[0] = '\0';
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "redirects"),
                   "a redirect loop gives up");

  snprintf(url, sizeof url, "http://127.0.0.1:%d/big", port);
  CTUI_WM_HTTP_REQ big = {.url = url, .timeout_ms = 3000, .max = 16};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&big, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "over 16 bytes"),
                   "a reply over max refused");

  /* before /silent and with /stall last: the server answers one at a
   * time, and those two keep it for 5 s */
  test_streams(port);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/silent", port);
  CTUI_WM_HTTP_REQ slow = {.url = url, .timeout_ms = 300};
  long t0 = ctui_wm_net_now();
  CTUI_TEST_ASSERT(ctui_wm_net_http(&slow, &rep, g_err, sizeof g_err) != 0 &&
                       !strcmp(g_err, "timed out") &&
                       ctui_wm_net_now() - t0 < 2000,
                   "a server that never answers: timed out at the deadline");

  /* the listener is gone with the server: refused */
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/", port);
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) != 0 &&
                       strstr(g_err, "connecting"),
                   "nothing listening: connecting fails, with why");
}

/* a ClientHello into a socketpair whose far end is gone: the CA bundle
 * parsed, a key share made, the send refused -- no server needed */
static void *tls_start(void *arg) {
  int *failed = arg;
  for (int round = 0; round < 4; round++) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) {
      (*failed)++;
      return NULL;
    }
    close(sv[1]);
    char err[256];
    CTUI_WM_TLS *t = ctui_wm_tls_open(
        sv[0], "example.org", ctui_wm_net_now() + 2000, err, sizeof err);
    if (t) {
      ctui_wm_tls_close(t);
      (*failed)++;
    }
    close(sv[0]);
  }
  return NULL;
}

static void test_tls_threads(void) {
  if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) != 0 &&
      access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) != 0 &&
      access("/etc/ssl/cert.pem", R_OK) != 0) {
    return; /* no CA bundle here: setup fails the same way in each */
  }
  enum { N = 8 };
  pthread_t th[N];
  int failed[N] = {0};
  int started = 0;
  for (int i = 0; i < N; i++) {
    started += pthread_create(&th[i], NULL, tls_start, &failed[i]) == 0;
  }
  int bad = 0;
  for (int i = 0; i < started; i++) {
    pthread_join(th[i], NULL);
    bad += failed[i];
  }
  CTUI_TEST_ASSERT(started == N && bad == 0,
                   "TLS started from 8 threads at once: each refused, "
                   "none crashed");
}

/* --- the server side --- */

static int head(const char *text, CTUI_WM_HTTPD_REQ *r) {
  static char buf[CTUI_WM_HTTPD_HEAD_MAX];
  snprintf(buf, sizeof buf, "%s", text);
  return ctui_wm_httpd_parse(buf, r, g_err, sizeof g_err);
}

static void test_httpd_parse(void) {
  CTUI_WM_HTTPD_REQ r;
  CTUI_TEST_ASSERT(
      head("GET /a%20b/c?x=1&y HTTP/1.1\r\nHost: h\r\n"
           "X-Thing:  spaced  \r\ncontent-length: 5\r\n",
           &r) == 0 &&
          !strcmp(r.method, "GET") && !strcmp(r.path, "/a b/c") &&
          !strcmp(r.query, "x=1&y") && r.minor == 1 && r.length == 5 &&
          r.keep_alive &&
          !strcmp(ctui_wm_httpd_header(&r, "x-thing"), "spaced") &&
          !ctui_wm_httpd_header(&r, "Cookie"),
      "a request head: path decoded, query, headers trimmed, length");
  CTUI_TEST_ASSERT(
      head("GET / HTTP/1.1\nHost: h\nConnection: x, Close\n", &r) == 0 &&
          !r.keep_alive && r.length == -1,
      "bare LFs; Connection: close ends keep-alive");
  CTUI_TEST_ASSERT(head("GET / HTTP/1.0\n", &r) == 0 && !r.keep_alive &&
                       head("GET / HTTP/1.0\nConnection: keep-alive\n", &r) ==
                           0 &&
                       r.keep_alive,
                   "HTTP/1.0: no Host needed, kept alive only when asked");
  static const struct {
    const char *head;
    int status;
  } BAD[] = {
      {"GET / HTTP/1.1\n", 400},                  /* no Host */
      {"GET /%zz HTTP/1.1\nHost: h\n", 400},      /* escape */
      {"GET /a%0 HTTP/1.1\nHost: h\n", 400},      /* cut escape */
      {"GET /%00 HTTP/1.1\nHost: h\n", 400},      /* a NUL */
      {"GET http://h/ HTTP/1.1\nHost: h\n", 400}, /* absolute */
      {"GET / HTTP/2.0\nHost: h\n", 505},
      {"GET /  HTTP/1.1\nHost: h\n", 400}, /* two spaces */
      {"G(T / HTTP/1.1\nHost: h\n", 400},
      {"GET / HTTP/1.1\nHost: h\n folded\n", 400},
      {"GET / HTTP/1.1\nHost : h\n", 400},
      {"GET / HTTP/1.1\nHost: h\nContent-Length: 1x\n", 400},
      {"GET / HTTP/1.1\nHost: h\nContent-Length: 1\nContent-Length: 2\n", 400},
      {"POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n", 411},
      {"POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n"
       "Content-Length: 3\n",
       400},
      {"GET / HTTP/1.1\nHost: a\x01b\n", 400},
  };
  int ok = 0;
  for (size_t i = 0; i < sizeof BAD / sizeof *BAD; i++) {
    int st = head(BAD[i].head, &r);
    ok += st == BAD[i].status;
    if (st != BAD[i].status) {
      printf("  bad head %zu: %d, not %d (%s)\n", i, st, BAD[i].status, g_err);
    }
  }
  CTUI_TEST_ASSERT(ok == (int)(sizeof BAD / sizeof *BAD),
                   "bad heads refused with their status (%d of %zu)", ok,
                   sizeof BAD / sizeof *BAD);
  char many[CTUI_WM_HTTPD_HEAD_MAX];
  int n = snprintf(many, sizeof many, "GET / HTTP/1.1\n");
  for (int i = 0; i <= CTUI_WM_HTTPD_HEADERS; i++) {
    n += snprintf(many + n, sizeof many - (size_t)n, "H%d: v\n", i);
  }
  CTUI_TEST_ASSERT(head(many, &r) == 431, "too many header lines: 431");
  CTUI_BUF b = {0};
  ctui_wm_httpd_escape(&b, "<a href=\"x\">R&D's</a>");
  CTUI_TEST_ASSERT(b.s &&
                       !strcmp(b.s, "&lt;a href=&quot;x&quot;&gt;R&amp;D&#39;"
                                    "s&lt;/a&gt;"),
                   "HTML escaped");
  free(b.s);
}

typedef struct {
  CTUI_WM_TLS_SERVER *tls;
  int conns; /* accepted so far */
} SRV;

/* a body in three writes, the last empty (skipped, not the end) */
static int streamed(CTUI_WM_HTTPD_OUT *o, void *ud) {
  free(ud);
  return ctui_wm_httpd_out(o, "one ", 4) || ctui_wm_httpd_out(o, "two", 3) ||
                 ctui_wm_httpd_out(o, "", 0)
             ? -1
             : 0;
}

static void on_page(const CTUI_WM_HTTPD_REQ *r, const char *body,
                    CTUI_WM_HTTPD_REPLY *rep, void *ud) {
  (void)ud;
  if (!strcmp(r->path, "/echo")) {
    ctui_wm_httpd_text(rep, 200, "text/plain", body ? body : "",
                       body ? (size_t)r->length : 0);
  } else if (!strcmp(r->path, "/go")) {
    rep->status = 302;
    snprintf(rep->headers, sizeof rep->headers, "Location: /hi\r\n");
  } else if (!strcmp(r->path, "/hi")) {
    ctui_wm_httpd_text(rep, 200, "text/plain", "hi there", 8);
  } else if (!strcmp(r->path, "/stream")) {
    rep->status = 200;
    rep->type = "text/plain";
    rep->stream = streamed;
    rep->stream_ud = calloc(1, 1); /* freed by streamed(): ASan checks */
  } else if (!strcmp(r->path, "/whoami")) {
    char cn[64], fpr[65], text[200];
    int has = ctui_wm_conn_peer_cert(r->conn, cn, sizeof cn, fpr) == 0;
    int n = snprintf(text, sizeof text, "%s %s %s", has ? cn : "-",
                     has ? fpr : "-", r->peer ? "peer" : "nopeer");
    ctui_wm_httpd_text(rep, 200, "text/plain", text, (size_t)n);
  } else {
    ctui_wm_httpd_text(rep, 404, "text/plain", "none", 4);
  }
}

static void on_conn(CTUI_WM_CONN *c, const char *peer, void *ud) {
  SRV *s = ud;
  char err[256];
  __atomic_fetch_add(&s->conns, 1, __ATOMIC_SEQ_CST);
  if (s->tls && ctui_wm_conn_accept_tls(c, s->tls, err, sizeof err) != 0) {
    ctui_wm_conn_close(c);
    return;
  }
  CTUI_WM_HTTPD h = {.handler = on_page, .server = "test", .idle_ms = 500};
  ctui_wm_httpd_serve(&h, c, peer);
}

typedef struct {
  CTUI_WM_LISTEN *ls[2];
  int stop;
} SERVE;

static void *serve_run(void *arg) {
  SERVE *s = arg;
  char err[128];
  ctui_wm_listen_serve(s->ls, 2, s->stop, err, sizeof err);
  return NULL;
}

static void *serve_one(void *arg) {
  SERVE *s = arg;
  char err[128];
  ctui_wm_listen_serve(s->ls, 1, s->stop, err, sizeof err);
  return NULL;
}

static int conns(SRV *s) {
  return __atomic_load_n(&s->conns, __ATOMIC_SEQ_CST);
}

/* GETs to one host on one connection; a POST on a new one; one the server
 * closed while idle (its idle_ms is 500) found out and sent again */
static void test_kept(SRV *plain, int port, SRV *tls, int tls_port) {
  char url[128], err[256];
  CTUI_WM_HTTP_REPLY rep;
  ctui_wm_net_idle_close();
  int c0 = conns(plain), ok = 1;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/hi", port);
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};
  for (int i = 0; i < 3; i++) {
    ok = ok && ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
         !strcmp(rep.body, "hi there");
    free(ok ? rep.body : NULL);
  }
  CTUI_TEST_ASSERT(
      ok && conns(plain) == c0 + 1 && ctui_wm_net_idle_count() == 1,
      "three GETs on one connection, kept after (%d)", conns(plain) - c0);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/echo", port);
  CTUI_WM_HTTP_REQ post = {.url = url,
                           .timeout_ms = 3000,
                           .method = "POST",
                           .body = "x",
                           .body_len = 1};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&post, &rep, err, sizeof err) == 0 &&
                       !strcmp(rep.body, "x") && conns(plain) == c0 + 2,
                   "a POST never goes on a kept connection (it isn't sent "
                   "twice)");
  free(rep.body);

  snprintf(url, sizeof url, "https://localhost:%d/hi", tls_port);
  int t0 = conns(tls);
  ok = 1;
  for (int i = 0; i < 2; i++) {
    ok = ok && ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
         !strcmp(rep.body, "hi there");
    free(ok ? rep.body : NULL);
  }
  CTUI_TEST_ASSERT(ok && conns(tls) == t0 + 1,
                   "over TLS: two GETs, one handshake (%s)", ok ? "" : err);

  /* past the server's idle time: it has closed both */
  nanosleep(&(struct timespec){0, 800000000}, NULL);
  ok = ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
       !strcmp(rep.body, "hi there");
  free(ok ? rep.body : NULL);
  CTUI_TEST_ASSERT(ok && conns(tls) == t0 + 2,
                   "over TLS: one the server closed meanwhile, sent again on "
                   "a new one (%s)",
                   ok ? "" : err);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/hi", port);
  int c1 = conns(plain);
  ok = ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
       !strcmp(rep.body, "hi there");
  free(ok ? rep.body : NULL);
  CTUI_TEST_ASSERT(ok && conns(plain) == c1 + 1,
                   "plainly: the same, found closed before sending (%s)",
                   ok ? "" : err);
  ctui_wm_net_idle_close();
  CTUI_TEST_ASSERT(ctui_wm_net_idle_count() == 0, "kept ones closed on asking");
}

/* req sent on a new plain connection to port, everything back until the
 * server closes into got */
static void raw_exchange(int port, const char *req, char *got, size_t cap) {
  char url[64], err[256];
  CTUI_WM_URL u;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/", port);
  ctui_wm_url_parse(url, &u, err, sizeof err);
  CTUI_WM_CONN *c =
      ctui_wm_conn_open(&u, ctui_wm_net_now() + 3000, err, sizeof err);
  size_t len = 0;
  if (c && ctui_wm_conn_write(c, req, strlen(req), err, sizeof err) == 0) {
    ssize_t r;
    while ((r = ctui_wm_conn_read(c, got + len, cap - 1 - len, err,
                                  sizeof err)) > 0) {
      len += (size_t)r;
    }
  }
  got[len] = '\0';
  ctui_wm_conn_close(c);
}

/* a body of unknown length: chunked to HTTP/1.1 (our client joins it,
 * the connection kept), until the close to HTTP/1.0, none for HEAD */
static void test_streamed(int port) {
  char url[128], err[256], got[2048];
  CTUI_WM_HTTP_REPLY rep;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/stream", port);
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "one two"),
                   "a streamed body, chunked, read whole (%s)", err);
  free(rep.body);
  raw_exchange(port,
               "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
               "\r\n",
               got, sizeof got);
  CTUI_TEST_ASSERT(strstr(got, "Transfer-Encoding: chunked\r\n") &&
                       !strstr(got, "Content-Length") &&
                       strstr(got, "\r\n\r\n4\r\none \r\n3\r\ntwo\r\n0\r\n"
                                   "\r\n"),
                   "HTTP/1.1: a chunk per write, the empty one skipped, then "
                   "the last chunk");
  raw_exchange(port, "GET /stream HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
               got, sizeof got);
  CTUI_TEST_ASSERT(!strstr(got, "Transfer-Encoding") &&
                       strstr(got, "Connection: close\r\n") &&
                       strstr(got, "\r\n\r\none two") &&
                       !strstr(got, "two\r\n"),
                   "HTTP/1.0: the body as is, the connection closed after it "
                   "(kept-alive asked for)");
  raw_exchange(port,
               "HEAD /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
               got, sizeof got);
  char *end = strstr(got, "\r\n\r\n");
  CTUI_TEST_ASSERT(end && end[4] == '\0' && strstr(got, "200 OK"),
                   "HEAD: the head only");
}

/* the server asking for a client certificate from its CA: the phone's
 * passes and its name and fingerprint reach the handler; a stranger's
 * (another CA) and none at all end at the handshake */
static void test_mutual(void) {
  char err[256];
  SRV srv = {0};
  srv.tls = ctui_wm_tls_server_new(
      "tests/data/pki/server.crt", "tests/data/pki/server.key",
      "tests/data/pki/client-ca.crt", err, sizeof err);
  CTUI_TEST_ASSERT(srv.tls != NULL, "a mutual-TLS server's config (%s)",
                   srv.tls ? "" : err);
  CTUI_TEST_ASSERT(!ctui_wm_tls_client_new("tests/data/pki/ca.crt",
                                           "tests/data/pki/phone.crt", NULL,
                                           err, sizeof err),
                   "a client certificate without its key refused");
  SERVE sv = {0};
  sv.ls[0] = ctui_wm_listen_new("127.0.0.1", 0, on_conn, &srv, err, sizeof err);
  int pfd[2];
  if (!srv.tls || !sv.ls[0] || pipe(pfd) != 0) {
    CTUI_TEST_ASSERT(0, "a listener on port 0 (%s)", err);
    ctui_wm_tls_server_free(srv.tls);
    return;
  }
  sv.stop = pfd[0];
  pthread_t th;
  pthread_create(&th, NULL, serve_one, &sv);
  struct {
    const char *cert, *key, *want;
  } T[] = {{"tests/data/pki/phone.crt", "tests/data/pki/phone.key",
            "phone 966a2e84f718869bc9e7aa391fd56ee27c40c8c171f6051253214d90a"
            "ff67ce9 peer"},
           {"tests/data/pki/stranger.crt", "tests/data/pki/stranger.key", NULL},
           {NULL, NULL, NULL}};
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    CTUI_WM_TLS_CLIENT *cl = ctui_wm_tls_client_new(
        "tests/data/pki/ca.crt", T[i].cert, T[i].key, err, sizeof err);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_port = htons((uint16_t)sv.ls[0]->port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CTUI_WM_TLS *t = NULL;
    char got[512] = "";
    if (cl && fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0) {
      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
      long dl = ctui_wm_net_now() + 3000;
      t = ctui_wm_tls_connect(fd, "localhost", cl, dl, err, sizeof err);
      const char *q =
          "GET /whoami HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
      size_t len = 0;
      ssize_t r = 0;
      if (t && ctui_wm_tls_write(t, q, strlen(q), dl, err, sizeof err) == 0) {
        while ((r = ctui_wm_tls_read(t, got + len, sizeof got - 1 - len, dl,
                                     err, sizeof err)) > 0) {
          len += (size_t)r;
        }
      }
      got[len] = '\0';
      /* TLS 1.3: the client's handshake is done before the server has
       * checked its certificate; a refusal shows on the first read */
      if (r < 0 || len == 0) {
        ctui_wm_tls_close(t);
        t = NULL;
      }
    }
    if (T[i].want) {
      char *body = strstr(got, "\r\n\r\n");
      CTUI_TEST_ASSERT(t && body && !strcmp(body + 4, T[i].want),
                       "the phone's certificate taken, its name and "
                       "fingerprint at the handler (%s)",
                       t ? got : err);
    } else {
      CTUI_TEST_ASSERT(
          !t, "%s refused at the handshake (%s)",
          T[i].cert ? "a stranger's certificate" : "no certificate", err);
    }
    ctui_wm_tls_close(t);
    if (fd >= 0) {
      close(fd);
    }
    ctui_wm_tls_client_free(cl);
  }
  ssize_t w = write(pfd[1], "x", 1);
  (void)w;
  pthread_join(th, NULL);
  for (int i = 0; i < 50 && ctui_wm_listen_active() > 0; i++) {
    nanosleep(&(struct timespec){0, 20000000}, NULL);
  }
  ctui_wm_listen_free(sv.ls[0]);
  ctui_wm_tls_server_free(srv.tls);
  close(pfd[0]);
  close(pfd[1]);
}

static void test_server(void) {
  char err[256];
  SRV plain = {0}, tls = {0};
  tls.tls = ctui_wm_tls_server_new("tests/data/pki/server.crt",
                                   "tests/data/pki/server.key", NULL, err,
                                   sizeof err);
  CTUI_TEST_ASSERT(tls.tls != NULL, "a TLS server's config (%s)",
                   tls.tls ? "" : err);
  CTUI_TEST_ASSERT(!ctui_wm_tls_server_new("tests/data/pki/server.crt",
                                           "tests/data/pki/nope.key", NULL, err,
                                           sizeof err) &&
                       strstr(err, "nope.key"),
                   "a missing key refused, named (%s)", err);
  SERVE sv = {0};
  sv.ls[0] =
      ctui_wm_listen_new("127.0.0.1", 0, on_conn, &plain, err, sizeof err);
  sv.ls[1] = ctui_wm_listen_new("127.0.0.1", 0, on_conn, &tls, err, sizeof err);
  int pfd[2];
  if (!tls.tls || !sv.ls[0] || !sv.ls[1] || pipe(pfd) != 0) {
    CTUI_TEST_ASSERT(0, "listeners on port 0 (%s)", err);
    return;
  }
  sv.stop = pfd[0];
  pthread_t th;
  pthread_create(&th, NULL, serve_run, &sv);
  char url[128];
  CTUI_WM_HTTP_REPLY rep;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/go", sv.ls[0]->port);
  CTUI_WM_HTTP_REQ req = {.url = url, .timeout_ms = 3000};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "hi there"),
                   "our client against our server: a redirect, then a page "
                   "(%s)",
                   err);
  free(rep.body);
  snprintf(url, sizeof url, "http://127.0.0.1:%d/echo", sv.ls[0]->port);
  req = (CTUI_WM_HTTP_REQ){.url = url,
                           .timeout_ms = 3000,
                           .method = "POST",
                           .body = "posted body",
                           .body_len = 11};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "posted body"),
                   "a POST's body read by Content-Length (%s)", err);
  free(rep.body);
  snprintf(url, sizeof url, "https://localhost:%d/hi", sv.ls[1]->port);
  req = (CTUI_WM_HTTP_REQ){.url = url, .timeout_ms = 3000};
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, err, sizeof err) == 0 &&
                       rep.status == 200 && !strcmp(rep.body, "hi there"),
                   "over TLS: the test CA's localhost certificate (%s)", err);
  free(rep.body);
  test_kept(&plain, sv.ls[0]->port, &tls, sv.ls[1]->port);
  test_streamed(sv.ls[0]->port);
  /* the TLS port reached plainly, TLS started with a name its
   * certificate doesn't carry */
  CTUI_WM_URL u;
  snprintf(url, sizeof url, "http://127.0.0.1:%d/", sv.ls[1]->port);
  ctui_wm_url_parse(url, &u, err, sizeof err);
  CTUI_WM_CONN *c =
      ctui_wm_conn_open(&u, ctui_wm_net_now() + 3000, err, sizeof err);
  int bad = c ? ctui_wm_conn_starttls(c, "wrong.example", err, sizeof err) : 0;
  ctui_wm_conn_close(c);
  CTUI_TEST_ASSERT(bad != 0 && strstr(err, "certificate"),
                   "a name the certificate doesn't carry refused (%s)", err);
  /* two requests on one connection, the second asking to close */
  snprintf(u.port, sizeof u.port, "%d", sv.ls[0]->port);
  c = ctui_wm_conn_open(&u, ctui_wm_net_now() + 3000, err, sizeof err);
  const char *two = "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n"
                    "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close"
                    "\r\n\r\n";
  char got[1024];
  size_t len = 0;
  if (c && ctui_wm_conn_write(c, two, strlen(two), err, sizeof err) == 0) {
    ssize_t r;
    while ((r = ctui_wm_conn_read(c, got + len, sizeof got - 1 - len, err,
                                  sizeof err)) > 0) {
      len += (size_t)r;
    }
  }
  got[len] = '\0';
  ctui_wm_conn_close(c);
  CTUI_TEST_ASSERT(strstr(got, "200 OK") && strstr(got, "hi there") &&
                       strstr(got, "404 Not Found") &&
                       strstr(got, "Connection: close") &&
                       strstr(got, "Server: test"),
                   "keep-alive: two answers on one connection, then closed");
  ssize_t w = write(pfd[1], "x", 1);
  (void)w;
  pthread_join(th, NULL);
  for (int i = 0; i < 50 && ctui_wm_listen_active() > 0; i++) {
    nanosleep(&(struct timespec){0, 20000000}, NULL);
  }
  CTUI_TEST_ASSERT(ctui_wm_listen_active() == 0,
                   "every connection's thread done");
  ctui_wm_listen_free(sv.ls[0]);
  ctui_wm_listen_free(sv.ls[1]);
  ctui_wm_tls_server_free(tls.tls);
  close(pfd[0]);
  close(pfd[1]);
}

int main(void) {
  ctui_log_init(E_ERR);
  /* before anything starts TLS: the client reads it once per process */
  setenv("SSL_CERT_FILE", "tests/data/pki/ca.crt", 1);
  test_urls();
  test_format();
  test_replies();
  test_decoder();
  test_coding();
  test_reuse();
  test_exchanges();
  test_tls_threads();
  test_httpd_parse();
  test_server();
  test_mutual();
  return ctui_test_summary();
}
