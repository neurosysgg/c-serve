/* plugins/net: URLs, the request, replies (Content-Length, chunked, to the
 * end, interim 1xx, cut off; whole and a byte at a time), then whole
 * exchanges over plain HTTP with a server forked on 127.0.0.1 -- a
 * redirect, a chunked reply, a POST, a server that never answers (the
 * deadline), one too big, the reply's headers -- and streamed ones (split
 * chunks, an endless body, a cut one, one that stalls). TLS itself runs
 * live only (HISTORY.md, session 77: open-meteo, badssl.com's bad
 * certificates refused). */
#define _POSIX_C_SOURCE 200809L

#include "conn.h"
#include "http.h"
#include "net.h"

#include "ctui.h"
#include "ctui_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_err[256];

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
      ctui_wm_http_format(&get, &u, &out, &len) == 0 &&
          !strncmp(out, "GET /p?q HTTP/1.1\r\nHost: h.example\r\n", 36) &&
          strstr(out, "Connection: close\r\n") &&
          !strstr(out, "Content-Length") && len > 4 &&
          !strcmp(out + len - 4, "\r\n\r\n"),
      "a GET: Host without the default port, no body");
  free(out);

  ctui_wm_url_parse("http://h:8080/t", &u, g_err, sizeof g_err);
  const char *hdrs[] = {"Authorization: Bearer x", NULL};
  CTUI_WM_HTTP_REQ post = {.method = "POST",
                           .content_type = "application/x-www-form-urlencoded",
                           .body = "a=1&b=2",
                           .body_len = 7,
                           .headers = hdrs};
  CTUI_TEST_ASSERT(
      ctui_wm_http_format(&post, &u, &out, &len) == 0 &&
          strstr(out, "Host: h:8080\r\n") &&
          strstr(out, "Authorization: Bearer x\r\n") &&
          strstr(out, "Content-Type: application/x-www-form-urlencoded\r\n") &&
          strstr(out, "Content-Length: 7\r\n") &&
          !strcmp(out + len - 11, "\r\n\r\na=1&b=2"),
      "a POST: the port in Host, extra headers, its type, length and body");
  free(out);

  const char *evil[] = {"X: a\r\nY: b", NULL};
  CTUI_WM_HTTP_REQ inj = {.headers = evil};
  CTUI_TEST_ASSERT(ctui_wm_http_format(&inj, &u, &out, &len) != 0,
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

/* --- a server on 127.0.0.1, one reply per request by its path --- */

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
          rep.len == 0,
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
  free(rep.body);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/missing", port);
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 404 && !strcmp(rep.body, "nope"),
                   "a 404 is a reply: its status and body");
  char v[32];
  CTUI_TEST_ASSERT(
      ctui_wm_http_reply_header(&rep, "content-length", v, sizeof v) &&
          !strcmp(v, "4") && rep.headers == rep.body + 5 &&
          !ctui_wm_http_reply_header(&rep, "Location", v, sizeof v),
      "the reply's headers, after its body, looked up by name");
  free(rep.body);

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

int main(void) {
  ctui_log_init(E_ERR);
  test_urls();
  test_format();
  test_replies();
  test_decoder();
  test_exchanges();
  return ctui_test_summary();
}
