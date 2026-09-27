/* plugins/net: URLs, the request, replies (Content-Length, chunked, to the
 * end, interim 1xx, cut off), then whole exchanges over plain HTTP with a
 * server forked on 127.0.0.1 -- a redirect, a chunked reply, a POST, a
 * server that never answers (the deadline), one too big. TLS itself runs
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
    const char *rep = reply_for(req);
    if (!rep) {
      sleep(5);
    } else {
      send(c, rep, strlen(rep), MSG_NOSIGNAL);
    }
    close(c);
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
  free(rep.body);

  snprintf(url, sizeof url, "http://127.0.0.1:%d/missing", port);
  CTUI_TEST_ASSERT(ctui_wm_net_http(&req, &rep, g_err, sizeof g_err) == 0 &&
                       rep.status == 404 && !strcmp(rep.body, "nope"),
                   "a 404 is a reply: its status and body");
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
  test_exchanges();
  return ctui_test_summary();
}
