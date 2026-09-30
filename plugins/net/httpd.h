#ifndef CTUI_WM_NET_HTTPD_H
#define CTUI_WM_NET_HTTPD_H

#include "conn.h"

#include "base/json.h"

#include <stddef.h>

/* The server side's HTTP/1.1: a request's head parsed (pure: the tests
 * and the fuzzer take it on buffers), its body read by Content-Length (a
 * chunked request body is refused: 411), a reply written, and a
 * connection served request after request (keep-alive) with a handler
 * answering each. Origin-form targets only ("/path?query"). */

#define CTUI_WM_HTTPD_HEAD_MAX 16384 /* a request's head, all of it */
#define CTUI_WM_HTTPD_HEADERS 64

typedef struct {
  char method[16];
  char target[4096]; /* as sent */
  char path[4096];   /* the target's path, percent-decoded ("/a b") */
  const char *query; /* in target, after '?' ("" if none) */
  int minor;         /* HTTP/1.minor */
  int n;
  struct {
    const char *name, *value; /* in the parsed head, trimmed */
  } h[CTUI_WM_HTTPD_HEADERS];
  long long length; /* Content-Length, -1 none */
  int keep_alive;   /* the client wants the connection kept */
} CTUI_WM_HTTPD_REQ;

/* the head (buf: its lines up to and without the blank line, NUL-
 * terminated; the request keeps pointers into it, and it's cut up in
 * place) into r: 0, or an HTTP status to refuse it with (400, 411, 414,
 * 431, 501, 505) and why in err */
int ctui_wm_httpd_parse(char *buf, CTUI_WM_HTTPD_REQ *r, char *err,
                        size_t err_cap);
/* header name's value (case-insensitive name, the first one), or NULL */
const char *ctui_wm_httpd_header(const CTUI_WM_HTTPD_REQ *r, const char *name);
/* status's reason phrase ("Not Found"; "" for one it doesn't know) */
const char *ctui_wm_httpd_reason(int status);

/* what a handler answers: status, the body (len bytes; free it if
 * owned), its Content-Type, extra header lines (each ending in CRLF; may
 * be NULL) */
typedef struct {
  int status;
  const char *type;
  char *body;
  size_t len;
  int owned; /* body is malloc'd: freed after it's sent */
  char headers[1024];
} CTUI_WM_HTTPD_REPLY;

/* the reply's text as body: a copy (owned), or a 500 */
void ctui_wm_httpd_text(CTUI_WM_HTTPD_REPLY *rep, int status, const char *type,
                        const char *body, size_t len);

/* one request's handler: r and its body (length bytes of it, NUL-
 * terminated; NULL without one) in, rep filled (status 0: a 500) */
typedef void (*CTUI_WM_HTTPD_FN)(const CTUI_WM_HTTPD_REQ *r, const char *body,
                                 CTUI_WM_HTTPD_REPLY *rep, void *ud);

typedef struct {
  CTUI_WM_HTTPD_FN handler;
  void *ud;
  const char *server; /* the Server header ("" or NULL: none) */
  long long body_max; /* a request body's limit (413 past it; 1 MiB) */
  int idle_ms;        /* waiting for the next request (10 s) */
  int timeout_ms;     /* reading one, writing its reply (30 s) */
  int max_requests;   /* on one connection (100) */
} CTUI_WM_HTTPD;

/* c served until the client closes, a request asks to, a limit is hit or
 * something fails; c closed then. peer is logged only. */
void ctui_wm_httpd_serve(const CTUI_WM_HTTPD *h, CTUI_WM_CONN *c,
                         const char *peer);

/* s appended to b with &<>"' as entities (HTML text or an attribute
 * value) */
void ctui_wm_httpd_escape(CTUI_WM_BUF *b, const char *s);
/* b's text as the reply's body (b's memory handed over, b emptied) */
void ctui_wm_httpd_take(CTUI_WM_HTTPD_REPLY *rep, int status, const char *type,
                        CTUI_WM_BUF *b);

#endif
