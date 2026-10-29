#ifndef CSERVE_HTTPD_H
#define CSERVE_HTTPD_H

#include "conn.h"

#include <stddef.h>

/* The server side's HTTP/1.1: a request's head parsed (pure: the tests
 * and the fuzzer take it on buffers), its body read by Content-Length (a
 * chunked request body is refused: 411), a reply written, and a
 * connection served request after request (keep-alive) with a handler
 * answering each. Origin-form targets only ("/path?query"). */

#define CSERVE_HTTPD_HEAD_MAX 16384 /* a request's head, all of it */
#define CSERVE_HTTPD_HEADERS 64

typedef struct {
  char method[16];
  char target[4096]; /* as sent */
  char path[4096];   /* the target's path, percent-decoded ("/a b") */
  const char *query; /* in target, after '?' ("" if none) */
  int minor;         /* HTTP/1.minor */
  int n;
  struct {
    const char *name, *value; /* in the parsed head, trimmed */
  } h[CSERVE_HTTPD_HEADERS];
  long long length; /* Content-Length, -1 none */
  int keep_alive;   /* the client wants the connection kept */
  /* set by serve() (parse() leaves them NULL): the peer's address as
   * text, the connection (its TLS peer: cserve_conn_peer_cert()) */
  const char *peer;
  CSERVE_CONN *conn;
} CSERVE_HTTPD_REQ;

/* the head (buf: its lines up to and without the blank line, NUL-
 * terminated; the request keeps pointers into it, and it's cut up in
 * place) into r: 0, or an HTTP status to refuse it with (400, 411, 414,
 * 431, 501, 505) and why in err */
int cserve_httpd_parse(char *buf, CSERVE_HTTPD_REQ *r, char *err,
                       size_t err_cap);
/* header name's value (case-insensitive name, the first one), or NULL */
const char *cserve_httpd_header(const CSERVE_HTTPD_REQ *r, const char *name);
/* status's reason phrase ("Not Found"; "" for one it doesn't know) */
const char *cserve_httpd_reason(int status);

/* a streamed body's writer (stream() below): n bytes of it out at once,
 * as one chunk: 0, or -1 once the client is gone (later calls do
 * nothing) */
typedef struct CSERVE_HTTPD_OUT CSERVE_HTTPD_OUT;
int cserve_httpd_out(CSERVE_HTTPD_OUT *o, const char *buf, size_t n);

/* what a handler answers: status, the body (len bytes; free it if
 * owned), its Content-Type, extra header lines (each ending in CRLF; may
 * be NULL). Or, with stream set, a body of unknown length: called once
 * after the head is sent (always, also when it wasn't, or the reply has
 * no body: its writes fail or are dropped then; it frees stream_ud), it
 * writes the body through o and returns 0 when all of it went, -1 if it
 * failed part-way; out chunked (HTTP/1.1, the connection kept) or until
 * the connection closes (HTTP/1.0). */
typedef struct {
  int status;
  const char *type;
  char *body;
  size_t len;
  int owned; /* body is malloc'd: freed after it's sent */
  char headers[4096];
  int (*stream)(CSERVE_HTTPD_OUT *o, void *stream_ud);
  void *stream_ud;
} CSERVE_HTTPD_REPLY;

/* the reply's text as body: a copy (owned), or a 500 */
void cserve_httpd_text(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       const char *body, size_t len);

/* one request's handler: r and its body (length bytes of it, NUL-
 * terminated; NULL without one) in, rep filled (status 0: a 500) */
typedef void (*CSERVE_HTTPD_FN)(const CSERVE_HTTPD_REQ *r, const char *body,
                                CSERVE_HTTPD_REPLY *rep, void *ud);

typedef struct {
  CSERVE_HTTPD_FN handler;
  void *ud;
  const char *server; /* the Server header ("" or NULL: none) */
  long long body_max; /* a request body's limit (413 past it; 1 MiB) */
  int idle_ms;        /* waiting for the next request (10 s) */
  int timeout_ms;     /* reading one, writing its reply (30 s) */
  int max_requests;   /* on one connection (100) */
} CSERVE_HTTPD;

/* c served until the client closes, a request asks to, a limit is hit or
 * something fails; c closed then. peer is logged only. */
void cserve_httpd_serve(const CSERVE_HTTPD *h, CSERVE_CONN *c,
                        const char *peer);

/* s handed to add with &<>"' as entities (HTML text or an attribute
 * value), a run at a time: whatever buffer the caller keeps */
void cserve_httpd_escape(void (*add)(void *ctx, const char *s, size_t n),
                         void *ctx, const char *s);
/* body (malloc'd, len bytes; NULL: none) as the reply's, handed over */
void cserve_httpd_take(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       char *body, size_t len);

#endif
