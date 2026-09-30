#ifndef CTUI_WM_NET_HTTP_H
#define CTUI_WM_NET_HTTP_H

#include "base/plugin.h"

#include <stddef.h>

/* The pure half of the net plugin's HTTP/1.1 client: URLs, the request
 * and the reply, on buffers (no sockets here, so the tests and the fuzzer
 * take it as it is). A reply (the request says "Connection: close") is
 * decoded as it arrives: status line, headers, then the body by
 * Content-Length, chunked, or up to the end. */

typedef struct {
  int tls;         /* https */
  char host[256];  /* without brackets for an IPv6 literal */
  char port[8];    /* "443", "80", or the URL's own */
  char path[4096]; /* from the first '/' (query included; "/" if none);
                    * the fragment dropped */
} CTUI_WM_URL;

/* url ("http://" or "https://", no user:password@) into u: 0, or -1
 * with why in err */
int ctui_wm_url_parse(const char *url, CTUI_WM_URL *u, char *err,
                      size_t err_cap);

/* where a Location header value points, from the URL it came from:
 * absolute, "//host/..." or a path ("/x", or relative to base's folder).
 * 0, or -1 with why in err */
int ctui_wm_url_resolve(const CTUI_WM_URL *base, const char *loc,
                        CTUI_WM_URL *u, char *err, size_t err_cap);

/* u as a URL again ("https://host/path", the port only when it isn't
 * the scheme's own): 0, or -1 if it doesn't fit */
int ctui_wm_url_format(const CTUI_WM_URL *u, char *out, size_t cap);

/* the request for req to u, malloc'd into *out (its length in *len): 0,
 * or -1 (out of memory, or a header value with CR/LF in it) */
int ctui_wm_http_format(const CTUI_WM_HTTP_REQ *req, const CTUI_WM_URL *u,
                        char **out, size_t *len);

typedef struct {
  int status;
  const char *headers; /* the header lines (after the status line), up to
                        * the blank line; in the parsed buffer */
  size_t headers_len;
  char *body; /* malloc'd, NUL-terminated (chunked: decoded) */
  size_t len;
} CTUI_WM_HTTP_PARSED;

/* a whole reply (buf, n bytes, as read until the server closed): 0, or
 * -1 with why in err (a truncated reply is one: fewer bytes than its
 * Content-Length, a chunked body without its last chunk) */
int ctui_wm_http_parse(const char *buf, size_t n, CTUI_WM_HTTP_PARSED *out,
                       char *err, size_t err_cap);

/* header name's value (case-insensitive name, the first one) copied into
 * val, trimmed: 1, or 0 if there is none (or it doesn't fit) */
int ctui_wm_http_header(const CTUI_WM_HTTP_PARSED *p, const char *name,
                        char *val, size_t cap);
/* the same in a reply the client gave (the `net` slot's `header`) */
int ctui_wm_http_reply_header(const CTUI_WM_HTTP_REPLY *rep, const char *name,
                              char *val, size_t cap);

/* A reply decoded as it arrives, fed in pieces of any size: the status
 * line and headers gathered (interim 1xx replies skipped), then on_head()
 * called, then the body handed to on_body() decoded (Content-Length, chunked,
 * or up to the end). ctui_wm_http_parse() is this, fed once. */
typedef struct CTUI_WM_HTTP_DEC CTUI_WM_HTTP_DEC;
struct CTUI_WM_HTTP_DEC {
  /* non-zero from either stops the reply there (fed() then returns 1) */
  int (*on_head)(CTUI_WM_HTTP_DEC *d); /* optional */
  int (*on_body)(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n);
  void *ctx;
  /* once on_head() is called: */
  int status;
  const char *headers; /* the header lines, as in CTUI_WM_HTTP_PARSED */
  size_t headers_len;
  size_t head_at; /* where the reply (after interim ones) started in what
                   * was fed */
  /* the decoder's own */
  int state, stopped;
  char *head; /* the head so far (malloc'd) */
  size_t head_len, head_cap, fed;
  unsigned long long left; /* of the Content-Length, or of the chunk */
  char line[64];           /* a chunk's size line so far */
  size_t line_len;
};

/* d ready for a reply (the caller sets on_head, on_body and ctx after) */
void ctui_wm_http_dec_init(CTUI_WM_HTTP_DEC *d);
/* n more bytes: 0 = more wanted, 1 = the reply is complete (or stopped:
 * d->stopped; the bytes after its end are ignored), -1 with why in err
 * (not HTTP, a bad length or chunk) */
int ctui_wm_http_dec_feed(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n,
                          char *err, size_t err_cap);
/* the server closed: 0 if that ends the reply (a body read to the end),
 * or -1 with why in err (it ended inside its headers or body) */
int ctui_wm_http_dec_end(CTUI_WM_HTTP_DEC *d, char *err, size_t err_cap);
void ctui_wm_http_dec_free(CTUI_WM_HTTP_DEC *d);

#endif
