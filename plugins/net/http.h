#ifndef CTUI_WM_NET_HTTP_H
#define CTUI_WM_NET_HTTP_H

#include "base/plugin.h"

#include <stddef.h>

/* The pure half of the net plugin's HTTP/1.1 client: URLs, the request
 * and the reply, on buffers (no sockets here, so the tests and the fuzzer
 * take it as it is). A reply is read whole (the request says
 * "Connection: close") and parsed at once: status line, headers, then
 * the body by Content-Length, chunked, or up to the end. */

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

#endif
