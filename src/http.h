#ifndef CSERVE_HTTP_H
#define CSERVE_HTTP_H

#include "http_types.h"

#include <stddef.h>

/* the User-Agent a request that names none sends; a host may say its own
 * with -DCSERVE_HTTP_AGENT='"name"' */
#ifndef CSERVE_HTTP_AGENT
#define CSERVE_HTTP_AGENT "c-serve"
#endif

/* The pure half of the HTTP/1.1 client (net.h): URLs, the request
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
} CSERVE_URL;

/* url ("http://" or "https://", no user:password@) into u: 0, or -1
 * with why in err */
int cserve_url_parse(const char *url, CSERVE_URL *u, char *err, size_t err_cap);

/* where a Location header value points, from the URL it came from:
 * absolute, "//host/..." or a path ("/x", or relative to base's folder).
 * 0, or -1 with why in err */
int cserve_url_resolve(const CSERVE_URL *base, const char *loc, CSERVE_URL *u,
                       char *err, size_t err_cap);

/* u as a URL again ("https://host/path", the port only when it isn't
 * the scheme's own): 0, or -1 if it doesn't fit */
int cserve_url_format(const CSERVE_URL *u, char *out, size_t cap);

/* the request for req to u, malloc'd into *out (its length in *len): 0,
 * or -1 (out of memory, or a header value with CR/LF in it). coded: the
 * reply may come gzip'd or deflated (coding.h undoes it), else as it is;
 * an Accept-Encoding in req's own headers is left to say it. The
 * connection is asked to stay open (HTTP/1.1's default). */
int cserve_http_format(const CSERVE_HTTP_REQ *req, const CSERVE_URL *u,
                       int coded, char **out, size_t *len);

/* whether req's own headers have name (case-insensitive) */
int cserve_http_req_has(const CSERVE_HTTP_REQ *req, const char *name);

typedef struct {
  int status;
  const char *headers; /* the header lines (after the status line), up to
                        * the blank line; in the parsed buffer */
  size_t headers_len;
  char *body; /* malloc'd, NUL-terminated (chunked: decoded) */
  size_t len;
} CSERVE_HTTP_PARSED;

/* a whole reply (buf, n bytes, as read until the server closed): 0, or
 * -1 with why in err (a truncated reply is one: fewer bytes than its
 * Content-Length, a chunked body without its last chunk) */
int cserve_http_parse(const char *buf, size_t n, CSERVE_HTTP_PARSED *out,
                      char *err, size_t err_cap);

/* header name's value (case-insensitive name, the first one) copied into
 * val, trimmed: 1, or 0 if there is none (or it doesn't fit) */
int cserve_http_header(const CSERVE_HTTP_PARSED *p, const char *name, char *val,
                       size_t cap);
/* the same in a reply the client gave: name's value (any case, the first;
 * trimmed) copied into val: 1, or 0 if there is none (or it doesn't fit) */
int cserve_http_reply_header(const CSERVE_HTTP_REPLY *rep, const char *name,
                             char *val, size_t cap);

/* A reply decoded as it arrives, fed in pieces of any size: the status
 * line and headers gathered (interim 1xx replies skipped), then on_head()
 * called, then the body handed to on_body() decoded (Content-Length, chunked,
 * or up to the end); a chunked one's trailers are read and dropped.
 * cserve_http_parse() is this, fed once. */
typedef struct CSERVE_HTTP_DEC CSERVE_HTTP_DEC;
struct CSERVE_HTTP_DEC {
  /* non-zero from either stops the reply there (fed() then returns 1) */
  int (*on_head)(CSERVE_HTTP_DEC *d); /* optional */
  int (*on_body)(CSERVE_HTTP_DEC *d, const char *buf, size_t n);
  void *ctx;
  int no_body; /* set before feeding: a HEAD's reply, no body whatever
                * its headers say */
  /* once on_head() is called: */
  int status;
  int keep; /* the server keeps the connection open after this reply */
  const char *headers; /* the header lines, as in CSERVE_HTTP_PARSED */
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
void cserve_http_dec_init(CSERVE_HTTP_DEC *d);
/* n more bytes: 0 = more wanted, 1 = the reply is complete (or stopped:
 * d->stopped; the bytes after its end are ignored), -1 with why in err
 * (not HTTP, a bad length or chunk) */
int cserve_http_dec_feed(CSERVE_HTTP_DEC *d, const char *buf, size_t n,
                         char *err, size_t err_cap);
/* the server closed: 0 if that ends the reply (a body read to the end),
 * or -1 with why in err (it ended inside its headers or body) */
int cserve_http_dec_end(CSERVE_HTTP_DEC *d, char *err, size_t err_cap);
void cserve_http_dec_free(CSERVE_HTTP_DEC *d);
/* the reply came whole, by its own length, and the server keeps the
 * connection: the next request can go on it (the caller checks that
 * nothing came after the reply: everything fed was d->fed) */
int cserve_http_dec_reusable(const CSERVE_HTTP_DEC *d);

#endif
