#ifndef CSERVE_HTTP_TYPES_H
#define CSERVE_HTTP_TYPES_H

#include <stddef.h>

/* The HTTP client's request and reply (net.h): what a caller fills in and
 * what comes back. Kept apart from net.h so a host's plugin table can name
 * them without the client's functions (ctui-wm's `net` slot does). */

typedef struct {
  const char *method; /* NULL: "GET" */
  const char *url;    /* http:// or https:// */
  /* a body to send (POST), with its type; NULL: none */
  const char *content_type;
  const char *body;
  size_t body_len;
  const char *const *headers; /* extra "Name: value" lines, NULL-ended;
                               * NULL: none */
  int timeout_ms;             /* the whole exchange, redirects included;
                               * 0: 30 s */
  size_t max;                 /* the most a reply may be; 0: 8 MiB */
  /* while http() gathers a reply's body: its bytes so far and its
   * Content-Length (0: not said), on the calling thread, after each
   * read; NULL: not wanted. A redirect's body isn't counted. */
  void (*progress)(void *ctx, size_t got, size_t total);
  void *progress_ctx;
  /* cookies (ctui-web's jar), on the calling thread: before each request
   * (a redirect's too) the Cookie header's value for its URL into out
   * (its length; 0 = none), and each reply's header lines (a redirect's
   * too) handed over with the URL they answered; NULL: none */
  size_t (*cookie)(void *ctx, const char *url, char *out, size_t cap);
  void (*replied)(void *ctx, const char *url, const char *headers, size_t len);
  void *cookie_ctx;
  const char *agent; /* the User-Agent; NULL: CSERVE_HTTP_AGENT */
  /* each redirect's next address, before it's asked (ctui-web's lists),
   * on the calling thread: 0 follows it -- as it is, or as rewritten into
   * out (cap bytes; left "" = as it is); non-zero stops there, the
   * request failing with why (why_cap bytes). NULL: all followed */
  int (*hop)(void *ctx, const char *url, char *out, size_t cap, char *why,
             size_t why_cap);
  void *hop_ctx;
} CSERVE_HTTP_REQ;

typedef struct {
  int status; /* the last reply's (after redirects) */
  char *body; /* malloc'd, NUL-terminated: free() it (the headers too) */
  size_t len;
  /* the last reply's header lines ("Name: value" each ending in CRLF or
   * LF), in body's allocation after it; header() looks one up */
  const char *headers;
  size_t headers_len;
  /* where the reply came from when redirects moved it (the fragment
   * dropped), in body's allocation after the headers; NULL: req->url */
  const char *url;
} CSERVE_HTTP_REPLY;

/* where http_stream() hands a reply as it arrives */
typedef struct {
  /* the last reply's status and headers are in rep (its body ""), before
   * any of the body; optional. Non-zero stops (http_stream() returns 0) */
  int (*head)(void *ctx, const CSERVE_HTTP_REPLY *rep);
  /* the next piece of the body, decoded. Non-zero stops */
  int (*body)(void *ctx, const char *buf, size_t n);
  void *ctx;
} CSERVE_HTTP_SINK;

#endif
