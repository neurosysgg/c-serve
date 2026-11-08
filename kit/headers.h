#ifndef CSERVE_HEADERS_H
#define CSERVE_HEADERS_H

#include "httpd.h"

#include <stddef.h>

/* A reply's headers by name, not by string: the ones an app sends, each
 * a CSERVE_HEADER (Content-Type and Content-Length are httpd's own,
 * from rep->type and the body). A value with a fixed vocabulary is an
 * enum of its own (CSERVE_CACHE). The security headers are the host's
 * (policy.h). */

typedef enum {
  CSERVE_H_CONTENT_LANGUAGE,
  CSERVE_H_CACHE_CONTROL,
  CSERVE_H_ETAG,
  CSERVE_H_VARY,
  CSERVE_H_ALLOW,
  CSERVE_H_LOCATION,
  CSERVE_H_SET_COOKIE,
  CSERVE_H_CONTENT_RANGE,
  CSERVE_H_ACCEPT_RANGES,
  CSERVE_H_X_ROBOTS_TAG,
  CSERVE_H_WWW_AUTHENTICATE,
  CSERVE_H_RETRY_AFTER,
  CSERVE_H_COUNT
} CSERVE_HEADER;

/* "Content-Language" */
const char *cserve_header_name(CSERVE_HEADER h);

/* "h: value" appended to rep->headers: 0, or -1 when value holds a CR,
 * an LF or a NUL (a header it would end and another it would start) or
 * the headers would outgrow their buffer -- the reply is a 500 then */
int cserve_header(CSERVE_HTTPD_REPLY *rep, CSERVE_HEADER h, const char *value);
/* whether rep has an h already (any case) */
int cserve_header_has(const CSERVE_HTTPD_REPLY *rep, CSERVE_HEADER h);

typedef enum {
  CSERVE_CACHE_NO_CACHE, /* keep it, but ask each time: no-cache */
  CSERVE_CACHE_NO_STORE, /* never keep it: no-store, private */
} CSERVE_CACHE;

const char *cserve_cache_value(CSERVE_CACHE c);

/* WWW-Authenticate: Basic realm="realm" on rep (BasicChallenge): 0, or
 * -1 when realm is empty or holds what qdtext doesn't -- a '"', a '\\',
 * a control, a byte past ASCII -- or the headers would outgrow their
 * buffer. A realm carrying a request's text has it through
 * cserve_rawurlencode() first. */
int cserve_basic_challenge(CSERVE_HTTPD_REPLY *rep, const char *realm);

/* s as rawurlencode() writes it (RFC 3986's unreserved kept, every other
 * byte %XX, upper-case) into out: 0, or -1 when it won't fit in cap */
int cserve_rawurlencode(const char *s, char *out, size_t cap);

#endif
