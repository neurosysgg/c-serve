#ifndef CSERVE_READING_H
#define CSERVE_READING_H

#include "httpd.h"

#include <stddef.h>

/* What an app reads out of a request beyond its path: a query parameter,
 * a cookie, the language it prefers, whether its copy is current, the
 * bytes it asks for, whether it's the SPA's own fetch. Each is phpanta's
 * reading of the same thing, rule for rule (the PHP named on each), and
 * each is pure on strings: a header the request lacks is NULL, and NULL
 * reads as absent everywhere. */

/* whether s (n bytes) is UTF-8: shortest forms, no surrogates, nothing
 * past U+10FFFF (mb_check_encoding's) */
int cserve_utf8_valid(const char *s, size_t n);

/* name's value in a query ("a=1&b=two+words", without the '?'; Input::
 * fromUrlEncoded): '&'-separated pairs, each split at its first '=' (none:
 * an empty value), '+' a space, %XX a byte (a '%' without two hex digits
 * is itself). 0 with the value in out, 1 if it isn't there, -1 with why
 * in err if the query can't be read -- a name or value anywhere in it
 * that isn't UTF-8, name sent more than once, a value past cap: a 400. */
int cserve_query_get(const char *query, const char *name, char *out, size_t cap,
                     char *err, size_t err_cap);

/* name's value in a Cookie header (RequestCookies): ';'-separated pairs,
 * the first whose trimmed name is name exactly; the value trimmed, one
 * pair of double quotes around it dropped, nothing decoded. 0 with it in
 * out, 1 if it isn't there, -1 if it's longer than cap allows. */
int cserve_cookie_get(const char *cookie, const char *name, char *out,
                      size_t cap);

/* which of offered (n primary subtags, lower-case, the default first) an
 * Accept-Language header prefers (AcceptedLanguages, QualityValue): the
 * primary subtag of each range ("de-AT": "de"), its weight (q=, 1 when
 * not said; one past q's grammar drops the entry), a range said twice
 * worth the better of the two; a language not named is worth what "*" is,
 * and one named at q=0 is worth nothing whatever "*" says. A later
 * language wins only when it's worth strictly more: a tie, and a header
 * that's absent or says nothing, is the default (0). */
int cserve_accept_language(const char *header, const char *const *offered,
                           int n);

/* whether an If-None-Match header matches a validator (ETag.php):
 * "*" alone matches; otherwise each "..." in it, W/ or not, with a
 * trailing -gzip, -br or -deflate inside the quotes taken off (what a
 * compressing proxy appends), against fingerprint (without its quotes) */
int cserve_etag_matches(const char *if_none_match, const char *fingerprint);

/* whether X-Requested-With says XMLHttpRequest, in any case: the SPA's
 * own fetch, which is answered with a fragment */
int cserve_requested_xhr(const CSERVE_HTTPD_REQ *r);

typedef enum {
  CSERVE_RANGE_NONE,        /* no range, or one this doesn't read: 200 */
  CSERVE_RANGE_PARTIAL,     /* first..last, both inside the file: 206 */
  CSERVE_RANGE_UNSATISFIED, /* well formed, the file too short: 416 */
} CSERVE_RANGE;

/* a Range header against a file of size bytes (ByteRange.php): one
 * range, "bytes=a-b", "bytes=a-" or "bytes=-n" (the last n), any case;
 * a list, anything malformed, a number past what a long long holds, or
 * b before a is NONE. b past the end is the end; -0 asks for nothing,
 * which is UNSATISFIED; a suffix of an empty file is NONE (the whole of
 * nothing). first and last are set for PARTIAL. */
CSERVE_RANGE cserve_range(const char *header, long long size, long long *first,
                          long long *last);

/* the user and password an Authorization header carries in Basic
 * (AuthScheme::credentials): "Basic", any case, one or more spaces, then
 * base64 as PHP's strict base64_decode() reads it (whitespace stepped
 * over, padding optional but never wrong), split at its first ':' -- none
 * is a user with no password. 0 with both written, 1 with both empty: no
 * Basic credential, one that doesn't decode, holds a NUL, or won't fit.
 * Either way the caller compares: an empty password matches no digest. */
int cserve_basic_credentials(const char *authorization, char *user,
                             size_t user_cap, char *pass, size_t pass_cap);

#endif
