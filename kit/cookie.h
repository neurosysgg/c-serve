#ifndef CSERVE_COOKIE_H
#define CSERVE_COOKIE_H

#include "httpd.h"

#include <stddef.h>

/* A Set-Cookie an app can't get wrong: always Secure, Path=/ and no
 * Domain, so a "__Host-" name is what the browser takes it for; HttpOnly
 * unless asked otherwise; SameSite Strict or Lax; Max-Age or a session
 * cookie. A name that isn't an RFC 6265 token, or a value with a byte a
 * cookie-octet isn't (space, '"', ',', ';', '\', a control byte), is
 * refused, never escaped. */

typedef enum { CSERVE_SAMESITE_STRICT, CSERVE_SAMESITE_LAX } CSERVE_SAMESITE;

enum {
  CSERVE_COOKIE_SCRIPT = 1, /* readable by script: no HttpOnly */
};

/* name=value on rep (max_age seconds; < 0: a session cookie): 0, or -1
 * (a bad name or value, or no room in rep's headers) */
int cserve_cookie_set(CSERVE_HTTPD_REPLY *rep, const char *name,
                      const char *value, long max_age, CSERVE_SAMESITE same,
                      unsigned flags);
/* name dropped: an empty value that expired already: 0, or -1 */
int cserve_cookie_clear(CSERVE_HTTPD_REPLY *rep, const char *name,
                        CSERVE_SAMESITE same);
/* 1 when s is a cookie name (an RFC 6265 token), else 0 */
int cserve_cookie_name_ok(const char *s);
/* 1 when s (n bytes) is a cookie value (cookie-octets only), else 0 */
int cserve_cookie_value_ok(const char *s, size_t n);

#endif
