#ifndef CSERVE_POLICY_H
#define CSERVE_POLICY_H

#include <stddef.h>

/* The security headers an app's replies carry (phpanta's
 * SecurityHeaders), as data: an app names what it loads from elsewhere
 * (its CSERVE_APP's security slot), and the host builds the lines once
 * and puts them first on every reply that app answers. A static file
 * gets none, as under Apache. */

/* what the page loads from other origins, per CSP directive: NULL-ended
 * lists of sources ("https://w.soundcloud.com"); NULL: none. The rest of
 * the policy is fixed: 'self' for scripts, styles and images, frames
 * from no one but those named, nothing framing the page, no base, form
 * or plugin anywhere else. */
typedef struct {
  const char *const *script,
      *const *style, *const *img, *const *frame, *const *connect, *const *media,
                                                                      *const
                                                                          *font;
} CSERVE_SECURITY;

/* p's header lines, each ending in CRLF, into out (cap bytes): HSTS, the
 * CSP, Referrer-Policy, X-Content-Type-Options, Permissions-Policy,
 * COOP, CORP -- phpanta's values, in its order. 0, or -1 with why in err
 * (a source that isn't one word, or out too small). */
int cserve_security_headers(const CSERVE_SECURITY *p, char *out, size_t cap,
                            char *err, size_t err_cap);

#endif
