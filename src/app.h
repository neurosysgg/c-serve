#ifndef CSERVE_APP_H
#define CSERVE_APP_H

#include "policy.h"
#include "route.h"
#include "tarpit.h"

#include <stddef.h>

/* An app: what a site is to the host (docs/research/c-serve.md "Apps" in
 * neurosys). One vtable, exported as `cserve_app_<name>`: a development
 * host dlopen()s apps/<name>.so and looks it up, a production host is
 * linked with the apps it serves (a generated table) and loads nothing.
 *
 * The ABI, ctui-wm's plugin.h's way: abi and size first; slots are only
 * ever appended, so a host reads a slot past an app's size as NULL (an
 * older app) and refuses an app whose abi isn't its own. NULL in any slot
 * means not implemented. */

#define CSERVE_APP_ABI 2

/* what the host hands an app's init() */
typedef struct {
  const char *root; /* the web root (realpath()'d) */
  const char *data; /* the app's data directory (--data); NULL: none */
  /* the host's tarpit (tarpit.h; kit/tarpit.h takes it); NULL: off
   * (--no-tarpit, or a host without one) */
  const CSERVE_TARPIT_API *tarpit;
} CSERVE_APP_ENV;

typedef struct CSERVE_APP {
  int abi;          /* CSERVE_APP_ABI */
  size_t size;      /* sizeof(CSERVE_APP) when it was built */
  const char *name; /* "hello": its symbol is cserve_app_hello */
  /* before the first request: 0, or -1 with why in err (the host stops) */
  int (*init)(const CSERVE_APP_ENV *env, char *err, size_t err_cap);
  /* its routes, tried in order after the static files, before the CGI */
  const CSERVE_ROUTE *routes;
  int nroutes;
  /* after the last request */
  void (*fini)(void);
  /* what its pages load from elsewhere: the host builds its security
   * headers of it once and puts them first on every reply this app
   * answers (policy.h); NULL: none */
  const CSERVE_SECURITY *security;
  /* a request no route of any app fits, when there's no front (--cgi)
   * to hand it to: the first app's with one answers it; NULL: the host's
   * plain 404 */
  void (*not_found)(const CSERVE_HTTPD_REQ *r, const char *body,
                    CSERVE_HTTPD_REPLY *rep);
  /* a request one of its routes' patterns fits but none of their methods
   * does: allow is those methods (CSERVE_GET | ...; cserve_route_allow_
   * text() spells them), and the app answers -- its own 405, an OPTIONS's
   * 204. NULL: the router's plain 405 with Allow */
  void (*refuse)(const CSERVE_HTTPD_REQ *r, const char *body, unsigned allow,
                 CSERVE_HTTPD_REPLY *rep);
} CSERVE_APP;

#define CSERVE_APP_HEADER(n)                                                   \
  .abi = CSERVE_APP_ABI, .size = sizeof(CSERVE_APP), .name = (n)

/* app's slot, or NULL when it's past what app was built with (slots are
 * appended whole: one that starts inside size is all there) */
#define CSERVE_APP_SLOT(app, slot)                                             \
  (offsetof(CSERVE_APP, slot) < (app)->size ? (app)->slot : NULL)

#endif
