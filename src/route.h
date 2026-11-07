#ifndef CSERVE_ROUTE_H
#define CSERVE_ROUTE_H

#include "httpd.h"

#include <stddef.h>

/* An app's routes: a path pattern and the methods it answers, matched
 * against a request's decoded path. A pattern is segments: a literal
 * ("releases"), a {name} that takes one segment, or a last "*" that takes
 * the rest (none or more; its value without the leading '/'). A capture
 * never takes a segment starting with '.', so "..", "." and dotfiles
 * reach no handler. Empty segments count for nothing on either side
 * ("//a//" is "/a"), as in static.c. */

enum {
  CSERVE_GET = 1 << 0, /* and HEAD: the same reply, its body dropped */
  CSERVE_HEAD = 1 << 1,
  CSERVE_POST = 1 << 2,
  CSERVE_PUT = 1 << 3,
  CSERVE_PATCH = 1 << 4,
  CSERVE_DELETE = 1 << 5,
  CSERVE_OPTIONS = 1 << 6,
};

#define CSERVE_ROUTE_PARAMS 8

typedef struct {
  int n;
  struct {
    const char *name, *value; /* both NUL-terminated, in store */
  } p[CSERVE_ROUTE_PARAMS];
  char store[4096];
} CSERVE_ROUTE_MATCH;

typedef void (*CSERVE_ROUTE_FN)(const CSERVE_HTTPD_REQ *r, const char *body,
                                const CSERVE_ROUTE_MATCH *m,
                                CSERVE_HTTPD_REPLY *rep);

typedef struct {
  unsigned methods;    /* CSERVE_GET | ... */
  const char *pattern; /* "/releases/{slug}/{format}" */
  CSERVE_ROUTE_FN fn;
} CSERVE_ROUTE;

/* a method's bit ("GET": CSERVE_GET), 0 for one that isn't listed */
unsigned cserve_route_method(const char *method);

/* whether path fits pattern: 1 with m's captures, else 0 (a pattern with
 * more than CSERVE_ROUTE_PARAMS captures, or captures past m's store,
 * fits nothing) */
int cserve_route_match(const char *pattern, const char *path,
                       CSERVE_ROUTE_MATCH *m);

/* a capture's value ("slug"), or NULL */
const char *cserve_route_param(const CSERVE_ROUTE_MATCH *m, const char *name);

/* the first of routes (n of them) whose pattern and method fit r: its
 * index, with m its captures; or -1, with *allow the methods the patterns
 * that fit take (0: none fits) */
int cserve_route_find(const CSERVE_ROUTE *routes, int n,
                      const CSERVE_HTTPD_REQ *r, CSERVE_ROUTE_MATCH *m,
                      unsigned *allow);

/* allow as an Allow header's value ("GET, HEAD, POST", in the order the
 * methods are listed above) into out (cap bytes; 64 hold them all) */
void cserve_route_allow_text(unsigned allow, char *out, size_t cap);

/* r against routes (n of them), in order: 1 when one answered -- the first
 * whose pattern and method fit, or a 405 with Allow when patterns fit but
 * no method does -- 0 when no pattern fits (the next in line's) */
int cserve_route_dispatch(const CSERVE_ROUTE *routes, int n,
                          const CSERVE_HTTPD_REQ *r, const char *body,
                          CSERVE_HTTPD_REPLY *rep);

#endif
