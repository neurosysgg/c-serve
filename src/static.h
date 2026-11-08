#ifndef CSERVE_STATIC_H
#define CSERVE_STATIC_H

#include "httpd.h"

#include <limits.h>

/* A web root's files, the way phpanta's public/.htaccess serves them: the
 * build stamp stripped (/assets/{js,css}/v-XXXXXXXX/), a real file served
 * as it is with its type, cache tier and ETag, and everything else left to
 * the front (an app's routes, the CGI). (ctui-wm's ctui-remote's routing,
 * made a host's.) */

typedef enum {
  CSERVE_STATIC_FRONT, /* not a file: the front's */
  CSERVE_STATIC_FILE,  /* a file served as it is */
  CSERVE_STATIC_BAD,   /* refused (400: a path that climbs out) */
} CSERVE_STATIC_KIND;

typedef struct {
  const char *root; /* the web root, realpath()'d */
  /* a "." or ".." segment: 0 refused (BAD), 1 the front's (its 404:
   * neurosys's conformance suite asks it of PHP) */
  int climb_front;
} CSERVE_STATIC;

typedef struct {
  CSERVE_STATIC_KIND kind;
  char file[PATH_MAX]; /* FILE: its real path */
  int immutable;       /* asked for under a build stamp (v-1234abcd) */
} CSERVE_STATIC_ROUTE;

/* path (decoded, from the request) under s->root: a real, regular file
 * inside the root (symlinks resolved) that isn't PHP and has no
 * dot-segment is a FILE (the stamp stripped first: immutable); "." and
 * ".." are BAD or the front's (s->climb_front); the rest is the front's,
 * "/" and directories too (no index files) */
void cserve_static_route(const CSERVE_STATIC *s, const char *path,
                         CSERVE_STATIC_ROUTE *out);
/* a file name's Content-Type, by its extension */
const char *cserve_static_mime(const char *file);
/* its Cache-Control ("" for none): .htaccess's tiers */
const char *cserve_static_cache(const char *file, int immutable);

/* whether an Accept-Encoding takes gzip: "gzip" or "x-gzip" (or "*")
 * listed with a q above 0, "identity" and the rest aside; NULL: no */
int cserve_static_accepts_gzip(const char *accept_encoding);

/* rt (a FILE) as the reply to r: GET and HEAD only (else 405), a weak
 * ETag (If-None-Match: 304), nosniff; read whole up to 8 MiB, streamed
 * past it. A file with a compressed copy beside it (FILE.gz, a regular
 * file and no symlink, no older than FILE: cserve-precompress makes
 * them) varies on Accept-Encoding, and a client that takes gzip gets the
 * copy -- Content-Encoding: gzip, the copy's own ETag. Nothing is ever
 * compressed per request: what a reply holds can't leak through its
 * size (BREACH), and no encoder runs on the server. */
void cserve_static_serve(const CSERVE_HTTPD_REQ *r,
                         const CSERVE_STATIC_ROUTE *rt,
                         CSERVE_HTTPD_REPLY *rep);

#endif
