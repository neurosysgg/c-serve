#ifndef CSERVE_PAGE_H
#define CSERVE_PAGE_H

#include "arena.h"
#include "headers.h"
#include "httpd.h"
#include "markup.h"
#include "text.h"

/* A page answered (phpanta's ViewResponse): the request's language
 * negotiated, the view rendered -- inside the app's shell, or, for the
 * SPA's own fetch (X-Requested-With), as a fragment of its <title> and
 * its content alone -- and the reply made of it:
 *
 *   Content-Type: text/html; charset=utf-8
 *   Content-Language: <the language>
 *   Cache-Control: no-cache          unless the caller set one
 *   ETag: "<hex of the body>"        for a 2xx with no Cache-Control of
 *                                    the caller's
 *   Vary: X-Requested-With, Accept-Language, Cookie
 *
 * and a 304 with only Cache-Control, ETag and Vary when the request's
 * If-None-Match holds that ETag. The fragment and the document, and each
 * language, are different bytes and so different validators. */

typedef struct {
  const CSERVE_TR *title;     /* the page's <title> */
  const CSERVE_NODE *content; /* what goes into <main id="content"> */
} CSERVE_VIEW;

/* the document around a view, in language lang */
typedef const CSERVE_NODE *(*CSERVE_SHELL_FN)(CSERVE_ARENA *a,
                                              const CSERVE_VIEW *v, int lang,
                                              void *ud);

typedef struct {
  const CSERVE_LANGUAGES *languages;
  const char *cookie; /* the language switch's cookie ("lang"); NULL: none */
  CSERVE_SHELL_FN shell;
  void *ud;
} CSERVE_SITE;

/* the request's language (Request::language()): the cookie when it
 * names one offered exactly, else Accept-Language's choice, else the
 * default */
int cserve_page_language(const CSERVE_SITE *site, const CSERVE_HTTPD_REQ *r);

/* v answered with status into rep (whose headers the caller may have
 * started: a Cache-Control there is kept, and the page isn't validated).
 * A tree that fails to render, or an arena that failed while it was
 * built, is a 500 with why in the log. */
void cserve_page(const CSERVE_SITE *site, const CSERVE_HTTPD_REQ *r,
                 CSERVE_ARENA *a, const CSERVE_VIEW *v, int status,
                 CSERVE_HTTPD_REPLY *rep);

/* the body's validator: the hex of the first 16 bytes of its SHA-256,
 * into out (33 bytes) */
void cserve_page_fingerprint(const char *body, size_t len, char out[33]);

#endif
