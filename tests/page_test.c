/* kit/page.c: a view answered as ViewResponse answers it -- the document
 * or, for the SPA's fetch, the fragment; the language from the cookie
 * before Accept-Language; Content-Language, Cache-Control, ETag and Vary;
 * a 304 for the copy the client holds, never for a 404; a tree that
 * won't render a 500 */
#include "html.h"
#include "page.h"

#include "test.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const CSERVE_LANGUAGES LANGS = {{"en", "de"}, 2};
static const CSERVE_TEXT TITLE = CSERVE_TEXT_IN("home", "start");
static const CSERVE_TEXT WORD = CSERVE_TEXT_IN("hello", "hallo");

static const CSERVE_NODE *shell(CSERVE_ARENA *a, const CSERVE_VIEW *v, int lang,
                                void *ud) {
  (void)ud;
  return cserve_document(
      a,
      cserve_containing(
          a,
          cserve_attr(a, cserve_el(a, &cserve_tag_html), &cserve_attr_lang,
                      LANGS.tags[lang]),
          cserve_containing(a, cserve_el(a, &cserve_tag_head),
                            cserve_containing(a,
                                              cserve_el(a, &cserve_tag_title),
                                              cserve_tr(a, v->title))),
          cserve_containing(
              a, cserve_el(a, &cserve_tag_body),
              cserve_containing(a,
                                cserve_attr(a, cserve_el(a, &cserve_tag_main),
                                            &cserve_attr_id, "content"),
                                v->content))));
}

static const CSERVE_SITE SITE = {&LANGS, "lang", shell, NULL};

/* a GET of / with headers (name, value, ..., NULL) */
static CSERVE_HTTPD_REQ request(const char *first, ...) {
  CSERVE_HTTPD_REQ r = {.method = "GET",
                        .target = "/",
                        .path = "/",
                        .query = "",
                        .minor = 1,
                        .length = -1};
  va_list ap;
  va_start(ap, first);
  for (const char *name = first; name && r.n < CSERVE_HTTPD_HEADERS;
       name = va_arg(ap, const char *)) {
    r.h[r.n].name = name;
    r.h[r.n++].value = va_arg(ap, const char *);
  }
  va_end(ap);
  return r;
}

/* r's page (with status, and the caller's headers before), its reply's
 * header named name's value (into v, "" if none) */
static void answer(const CSERVE_HTTPD_REQ *r, int status, const char *before,
                   CSERVE_HTTPD_REPLY *rep) {
  CSERVE_ARENA *a = cserve_arena_new();
  *rep = (CSERVE_HTTPD_REPLY){0};
  snprintf(rep->headers, sizeof rep->headers, "%s", before ? before : "");
  CSERVE_VIEW v = {&TITLE, cserve_containing(a, cserve_el(a, &cserve_tag_p),
                                             cserve_tr(a, &WORD))};
  cserve_page(&SITE, r, a, &v, status, rep);
  cserve_arena_free(a);
}

static const char *header(const CSERVE_HTTPD_REPLY *rep, const char *name,
                          char *v, size_t cap) {
  v[0] = '\0';
  size_t nl = strlen(name);
  for (const char *p = rep->headers; *p;) {
    const char *e = strstr(p, "\r\n");
    if (!e) {
      break;
    }
    if (!strncmp(p, name, nl) && p[nl] == ':') {
      snprintf(v, cap, "%.*s", (int)(e - p - nl - 2), p + nl + 2);
      return v;
    }
    p = e + 2;
  }
  return v;
}

static void done(CSERVE_HTTPD_REPLY *rep) {
  if (rep->owned) {
    free(rep->body);
  }
}

static void test_document_and_fragment(void) {
  CSERVE_HTTPD_REQ r = request(NULL);
  CSERVE_HTTPD_REPLY doc, frag;
  char v[256], etag[64], etag2[64];
  answer(&r, 200, NULL, &doc);
  CSERVE_TEST_ASSERT(
      doc.status == 200 && !strcmp(doc.type, "text/html; charset=utf-8") &&
          !strncmp(doc.body, "<!DOCTYPE html>\n<html lang=\"en\">", 32) &&
          strstr(doc.body, "<title>home</title>") &&
          strstr(doc.body, "<p>hello</p>"),
      "a page is its shell's document, in the default language");
  CSERVE_TEST_ASSERT(
      !strcmp(header(&doc, "Content-Language", v, sizeof v), "en") &&
          !strcmp(header(&doc, "Cache-Control", v, sizeof v), "no-cache") &&
          !strcmp(header(&doc, "Vary", v, sizeof v),
                  "X-Requested-With, Accept-Language, Cookie"),
      "Content-Language, Cache-Control: no-cache and the Vary");
  header(&doc, "ETag", etag, sizeof etag);
  CSERVE_TEST_ASSERT(strlen(etag) == 34 && etag[0] == '"' && etag[33] == '"',
                     "a strong validator of 32 hex digits (%s)", etag);
  r = request("X-Requested-With", "xmlhttprequest", NULL);
  answer(&r, 200, NULL, &frag);
  CSERVE_TEST_ASSERT(
      frag.body && !strcmp(frag.body, "<title>home</title>\n<p>hello</p>"),
      "the SPA's fetch gets the title and the content alone "
      "(\"%s\")",
      frag.body ? frag.body : "");
  header(&frag, "ETag", etag2, sizeof etag2);
  CSERVE_TEST_ASSERT(*etag2 && strcmp(etag, etag2),
                     "the fragment's validator isn't the document's");
  done(&doc);
  done(&frag);
}

static void test_language(void) {
  CSERVE_HTTPD_REPLY rep;
  char v[64];
  CSERVE_HTTPD_REQ r = request("Accept-Language", "de-AT, en;q=0.5", NULL);
  answer(&r, 200, NULL, &rep);
  CSERVE_TEST_ASSERT(
      strstr(rep.body, "<p>hallo</p>") &&
          strstr(rep.body, "<title>start</title>") &&
          !strcmp(header(&rep, "Content-Language", v, sizeof v), "de"),
      "Accept-Language chooses German");
  done(&rep);
  r = request("Accept-Language", "de", "Cookie", "theme=dark; lang=en", NULL);
  answer(&r, 200, NULL, &rep);
  CSERVE_TEST_ASSERT(strstr(rep.body, "<p>hello</p>"),
                     "the cookie wins over the header");
  done(&rep);
  r = request("Accept-Language", "de", "Cookie", "lang=DE", NULL);
  answer(&r, 200, NULL, &rep);
  CSERVE_TEST_ASSERT(strstr(rep.body, "<p>hallo</p>"),
                     "a cookie that names nothing offered falls through");
  done(&rep);
}

static void test_validation(void) {
  CSERVE_HTTPD_REQ r = request(NULL);
  CSERVE_HTTPD_REPLY rep;
  char etag[64], v[64], inm[80];
  answer(&r, 200, NULL, &rep);
  header(&rep, "ETag", etag, sizeof etag);
  done(&rep);
  snprintf(inm, sizeof inm, "W/%.*s-gzip\"", (int)strlen(etag) - 1, etag);
  r = request("If-None-Match", inm, NULL);
  answer(&r, 200, NULL, &rep);
  CSERVE_TEST_ASSERT(rep.status == 304 && !rep.len &&
                         !strcmp(header(&rep, "ETag", v, sizeof v), etag) &&
                         !*header(&rep, "Content-Language", v, sizeof v) &&
                         *header(&rep, "Vary", v, sizeof v),
                     "the copy the client holds: a 304, validator and Vary "
                     "only");
  done(&rep);
  r = request("If-None-Match", "*", NULL);
  answer(&r, 404, NULL, &rep);
  CSERVE_TEST_ASSERT(rep.status == 404 && rep.len &&
                         !*header(&rep, "ETag", v, sizeof v),
                     "a 404 has no validator and is never a 304");
  done(&rep);
  answer(&r, 200, "Cache-Control: no-store, private\r\n", &rep);
  CSERVE_TEST_ASSERT(rep.status == 200 && !*header(&rep, "ETag", v, sizeof v) &&
                         !strcmp(header(&rep, "Cache-Control", v, sizeof v),
                                 "no-store, private"),
                     "a page the caller says how to keep isn't validated");
  done(&rep);
}

static void test_failure(void) {
  CSERVE_ARENA *a = cserve_arena_new();
  CSERVE_HTTPD_REQ r = request(NULL);
  CSERVE_HTTPD_REPLY rep = {0};
  CSERVE_VIEW v = {&TITLE,
                   cserve_attr(a, cserve_el(a, &cserve_tag_a),
                               &cserve_attr_href, "javascript:alert(1)")};
  cserve_page(&SITE, &r, a, &v, 200, &rep);
  CSERVE_TEST_ASSERT(
      rep.status == 500 && !strstr(rep.body, "javascript"),
      "a tree that won't render is a 500, and says nothing of it");
  done(&rep);
  cserve_arena_free(a);
}

int main(void) {
  printf("page_test\n");
  test_document_and_fragment();
  test_language();
  test_validation();
  test_failure();
  return cserve_test_summary();
}
