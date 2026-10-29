/* static.c: the routing (the stamp, dot-segments, PHP, a symlink out of
 * the root, both climb modes), types and cache tiers, and a file served:
 * its ETag, a 304, a 405 */
/* mkdtemp/symlink/realpath are POSIX, not C11 */
#define _GNU_SOURCE

#include "static.h"

#include "test.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[] = "/tmp/cserve-static-XXXXXX";
static char g_root[PATH_MAX];

static void put(const char *rel, const char *text) {
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/%s", g_dir, rel);
  FILE *f = fopen(path, "w");
  if (f) {
    fputs(text, f);
    fclose(f);
  }
}

static const char *kind_name(CSERVE_STATIC_KIND k) {
  return k == CSERVE_STATIC_FILE    ? "file"
         : k == CSERVE_STATIC_FRONT ? "the front"
                                    : "refused";
}

static void test_route(void) {
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/outside.txt", g_dir);
  put("outside.txt", "secret");
  put("public/app.css", "body{}");
  put("public/index.php", "<?php");
  put("public/.user.ini", "x=1");
  put("public/assets/js/main.js", "go()");
  put("public/sub/x.php", "<?php");
  put("public/sub/page.html", "<p>");
  char link[PATH_MAX];
  snprintf(link, sizeof link, "%s/out.txt", g_root);
  CSERVE_TEST_ASSERT(symlink(path, link) == 0, "a symlink out of the root");

  struct {
    const char *path;
    CSERVE_STATIC_KIND kind, front_kind; /* climb_front 0, 1 */
    const char *file;                    /* under the root */
    int immutable;
  } T[] = {
      {"/app.css", CSERVE_STATIC_FILE, CSERVE_STATIC_FILE, "/app.css", 0},
      {"//sub//page.html", CSERVE_STATIC_FILE, CSERVE_STATIC_FILE,
       "/sub/page.html", 0},
      {"/assets/js/main.js", CSERVE_STATIC_FILE, CSERVE_STATIC_FILE,
       "/assets/js/main.js", 0},
      {"/assets/js/v-0123abcd/main.js", CSERVE_STATIC_FILE, CSERVE_STATIC_FILE,
       "/assets/js/main.js", 1},
      {"/assets/js/v-0123ABCD/main.js", CSERVE_STATIC_FRONT,
       CSERVE_STATIC_FRONT, NULL, 0},
      {"/sub/v-0123abcd/page.html", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT,
       NULL, 0},
      {"/", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/sub", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/index.php", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/sub/x.php", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/.user.ini", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/.htaccess", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/out.txt", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/media/play", CSERVE_STATIC_FRONT, CSERVE_STATIC_FRONT, NULL, 0},
      {"/sub/../../outside.txt", CSERVE_STATIC_BAD, CSERVE_STATIC_FRONT, NULL,
       0},
      {"/assets/js/v-00000000/../../index.php", CSERVE_STATIC_BAD,
       CSERVE_STATIC_FRONT, NULL, 0},
      {"/./app.css", CSERVE_STATIC_BAD, CSERVE_STATIC_FRONT, NULL, 0},
      {"app.css", CSERVE_STATIC_BAD, CSERVE_STATIC_BAD, NULL, 0},
  };
  for (int front = 0; front < 2; front++) {
    CSERVE_STATIC s = {.root = g_root, .climb_front = front};
    for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
      CSERVE_STATIC_ROUTE rt;
      cserve_static_route(&s, T[i].path, &rt);
      CSERVE_STATIC_KIND want_kind = front ? T[i].front_kind : T[i].kind;
      char want[PATH_MAX] = "";
      if (T[i].file) {
        snprintf(want, sizeof want, "%s%s", g_root, T[i].file);
      }
      CSERVE_TEST_ASSERT(
          rt.kind == want_kind && (!T[i].file || !strcmp(rt.file, want)) &&
              rt.immutable == T[i].immutable,
          "%s%s -> %s %s", front ? "(climb front) " : "", T[i].path,
          kind_name(rt.kind), rt.immutable ? "(immutable)" : "");
    }
  }
  CSERVE_TEST_ASSERT(
      !strcmp(cserve_static_mime("a/b.JS"), "text/javascript; charset=utf-8") &&
          !strcmp(cserve_static_mime("x.woff2"), "font/woff2") &&
          !strcmp(cserve_static_mime("x.tar.gz"), "application/octet-stream") &&
          !strcmp(cserve_static_mime("dir.d/noext"),
                  "application/octet-stream"),
      "types by extension");
  CSERVE_TEST_ASSERT(
      !strcmp(cserve_static_cache("a.css", 0), "public, max-age=3600") &&
          !strcmp(cserve_static_cache("a.js", 1),
                  "public, max-age=31536000, immutable") &&
          !strcmp(cserve_static_cache("a.png", 1), "public, max-age=2592000") &&
          !strcmp(cserve_static_cache("a.html", 0), ""),
      ".htaccess's cache tiers");
}

/* a request's head (Host added) parsed into r: 0, or -1 */
static int request(char *buf, size_t cap, const char *method,
                   const char *target, const char *extra, CSERVE_HTTPD_REQ *r) {
  snprintf(buf, cap, "%s %s HTTP/1.1\r\nHost: h\r\n%s\r\n", method, target,
           extra);
  char err[128];
  return cserve_httpd_parse(buf, r, err, sizeof err) == 0 ? 0 : -1;
}

/* path served for method (with extra headers): the reply in rep */
static void serve(const char *method, const char *path, const char *extra,
                  CSERVE_HTTPD_REPLY *rep) {
  char buf[1024];
  CSERVE_HTTPD_REQ r;
  CSERVE_STATIC s = {.root = g_root};
  CSERVE_STATIC_ROUTE rt;
  memset(rep, 0, sizeof *rep);
  if (request(buf, sizeof buf, method, path, extra, &r) != 0) {
    return;
  }
  cserve_static_route(&s, r.path, &rt);
  if (rt.kind == CSERVE_STATIC_FILE) {
    cserve_static_serve(&r, &rt, rep);
  }
}

static void done(CSERVE_HTTPD_REPLY *rep) {
  if (rep->owned) {
    free(rep->body);
  }
}

static void test_serve(void) {
  CSERVE_HTTPD_REPLY rep;
  serve("GET", "/app.css", "", &rep);
  CSERVE_TEST_ASSERT(
      rep.status == 200 && rep.len == 6 && !memcmp(rep.body, "body{}", 6) &&
          !strcmp(rep.type, "text/css; charset=utf-8") &&
          strstr(rep.headers, "Cache-Control: public, max-age=3600\r\n") &&
          strstr(rep.headers, "X-Content-Type-Options: nosniff"),
      "a file: its body, type and cache tier");
  char etag[80] = "", extra[160];
  const char *e = strstr(rep.headers, "ETag: ");
  if (e) {
    snprintf(etag, sizeof etag, "%.*s", (int)strcspn(e + 6, "\r"), e + 6);
  }
  done(&rep);
  snprintf(extra, sizeof extra, "If-None-Match: \"x\", %s\r\n", etag);
  serve("GET", "/app.css", extra, &rep);
  CSERVE_TEST_ASSERT(etag[0] == 'W' && rep.status == 304 && !rep.len &&
                         strstr(rep.headers, etag),
                     "its ETag again: 304, the ETag kept (%s)", etag);
  done(&rep);
  serve("GET", "/app.css", "If-None-Match: W/\"other\"\r\n", &rep);
  CSERVE_TEST_ASSERT(rep.status == 200, "another ETag: 200");
  done(&rep);
  serve("GET", "/assets/js/v-0123abcd/main.js", "", &rep);
  CSERVE_TEST_ASSERT(rep.status == 200 && strstr(rep.headers, "immutable"),
                     "a stamped asset: kept a year");
  done(&rep);
  serve("POST", "/app.css", "Content-Length: 0\r\n", &rep);
  CSERVE_TEST_ASSERT(rep.status == 405 &&
                         !strcmp(rep.headers, "Allow: GET, HEAD\r\n"),
                     "a POST to a file: 405, GET and HEAD allowed");
  done(&rep);
}

int main(void) {
  if (!mkdtemp(g_dir)) {
    CSERVE_TEST_ASSERT(0, "a scratch dir");
    return cserve_test_summary();
  }
  const char *dirs[] = {"public", "public/assets", "public/assets/js",
                        "public/sub"};
  char pub[PATH_MAX];
  for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) {
    snprintf(pub, sizeof pub, "%s/%s", g_dir, dirs[i]);
    mkdir(pub, 0700);
  }
  snprintf(pub, sizeof pub, "%s/public", g_dir);
  if (!realpath(pub, g_root)) {
    return 1;
  }
  test_route();
  test_serve();
  char rm[PATH_MAX + 16];
  snprintf(rm, sizeof rm, "rm -rf '%s'", g_dir);
  int rc = system(rm);
  (void)rc;
  return cserve_test_summary();
}
