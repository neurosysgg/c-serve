/* route.c: patterns and their captures, the dot-segments a capture never
 * takes, and dispatch's answers -- a handler, a 405 naming what's
 * allowed, or nothing (the next in line's) */
#include "route.h"

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_match(void) {
  struct {
    const char *pattern, *path;
    int fits;
    const char *slug, *rest; /* the captures it should have; NULL: none */
  } T[] = {
      {"/", "/", 1, NULL, NULL},
      {"/", "///", 1, NULL, NULL},
      {"/", "/a", 0, NULL, NULL},
      {"/releases", "/releases", 1, NULL, NULL},
      {"/releases", "//releases//", 1, NULL, NULL},
      {"/releases", "/release", 0, NULL, NULL},
      {"/releases", "/releases/ill", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/ill", 1, "ill", NULL},
      {"/releases/{slug}", "/releases", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/ill/flac", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/..", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/.", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/.user.ini", 0, NULL, NULL},
      {"/releases/{slug}", "/releases/ill%20x", 1, "ill%20x", NULL},
      {"/assets/*", "/assets/js/main.js", 1, NULL, "js/main.js"},
      {"/assets/*", "/assets", 1, NULL, ""},
      {"/assets/*", "/assets/js/../x", 0, NULL, NULL},
      {"/assets/*", "/assets/.git/config", 0, NULL, NULL},
      {"/assets/*", "/other/x", 0, NULL, NULL},
  };
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    CSERVE_ROUTE_MATCH m;
    int fits = cserve_route_match(T[i].pattern, T[i].path, &m);
    const char *slug = fits ? cserve_route_param(&m, "slug") : NULL;
    const char *rest = fits ? cserve_route_param(&m, "*") : NULL;
    CSERVE_TEST_ASSERT(fits == T[i].fits &&
                           (!T[i].slug || (slug && !strcmp(slug, T[i].slug))) &&
                           (!T[i].rest || (rest && !strcmp(rest, T[i].rest))),
                       "%s %s %s", T[i].pattern,
                       T[i].fits ? "fits" : "doesn't fit", T[i].path);
  }
  CSERVE_ROUTE_MATCH m;
  CSERVE_TEST_ASSERT(cserve_route_match("/{a}/{b}", "/x/y", &m) && m.n == 2 &&
                         !strcmp(cserve_route_param(&m, "a"), "x") &&
                         !strcmp(cserve_route_param(&m, "b"), "y") &&
                         !cserve_route_param(&m, "c"),
                     "two captures, by name; one it hasn't: NULL");
  CSERVE_TEST_ASSERT(!cserve_route_match("/{a}/{b}/{c}/{d}/{e}/{f}/{g}/{h}/{i}",
                                         "/1/2/3/4/5/6/7/8/9", &m),
                     "more captures than a match holds: fits nothing");
  char long_path[5000];
  long_path[0] = '/';
  memset(long_path + 1, 'a', sizeof long_path - 2);
  long_path[sizeof long_path - 1] = '\0';
  CSERVE_TEST_ASSERT(!cserve_route_match("/{a}", long_path, &m),
                     "a capture past the store: fits nothing");
  CSERVE_TEST_ASSERT(cserve_route_method("GET") == CSERVE_GET &&
                         cserve_route_method("DELETE") == CSERVE_DELETE &&
                         cserve_route_method("BREW") == 0 &&
                         cserve_route_method("get") == 0,
                     "methods by name, case and all");
}

/* what the last handler saw (copied: the match is dispatch's own) */
static const char *g_called;
static char g_seen[64];

static void on_show(const CSERVE_HTTPD_REQ *r, const char *body,
                    const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)r;
  (void)body;
  const char *slug = cserve_route_param(m, "slug");
  snprintf(g_seen, sizeof g_seen, "%s", slug ? slug : "");
  g_called = g_seen;
  cserve_httpd_text(rep, 200, "text/plain", "show", 4);
}

static void on_write(const CSERVE_HTTPD_REQ *r, const char *body,
                     const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)r;
  (void)body;
  (void)m;
  g_called = "write";
  cserve_httpd_text(rep, 201, "text/plain", "made", 4);
}

static const CSERVE_ROUTE ROUTES[] = {
    {CSERVE_GET, "/releases/{slug}", on_show},
    {CSERVE_POST | CSERVE_DELETE, "/releases/{slug}", on_write},
    {CSERVE_GET, "/about", on_show},
};

/* method target against ROUTES: dispatch's answer, the reply in rep */
static int ask(const char *method, const char *target,
               CSERVE_HTTPD_REPLY *rep) {
  char buf[512], err[128];
  snprintf(buf, sizeof buf, "%s %s HTTP/1.1\r\nHost: h\r\n\r\n", method,
           target);
  CSERVE_HTTPD_REQ r;
  memset(rep, 0, sizeof *rep);
  g_called = NULL;
  if (cserve_httpd_parse(buf, &r, err, sizeof err) != 0) {
    return -1;
  }
  int answered = cserve_route_dispatch(
      ROUTES, (int)(sizeof ROUTES / sizeof *ROUTES), &r, NULL, rep);
  if (rep->owned) {
    free(rep->body);
    rep->owned = 0;
  }
  return answered;
}

static void test_dispatch(void) {
  CSERVE_HTTPD_REPLY rep;
  CSERVE_TEST_ASSERT(ask("GET", "/releases/ill", &rep) == 1 &&
                         rep.status == 200 && g_called &&
                         !strcmp(g_called, "ill"),
                     "GET: the first route that fits, its capture");
  CSERVE_TEST_ASSERT(ask("HEAD", "/releases/ill", &rep) == 1 &&
                         rep.status == 200,
                     "HEAD: GET's route");
  CSERVE_TEST_ASSERT(ask("POST", "/releases/ill", &rep) == 1 &&
                         rep.status == 201 && g_called &&
                         !strcmp(g_called, "write"),
                     "POST: the route further down that has it");
  CSERVE_TEST_ASSERT(
      ask("PUT", "/releases/ill", &rep) == 1 && rep.status == 405 &&
          !strcmp(rep.headers, "Allow: GET, HEAD, POST, DELETE\r\n") &&
          !g_called,
      "PUT: 405, every fitting route's methods allowed (%s)", rep.headers);
  CSERVE_TEST_ASSERT(ask("BREW", "/about", &rep) == 1 && rep.status == 405 &&
                         !strcmp(rep.headers, "Allow: GET, HEAD\r\n"),
                     "a method nobody has heard of: 405 too");
  CSERVE_TEST_ASSERT(ask("GET", "/releases/ill/flac", &rep) == 0 &&
                         rep.status == 0 && !g_called,
                     "no pattern fits: not answered");
  CSERVE_TEST_ASSERT(ask("GET", "/releases/%2e%2e", &rep) == 0 && !g_called,
                     "an encoded \"..\": no capture takes it");
}

int main(void) {
  test_match();
  test_dispatch();
  return cserve_test_summary();
}
