/* the test app: two routes, so the host's ABI, its router and both ways
 * of linking an app (dlopen()ed, built in) have something to answer */
#include "app.h"

#include <stdio.h>
#include <string.h>

static char g_root[256];

static void hello(const CSERVE_HTTPD_REQ *r, const char *body,
                  const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)r;
  (void)body;
  const char *name = cserve_route_param(m, "name");
  char text[512];
  int n = snprintf(text, sizeof text, "hello, %s (from %s)\n",
                   name ? name : "world", g_root);
  cserve_httpd_text(rep, 200, "text/plain; charset=utf-8", text,
                    n > 0 && (size_t)n < sizeof text ? (size_t)n : 0);
}

static const CSERVE_ROUTE ROUTES[] = {
    {CSERVE_GET, "/hello", hello},
    {CSERVE_GET, "/hello/{name}", hello},
};

static int init(const CSERVE_APP_ENV *env, char *err, size_t err_cap) {
  if (snprintf(g_root, sizeof g_root, "%s", env->root) >= (int)sizeof g_root) {
    snprintf(err, err_cap, "a root too long for hello");
    return -1;
  }
  return 0;
}

const CSERVE_APP cserve_app_hello = {
    CSERVE_APP_HEADER("hello"),
    .init = init,
    .routes = ROUTES,
    .nroutes = sizeof ROUTES / sizeof *ROUTES,
};
