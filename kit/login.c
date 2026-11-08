#include "login.h"

#include "headers.h"

#include <stdio.h>
#include <string.h>

/* set once by init(), before the first request; read by every worker */
static const CSERVE_TARPIT_API *g_api;

void cserve_login_use(const CSERVE_TARPIT_API *api) { g_api = api; }

static int on(const CSERVE_HTTPD_REQ *r) {
  return g_api && (r->peer_family == 4 || r->peer_family == 6);
}

int cserve_login_check(const CSERVE_HTTPD_REQ *r, const char *account,
                       CSERVE_HTTPD_REPLY *rep) {
  long left =
      on(r) ? g_api->waiting(g_api->t, r->peer_family, r->peer_net, account, 1)
            : 0;
  if (left <= 0) {
    return 0;
  }
  long s = (left + 999) / 1000;
  char text[96], after[24];
  int n = snprintf(text, sizeof text, "too many tries: wait %ld s\n", s);
  snprintf(after, sizeof after, "%ld", s);
  rep->headers[0] = '\0';
  cserve_httpd_text(rep, 429, "text/plain; charset=utf-8", text,
                    n > 0 ? (size_t)n : 0);
  if (cserve_header(rep, CSERVE_H_RETRY_AFTER, after) != 0 ||
      cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                    cserve_cache_value(CSERVE_CACHE_NO_STORE)) != 0) {
    rep->headers[0] = '\0';
  }
  return 1;
}

void cserve_login_fail(const CSERVE_HTTPD_REQ *r, const char *account,
                       CSERVE_HTTPD_REPLY *rep) {
  if (on(r)) {
    rep->delay_ms =
        g_api->failed(g_api->t, r->peer_family, r->peer_net, account);
  }
}

void cserve_login_pass(const CSERVE_HTTPD_REQ *r, const char *account) {
  if (on(r)) {
    g_api->passed(g_api->t, r->peer_family, r->peer_net, account);
  }
}
