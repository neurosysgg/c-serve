#ifndef CSERVE_CGI_H
#define CSERVE_CGI_H

#include "httpd.h"

#include <stddef.h>

/* A front controller (php-cgi and index.php) run per request: its
 * environment as Apache names it, the request's body on its stdin, its
 * reply head parsed and the rest streamed, every wait bounded. (ctui-wm's
 * ctui-remote's CGI, made a host's.) */

typedef struct {
  const char *const *argv; /* the program ("php-cgi"), NULL-terminated */
  const char *root;        /* DOCUMENT_ROOT, its cwd, realpath()'d */
  const char *script;      /* the front controller under root ("index.php") */
  const char *software;    /* SERVER_SOFTWARE; NULL: "c-serve" */
  int port;                /* SERVER_PORT: the one the request came in on */
  int https;               /* HTTPS=on, REQUEST_SCHEME=https */
  const char *const *env;  /* "K=V" set for every request; NULL: none */
  int head_ms;             /* its reply head; 0: 30 s */
  int idle_ms;             /* quiet on its body; 0: 120 s (a long push) */
} CSERVE_CGI;

/* the CGI's environment for r: a few of ours (HOME, PATH, the locale, the
 * XDG directories, PHPRC), the request's variables, its headers as HTTP_*
 * (repeats joined; '_' names, Proxy and the CONTENT_ two dropped), c->env,
 * then extra ("K=V", NULL-terminated; NULL: none): malloc'd strings in a
 * NULL-terminated array (cserve_cgi_env_free()), or NULL */
char **cserve_cgi_env(const CSERVE_CGI *c, const CSERVE_HTTPD_REQ *r,
                      const char *const *extra);
void cserve_cgi_env_free(char **env);

/* a CGI reply's head in buf[0, len): 0 while it isn't whole yet; its
 * length (the body starts there) with rep's status and headers set and
 * its Content-Type in type; -1 when it's broken (why in err). Status:
 * (or Location: alone, a 302) sets the status, else 200; hop-by-hop
 * headers and Content-Length are dropped (the body is streamed). */
long cserve_cgi_head(const char *buf, size_t len, CSERVE_HTTPD_REPLY *rep,
                     char *type, size_t type_cap, char *err, size_t err_cap);

/* c's program run for r (body: its body, extra as for cserve_cgi_env()):
 * rep filled, its body streamed from the program -- or an error page:
 * 502 when it can't be started or says nothing that's a reply, 504 when
 * its head doesn't come within head_ms (it's killed) */
void cserve_cgi(const CSERVE_CGI *c, const CSERVE_HTTPD_REQ *r,
                const char *body, const char *const *extra,
                CSERVE_HTTPD_REPLY *rep);

#endif
