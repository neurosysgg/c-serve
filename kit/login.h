#ifndef CSERVE_LOGIN_H
#define CSERVE_LOGIN_H

#include "app.h"
#include "httpd.h"

/* A login's brake, as an app uses it (the host's table: src/tarpit.h).
 * A gate that checks a password does, in this order:
 *
 *   if (cserve_login_check(r, account, rep)) return;  // a 429, answered
 *   ...the password checked...
 *   ok ? cserve_login_pass(r, account)
 *      : cserve_login_fail(r, account, rep);          // after its 401
 *
 * check() comes before the password, so a key that must wait costs no
 * PBKDF2; fail() holds the 401 back (rep->delay_ms) for the key's wait,
 * on the loop's timer. Only a try counts: a request that brought no
 * credentials at all is a browser asking what to send, not a guess, and
 * the gate calls none of these for it.
 *
 * Without the host's tarpit (cserve_login_use(NULL): --no-tarpit) or a
 * request whose peer the server didn't say (the threaded server: family
 * 0), every call does nothing. */

/* the host's tarpit, from init()'s env->tarpit (NULL: none) */
void cserve_login_use(const CSERVE_TARPIT_API *api);

/* 1 when the key must still wait: rep is the 429, with Retry-After, and
 * the wait is longer for it; 0 otherwise */
int cserve_login_check(const CSERVE_HTTPD_REQ *r, const char *account,
                       CSERVE_HTTPD_REPLY *rep);
/* a failed try counted, and rep (its 401, already filled) held back */
void cserve_login_fail(const CSERVE_HTTPD_REQ *r, const char *account,
                       CSERVE_HTTPD_REPLY *rep);
/* a try that opened it: the account's count cleared */
void cserve_login_pass(const CSERVE_HTTPD_REQ *r, const char *account);

#endif
