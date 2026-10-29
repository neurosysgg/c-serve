#ifndef CSERVE_NET_H
#define CSERVE_NET_H

#include "http_types.h"

#include <stddef.h>

/* The HTTP client: http.h's request and reply over conn.h's connection,
 * redirects followed, one deadline for all of it; a gathered body asked
 * for gzip'd or deflated and handed back decoded (coding.h). Blocking: its
 * callers run it in a child of their own or a thread. */

/* req, following up to 5 redirects (a GET's; a POST's 301 / 302 / 303 as a
 * GET without its body, as browsers do; others come back as they are). 0
 * when a reply came, whatever its status (rep filled), or -1 with why in
 * err ("resolving X: ...", "timed out", "TLS: ...") */
int cserve_net_http(const CSERVE_HTTP_REQ *req, CSERVE_HTTP_REPLY *rep,
                    char *err, size_t err_cap);
/* req the same way, its body handed to sink as it arrives instead of
 * gathered: no size limit (req->max unused); req->timeout_ms covers
 * everything up to the headers, then each wait for more of the body (an
 * endless one runs until the sink stops it). rep gets the status and
 * headers (body ""; free() it). 0 when the body came to its end or the
 * sink stopped it, -1 with why in err (a body cut short too: "the reply
 * ended inside its body") */
int cserve_net_http_stream(const CSERVE_HTTP_REQ *req,
                           const CSERVE_HTTP_SINK *sink, CSERVE_HTTP_REPLY *rep,
                           char *err, size_t err_cap);

/* Connections are kept open between requests (keep-alive, at most a few
 * per process, briefly): a GET to the same host goes on one. These close
 * them all, and count them (the tests) */
void cserve_net_idle_close(void);
int cserve_net_idle_count(void);

#endif
