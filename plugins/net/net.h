#ifndef CTUI_WM_NET_H
#define CTUI_WM_NET_H

#include "base/plugin.h"

#include <stddef.h>

/* The net plugin's HTTP client (the `net` slot's `http`, plugin.h says
 * what it does): http.h's request and reply over conn.h's connection,
 * redirects followed, one deadline for all of it. Blocking: its callers
 * run it in a child of their own (the weather widget) or a thread. */
int ctui_wm_net_http(const CTUI_WM_HTTP_REQ *req, CTUI_WM_HTTP_REPLY *rep,
                     char *err, size_t err_cap);
/* the same, the body handed to sink as it arrives (the `net` slot's
 * `http_stream`) */
int ctui_wm_net_http_stream(const CTUI_WM_HTTP_REQ *req,
                            const CTUI_WM_HTTP_SINK *sink,
                            CTUI_WM_HTTP_REPLY *rep, char *err, size_t err_cap);

#endif
