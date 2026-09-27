#ifndef CTUI_WM_NET_CONN_H
#define CTUI_WM_NET_CONN_H

#include "http.h"

#include <stddef.h>
#include <sys/types.h>

/* One connection to a URL's host: TCP with a deadline (every address the
 * name resolves to, in order, until one answers), TLS on it for https
 * (tls.h). Every call gives up at the deadline (CLOCK_MONOTONIC ms, as
 * ctui_wm_net_now() gives it); only the name lookup can't be cut short
 * (getaddrinfo() has its resolver's own timeouts). */

typedef struct CTUI_WM_CONN CTUI_WM_CONN;

long ctui_wm_net_now(void);

/* fd ready for events (POLLIN/POLLOUT) before deadline: 0, or -1 with
 * why in err ("timed out") */
int ctui_wm_net_wait(int fd, short events, long deadline, char *err,
                     size_t err_cap);

/* connected (and the TLS handshake done, the host's certificate checked)
 * to u's host, or NULL with why in err */
CTUI_WM_CONN *ctui_wm_conn_open(const CTUI_WM_URL *u, long deadline, char *err,
                                size_t err_cap);
/* all of buf sent: 0, or -1 with why in err */
int ctui_wm_conn_write(CTUI_WM_CONN *c, const char *buf, size_t n, char *err,
                       size_t err_cap);
/* up to n bytes: how many, 0 once the server has closed, -1 with why in
 * err */
ssize_t ctui_wm_conn_read(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
                          size_t err_cap);
void ctui_wm_conn_close(CTUI_WM_CONN *c);

#endif
