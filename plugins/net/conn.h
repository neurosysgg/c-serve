#ifndef CTUI_WM_NET_CONN_H
#define CTUI_WM_NET_CONN_H

#include "http.h"
#include "tls.h"

#include <stddef.h>
#include <sys/types.h>

/* One connection to a URL's host: TCP with a deadline (every address the
 * name resolves to, in order, until one answers), TLS on it for https
 * (tls.h). Every call gives up at the deadline (CLOCK_MONOTONIC ms, as
 * ctui_wm_net_now() gives it); only the name lookup can't be cut short
 * (getaddrinfo() has its resolver's own timeouts). A long-lived one
 * (ctui-mail's IMAP and SMTP: the URL only brings host, port and tls)
 * moves its deadline per exchange and reads lines and counted bytes
 * through a buffer. */

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

/* the deadline every call from now on gives up at */
void ctui_wm_conn_deadline(CTUI_WM_CONN *c, long deadline);
/* TCP keepalive probes after idle_s quiet seconds (a connection idling
 * for minutes, like IMAP IDLE, notices a dead peer) */
void ctui_wm_conn_keepalive(CTUI_WM_CONN *c, int idle_s);
/* TLS started on a plain connection (after the protocol's STARTTLS), the
 * certificate checked against host: 0, or -1 with why in err */
int ctui_wm_conn_starttls(CTUI_WM_CONN *c, const char *host, char *err,
                          size_t err_cap);
/* its socket, for a caller polling it with fds of its own; a read may
 * have data without the socket being readable: see pending() */
int ctui_wm_conn_fd(const CTUI_WM_CONN *c);
/* an idle connection kept for a later request still looks open: nothing
 * buffered, no hangup or error, nothing unasked come in plainly */
int ctui_wm_conn_idle_ok(const CTUI_WM_CONN *c);
/* whether a read returns at once (bytes buffered here or in TLS) */
int ctui_wm_conn_pending(const CTUI_WM_CONN *c);

/* The server side: a connection a listener accepted (listen.h), with
 * deadline, or NULL (out of memory; fd closed then). A server speaking TLS
 * from the first byte, or after its protocol's STARTTLS, accepts it with
 * accept_tls(): 0, or -1 with why in err. */
CTUI_WM_CONN *ctui_wm_conn_adopt(int fd, long deadline);
int ctui_wm_conn_accept_tls(CTUI_WM_CONN *c, CTUI_WM_TLS_SERVER *srv, char *err,
                            size_t err_cap);
/* whether TLS is on */
int ctui_wm_conn_tls(const CTUI_WM_CONN *c);

/* the next line (up to LF; its CRLF or LF not in it), at most max bytes:
 * its length with *line pointing at it (valid until the next read,
 * NUL-terminated); -1 with why in err (the peer closed, too long) */
ssize_t ctui_wm_conn_line(CTUI_WM_CONN *c, const char **line, size_t max,
                          char *err, size_t err_cap);
/* exactly n bytes into buf: 0, or -1 with why in err */
int ctui_wm_conn_bytes(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
                       size_t err_cap);

#endif
