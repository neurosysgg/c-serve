#ifndef CSERVE_CONN_H
#define CSERVE_CONN_H

#include "http.h"
#include "tls.h"

#include <stddef.h>
#include <sys/types.h>

/* One connection to a URL's host: TCP with a deadline (every address the
 * name resolves to, in order, until one answers), TLS on it for https
 * (tls.h). Every call gives up at the deadline (CLOCK_MONOTONIC ms, as
 * cserve_net_now() gives it); only the name lookup can't be cut short
 * (getaddrinfo() has its resolver's own timeouts). A long-lived one
 * (ctui-mail's IMAP and SMTP: the URL only brings host, port and tls)
 * moves its deadline per exchange and reads lines and counted bytes
 * through a buffer. */

typedef struct CSERVE_CONN CSERVE_CONN;

long cserve_net_now(void);

/* fd ready for events (POLLIN/POLLOUT) before deadline: 0, or -1 with
 * why in err ("timed out") */
int cserve_net_wait(int fd, short events, long deadline, char *err,
                    size_t err_cap);

/* connected (and the TLS handshake done, the host's certificate checked)
 * to u's host, or NULL with why in err */
CSERVE_CONN *cserve_conn_open(const CSERVE_URL *u, long deadline, char *err,
                              size_t err_cap);
/* all of buf sent: 0, or -1 with why in err */
int cserve_conn_write(CSERVE_CONN *c, const char *buf, size_t n, char *err,
                      size_t err_cap);
/* up to n bytes: how many, 0 once the server has closed, -1 with why in
 * err */
ssize_t cserve_conn_read(CSERVE_CONN *c, char *buf, size_t n, char *err,
                         size_t err_cap);
void cserve_conn_close(CSERVE_CONN *c);

/* the deadline every call from now on gives up at */
void cserve_conn_deadline(CSERVE_CONN *c, long deadline);
/* TCP keepalive probes after idle_s quiet seconds (a connection idling
 * for minutes, like IMAP IDLE, notices a dead peer) */
void cserve_conn_keepalive(CSERVE_CONN *c, int idle_s);
/* TLS started on a plain connection (after the protocol's STARTTLS), the
 * certificate checked against host: 0, or -1 with why in err */
int cserve_conn_starttls(CSERVE_CONN *c, const char *host, char *err,
                         size_t err_cap);
/* its socket, for a caller polling it with fds of its own; a read may
 * have data without the socket being readable: see pending() */
int cserve_conn_fd(const CSERVE_CONN *c);
/* an idle connection kept for a later request still looks open: nothing
 * buffered, no hangup or error, nothing unasked come in plainly */
int cserve_conn_idle_ok(const CSERVE_CONN *c);
/* whether a read returns at once (bytes buffered here or in TLS) */
int cserve_conn_pending(const CSERVE_CONN *c);

/* The server side: a connection a listener accepted (listen.h), with
 * deadline, or NULL (out of memory; fd closed then). A server speaking TLS
 * from the first byte, or after its protocol's STARTTLS, accepts it with
 * accept_tls(): 0, or -1 with why in err. */
CSERVE_CONN *cserve_conn_adopt(int fd, long deadline);
int cserve_conn_accept_tls(CSERVE_CONN *c, CSERVE_TLS_SERVER *srv, char *err,
                           size_t err_cap);
/* whether TLS is on */
int cserve_conn_tls(const CSERVE_CONN *c);
/* the other side's certificate (tls.h's cserve_tls_peer()): 0, or -1
 * plainly or without one */
int cserve_conn_peer_cert(const CSERVE_CONN *c, char *cn, size_t cn_cap,
                          char fpr[65]);

/* the next line (up to LF; its CRLF or LF not in it), at most max bytes:
 * its length with *line pointing at it (valid until the next read,
 * NUL-terminated); -1 with why in err (the peer closed, too long) */
ssize_t cserve_conn_line(CSERVE_CONN *c, const char **line, size_t max,
                         char *err, size_t err_cap);
/* exactly n bytes into buf: 0, or -1 with why in err */
int cserve_conn_bytes(CSERVE_CONN *c, char *buf, size_t n, char *err,
                      size_t err_cap);

#endif
