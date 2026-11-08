#ifndef CSERVE_LOOP_H
#define CSERVE_LOOP_H

#include "httpd.h"
#include "tls.h"

#include <stddef.h>

/* The server for the open internet: one thread owns every socket, in one
 * epoll loop, and every wait it has is a deadline in one heap (heap.h);
 * what a request asks of an app runs on a fixed pool of workers (pool.h)
 * and never on the loop. A connection costs memory and a slot, never a
 * thread, so a slow client -- a head sent a byte a second, a reply read
 * as slowly -- holds only its own slot until its deadline.
 *
 * HTTP/1.1 as httpd.h's threaded server speaks it, decided by the same
 * pure functions: the head framed (cserve_httpd_frame()) and parsed
 * (cserve_httpd_parse()), the reply's head written (cserve_httpd_head()),
 * keep-alive (cserve_httpd_keep()). A body is read whole by its
 * Content-Length before the handler runs; a pulled body (httpd.h) is
 * pulled on the loop, as the socket takes it, so a pull must return as
 * soon as a file read does.
 *
 * Deadlines: the handshake and the first request's head share one
 * (timeout_ms from the accept); a later request's head has idle_ms from
 * the last reply; a body has timeout_ms from its head; writing has
 * timeout_ms, renewed whenever the client takes some of it. A head cut
 * off by its deadline is refused with a 400, as the threaded server does;
 * anything else past a deadline is closed without a word.
 *
 * Limits: max_conns connections at once, per_addr from one network (an
 * IPv4 address, an IPv6 /64); past either a connection is closed as soon
 * as it's accepted. A request the pool has no room for gets a 503 with
 * Retry-After, and the connection closes. A reply with a delay_ms (a
 * failed login's: tarpit.h) waits that long on its connection's timer
 * before it goes; past parked_max of those at once, the connection is
 * closed instead -- never answered early.
 *
 * Every reply is said in one access-log line (log.h, CSERVE_LOG_INFO):
 * the method, the path without its query, the status, the body's bytes,
 * the milliseconds, and the address family -- never the address. */

typedef struct {
  /* runs on a worker: r and its body in, rep filled (status 0: a 500) */
  CSERVE_HTTPD_FN handler;
  void *ud;
  const char *server; /* the Server header ("" or NULL: none) */
  long long body_max; /* a request body's limit (413 past it; 1 MiB) */
  int idle_ms;        /* waiting for the next request (10 s) */
  int timeout_ms;     /* see above (30 s) */
  int max_requests;   /* on one connection (100) */
  int workers;        /* the pool's threads (4) */
  int queue;          /* requests handed to the pool at once (64) */
  int max_conns;      /* connections at once (1024) */
  int per_addr;       /* from one network at once (32) */
  int parked_max;     /* replies held back at once (httpd.h's delay_ms;
                         256): past it, the connection is closed instead */
} CSERVE_LOOP_CONFIG;

typedef struct CSERVE_LOOP CSERVE_LOOP;

/* a loop under cfg (copied; 0 fields take their defaults), its pool
 * started, or NULL with why in err */
CSERVE_LOOP *cserve_loop_new(const CSERVE_LOOP_CONFIG *cfg, char *err,
                             size_t err_cap);
/* fd (listening, non-blocking: cserve_listen_socket()) served, with TLS
 * from the first byte when tls is set: 0, or -1 with why in err. The
 * loop closes fd when it's freed. */
int cserve_loop_listen(CSERVE_LOOP *l, int fd, CSERVE_TLS_SERVER *tls,
                       char *err, size_t err_cap);
/* serves until stop_fd turns readable: then the listeners close, idle
 * connections go, and the rest have grace_ms to finish (5 s) before
 * they're cut. 0, or -1 with why in err (epoll failed). */
int cserve_loop_run(CSERVE_LOOP *l, int stop_fd, int grace_ms, char *err,
                    size_t err_cap);
/* every connection closed, the pool joined (requests it holds still
 * run), the listeners closed */
void cserve_loop_free(CSERVE_LOOP *l);

/* connections open now (the tests' gauge) */
int cserve_loop_conns(const CSERVE_LOOP *l);

#endif
