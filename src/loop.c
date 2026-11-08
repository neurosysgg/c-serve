/* The loop (loop.h). One rule keeps it safe: only the entry points an
 * event lands in -- accept, a connection's readiness, the pool's fd, a
 * deadline -- do I/O or close a connection, and each returns at once
 * after closing one. What moves a connection from one state to the next
 * (got_head(), dispatch(), refuse(), start_reply()) never does either:
 * it sets the state, the deadline and the events it waits for, and the
 * loop comes back to it. */
#define _GNU_SOURCE /* accept4() */
#include "loop.h"

#include "conn.h"
#include "heap.h"
#include "listen.h"
#include "log.h"
#include "pool.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#define IN_CAP (CSERVE_HTTPD_HEAD_MAX + 4096)
#define PULL_CAP 65536
#define PULL_ROOM 16 /* a chunk's size line, written in front of its data */
#define LISTEN_MAX 16
#define EVENTS 64
/* a refusal for a head cut off by its deadline gets this long to go */
#define REFUSAL_MS 1000
/* a closing connection reads what's still coming for this long, at most
 * this much, before it closes (lingering close: see linger()) */
#define LINGER_MS 2000
#define LINGER_MAX (256 * 1024)

enum { S_HANDSHAKE, S_HEAD, S_BODY, S_WORK, S_PARKED, S_WRITE, S_LINGER };

/* the reply's pieces, in the order they go */
enum { P_HEAD, P_BODY, P_PULL, P_END };

/* what an event is for: kind, and for a connection its slot and the
 * generation it had when it was registered (a slot is reused; an event
 * still queued for the one that left must not land on the new one) */
enum { K_LISTEN = 1, K_POOL, K_STOP, K_CONN, K_WATCH };
#define WATCH_MAX 4
#define TAG(kind, gen, i)                                                      \
  ((uint64_t)(kind) << 56 | (uint64_t)((gen) & 0xffffff) << 32 | (uint32_t)(i))
#define TAG_KIND(t) ((int)((t) >> 56))
#define TAG_GEN(t) ((unsigned)(((t) >> 32) & 0xffffff))
#define TAG_INDEX(t) ((int)(uint32_t)(t))

typedef struct {
  CSERVE_HEAP_NODE timer; /* first: the heap's node is its connection */
  int slot, fd, state;
  unsigned gen;
  uint32_t events; /* what epoll waits for on it now */
  int dead;        /* closed while the pool had it: freed when it's back */
  CSERVE_TLS *tls;
  int family;
  unsigned char net[16];
  char peer[64];
  int requests; /* answered on it so far */
  long t0;      /* when the request's head was complete */
  /* reading */
  char in[IN_CAP];
  size_t in_len;
  CSERVE_HTTPD_FRAME frame;
  char head[CSERVE_HTTPD_HEAD_MAX];
  CSERVE_HTTPD_REQ req;
  int understood; /* req parsed: the reply answers it */
  char *body;
  size_t body_got;
  /* writing */
  CSERVE_HTTPD_REPLY rep;
  int keep, chunked, has_body, phase;
  char refusal[320];
  char ohead[5120];
  const char *seg; /* the piece going out, and how far it's got */
  size_t seg_len, seg_off;
  char *pull_buf;
  long long pulled; /* the pulled body's bytes so far */
  long long sent;   /* the body's bytes the client has taken */
  size_t lingered;  /* bytes read and dropped while closing */
} CONN;

struct CSERVE_LOOP {
  CSERVE_LOOP_CONFIG cfg;
  int ep;
  CSERVE_POOL *pool;
  CSERVE_HEAP heap;
  CONN **conns;
  int *free_slots, nfree, parked;
  atomic_int live; /* read by cserve_loop_conns() from any thread */
  unsigned gen;
  struct {
    int fd;
    CSERVE_TLS_SERVER *tls;
  } ls[LISTEN_MAX];
  int nls;
  struct {
    void (*fn)(void *ud);
    void *ud;
  } ws[WATCH_MAX];
  int nws;
  int stopping;
};

static void work(void *job, void *ud) {
  const CSERVE_LOOP *l = ud;
  CONN *c = job;
  memset(&c->rep, 0, sizeof c->rep);
  l->cfg.handler(&c->req, c->body, &c->rep, l->cfg.ud);
  if (c->rep.status == 0) {
    cserve_httpd_release(&c->rep);
    cserve_httpd_text(&c->rep, 500, "text/plain; charset=utf-8", "no answer\n",
                      10);
  }
}

/* --- a connection's bookkeeping --- */

static void wait_for(CSERVE_LOOP *l, CONN *c, uint32_t events) {
  if (c->events == events || c->fd < 0) {
    return;
  }
  struct epoll_event ev = {.events = events,
                           .data.u64 = TAG(K_CONN, c->gen, c->slot)};
  epoll_ctl(l->ep, EPOLL_CTL_MOD, c->fd, &ev);
  c->events = events;
}

/* the events a WANT from a read or write waits for */
static uint32_t wanted(long r) {
  return r == CSERVE_TLS_WANT_WRITE ? EPOLLOUT : EPOLLIN;
}

static void due(CSERVE_LOOP *l, CONN *c, long ms) {
  (void)cserve_heap_set(&l->heap, &c->timer, cserve_net_now() + ms);
}

static void conn_close(CSERVE_LOOP *l, CONN *c) {
  cserve_heap_remove(&l->heap, &c->timer);
  if (c->fd >= 0) {
    epoll_ctl(l->ep, EPOLL_CTL_DEL, c->fd, NULL);
    cserve_tls_close(c->tls);
    c->tls = NULL;
    close(c->fd);
    c->fd = -1;
  }
  if (c->state == S_WORK) {
    c->dead = 1; /* the pool has it: its body and reply are a worker's */
    return;
  }
  if (c->state == S_PARKED) {
    l->parked--;
  }
  cserve_httpd_release(&c->rep);
  free(c->body);
  free(c->pull_buf);
  l->conns[c->slot] = NULL;
  l->free_slots[l->nfree++] = c->slot;
  l->live--;
  free(c);
}

static const char *family_text(int family) {
  return family == 4 ? "v4" : family == 6 ? "v6" : "?";
}

static long io_recv(CONN *c, char *buf, size_t n) {
  if (c->tls) {
    char err[200];
    long r = cserve_tls_recv(c->tls, buf, n, err, sizeof err);
    return r;
  }
  for (;;) {
    ssize_t r = recv(c->fd, buf, n, 0);
    if (r >= 0) {
      return (long)r;
    }
    if (errno != EINTR) {
      return errno == EAGAIN || errno == EWOULDBLOCK ? CSERVE_TLS_WANT_READ
                                                     : -1;
    }
  }
}

static long io_send(CONN *c, const char *buf, size_t n) {
  if (c->tls) {
    char err[200];
    return cserve_tls_send(c->tls, buf, n, err, sizeof err);
  }
  for (;;) {
    ssize_t w = send(c->fd, buf, n, MSG_NOSIGNAL);
    if (w >= 0) {
      return (long)w;
    }
    if (errno != EINTR) {
      return errno == EAGAIN || errno == EWOULDBLOCK ? CSERVE_TLS_WANT_WRITE
                                                     : -1;
    }
  }
}

/* The last reply is out and the connection is to close. Closing a socket
 * with bytes it hasn't read makes the kernel answer with a reset, which
 * throws away whatever of the reply the client hasn't received yet -- a
 * request pipelined behind this one, a TLS record the client sent after
 * its request. So the TLS side says close_notify, the writing side is
 * shut (the client sees the end), and what still comes is read and
 * dropped, for LINGER_MS or LINGER_MAX bytes, until the client closes
 * too. */
static void linger(CSERVE_LOOP *l, CONN *c) {
  cserve_tls_close(c->tls);
  c->tls = NULL;
  shutdown(c->fd, SHUT_WR);
  c->state = S_LINGER;
  due(l, c, LINGER_MS);
  wait_for(l, c, EPOLLIN);
}

static void do_linger(CSERVE_LOOP *l, CONN *c) {
  char buf[4096];
  for (;;) {
    ssize_t r = recv(c->fd, buf, sizeof buf, 0);
    if (r > 0 && (c->lingered += (size_t)r) <= LINGER_MAX) {
      continue;
    }
    if (r < 0 && errno == EINTR) {
      continue;
    }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    }
    conn_close(l, c); /* the client's end, an error, or enough of it */
    return;
  }
}

/* --- moving between states (no I/O, no closing: see the top) --- */

/* the reply in c->rep on its way: r the request it answers (NULL: one
 * refused before it was understood) */
static void refuse(CSERVE_LOOP *l, CONN *c, int status, const char *why,
                   const CSERVE_HTTPD_REQ *r);

static void start_reply(CSERVE_LOOP *l, CONN *c, const CSERVE_HTTPD_REQ *r,
                        int keep) {
  int n = cserve_httpd_head(l->cfg.server, r, &c->rep, keep, c->ohead,
                            sizeof c->ohead, &c->chunked, &c->has_body);
  if (n < 0) {
    cserve_logf(CSERVE_LOG_WARN, "a reply's head is too long");
    cserve_httpd_release(&c->rep);
    refuse(l, c, 500, "the reply's head is too long", r);
    return;
  }
  c->keep = keep;
  c->phase = P_HEAD;
  c->seg = c->ohead;
  c->seg_len = (size_t)n;
  c->seg_off = 0;
  c->pulled = c->sent = 0;
  c->state = S_WRITE;
  due(l, c, l->cfg.timeout_ms);
  wait_for(l, c, EPOLLOUT);
}

static void refuse(CSERVE_LOOP *l, CONN *c, int status, const char *why,
                   const CSERVE_HTTPD_REQ *r) {
  cserve_httpd_release(&c->rep);
  memset(&c->rep, 0, sizeof c->rep);
  int n = snprintf(c->refusal, sizeof c->refusal, "%d %s: %s\n", status,
                   cserve_httpd_reason(status), why);
  c->rep.status = status;
  c->rep.type = "text/plain; charset=utf-8";
  c->rep.body = c->refusal;
  c->rep.len = n < 0                            ? 0
               : (size_t)n >= sizeof c->refusal ? sizeof c->refusal - 1
                                                : (size_t)n;
  if (status == 503) {
    snprintf(c->rep.headers, sizeof c->rep.headers, "Retry-After: 1\r\n");
  }
  c->understood = r != NULL;
  start_reply(l, c, r, 0);
}

static void dispatch(CSERVE_LOOP *l, CONN *c) {
  c->state = S_WORK;
  cserve_heap_remove(&l->heap, &c->timer);
  wait_for(l, c, 0);
  if (cserve_pool_submit(l->pool, c) != 0) {
    c->state = S_WRITE; /* never was the pool's */
    free(c->body);
    c->body = NULL;
    refuse(l, c, 503, "the server is busy", &c->req);
  }
}

/* c->head holds a whole head: parsed, its body (some of it, maybe all)
 * taken from what's been read, what follows it kept for the next one */
static void got_head(CSERVE_LOOP *l, CONN *c) {
  char err[256];
  size_t used = c->frame.pos;
  c->t0 = cserve_net_now();
  c->frame = (CSERVE_HTTPD_FRAME){0};
  int status = cserve_httpd_parse(c->head, &c->req, err, sizeof err);
  if (status) {
    refuse(l, c, status, err, NULL);
    return;
  }
  c->req.peer = c->peer;
  c->req.conn = NULL;
  c->req.peer_family = c->family;
  c->req.tls = c->tls != NULL;
  memcpy(c->req.peer_net, c->net, sizeof c->net);
  c->understood = 0;
  if (c->req.length > l->cfg.body_max) {
    refuse(l, c, 413, "the body is too large", NULL);
    return;
  }
  size_t extra = c->in_len - used;
  if (c->req.length > 0) {
    size_t length = (size_t)c->req.length;
    c->body = malloc(length + 1);
    if (!c->body) {
      refuse(l, c, 500, "out of memory", NULL);
      return;
    }
    c->body[length] = '\0';
    c->body_got = extra < length ? extra : length;
    memcpy(c->body, c->in + used, c->body_got);
    used += c->body_got;
  }
  memmove(c->in, c->in + used, c->in_len - used);
  c->in_len -= used;
  if (c->req.length > 0 && c->body_got < (size_t)c->req.length) {
    c->state = S_BODY;
    due(l, c, l->cfg.timeout_ms);
    wait_for(l, c, EPOLLIN);
    return;
  }
  dispatch(l, c);
}

/* --- the entry points' work --- */

static void do_read(CSERVE_LOOP *l, CONN *c) {
  while (c->state == S_HEAD || c->state == S_BODY) {
    long n;
    if (c->state == S_HEAD) {
      int status = 0;
      char err[200];
      int f = cserve_httpd_frame(&c->frame, c->in, c->in_len, c->head,
                                 sizeof c->head, &status, err, sizeof err);
      if (f == 1) {
        got_head(l, c);
        continue;
      }
      if (f < 0) {
        if (status) {
          refuse(l, c, status, err, NULL);
        } else {
          conn_close(l, c);
        }
        return;
      }
      if (c->in_len == sizeof c->in) {
        refuse(l, c, 431, "the head is too long", NULL);
        return;
      }
      n = io_recv(c, c->in + c->in_len, sizeof c->in - c->in_len);
      if (n > 0) {
        c->in_len += (size_t)n;
        continue;
      }
      /* the client gone in the middle of a head: refused, as the threaded
       * server does (it may only have stopped sending) */
      if (n == 0 && c->frame.len > 0) {
        refuse(l, c, 400, "the client stopped in its head", NULL);
        return;
      }
    } else {
      size_t need = (size_t)c->req.length - c->body_got;
      n = io_recv(c, c->body + c->body_got, need);
      if (n > 0) {
        c->body_got += (size_t)n;
        if (c->body_got == (size_t)c->req.length) {
          dispatch(l, c);
        }
        continue;
      }
    }
    if (n == 0 || n == -1) {
      conn_close(l, c);
      return;
    }
    wait_for(l, c, wanted(n));
    return;
  }
}

/* the next piece of the reply set going: 1, or 0 when the reply is all
 * out, -1 when its pulled body failed */
static int next_piece(CONN *c) {
  long long length = c->rep.stream_length;
  switch (c->phase) {
  case P_HEAD:
    if (!c->has_body) {
      return 0;
    }
    if (!c->rep.pull) {
      c->phase = P_BODY;
      c->seg = c->rep.body;
      c->seg_len = c->rep.len;
      c->seg_off = 0;
      return c->rep.len ? 1 : 0;
    }
    c->phase = P_PULL;
    /* fall through */
  case P_PULL: {
    if (!c->pull_buf && !(c->pull_buf = malloc(PULL_ROOM + PULL_CAP + 2))) {
      return -1;
    }
    char *data = c->pull_buf + PULL_ROOM;
    long got = c->rep.pull(c->rep.pull_ud, data, PULL_CAP);
    if (got < 0 || (length > 0 && c->pulled + got > length) ||
        (got == 0 && length > 0 && c->pulled != length)) {
      return -1;
    }
    if (got == 0) {
      if (!c->chunked) {
        return 0;
      }
      c->phase = P_END;
      c->seg = "0\r\n\r\n";
      c->seg_len = 5;
      c->seg_off = 0;
      return 1;
    }
    c->pulled += got;
    c->seg = data;
    c->seg_len = (size_t)got;
    if (c->chunked) {
      char size[PULL_ROOM];
      int k = snprintf(size, sizeof size, "%lx\r\n", (unsigned long)got);
      memcpy(data - k, size, (size_t)k);
      memcpy(data + got, "\r\n", 2);
      c->seg = data - k;
      c->seg_len += (size_t)k + 2;
    }
    c->seg_off = 0;
    return 1;
  }
  default:
    return 0;
  }
}

static void access_line(const CONN *c) {
  const char *t = c->understood ? c->req.target : "-";
  int path = (int)strcspn(t, "?");
  cserve_logf(CSERVE_LOG_INFO, "%s %.*s %d %lld %ldms %s",
              c->understood ? c->req.method : "-", path, t, c->rep.status,
              c->sent, cserve_net_now() - c->t0, family_text(c->family));
}

static void do_write(CSERVE_LOOP *l, CONN *c) {
  for (;;) {
    if (c->seg_off == c->seg_len) {
      int more = next_piece(c);
      if (more < 0) {
        cserve_logf(CSERVE_LOG_WARN, "a pulled body failed part-way");
        conn_close(l, c);
        return;
      }
      if (more == 0) {
        break;
      }
      continue; /* a piece may be empty: a body of length 0 */
    }
    long n = io_send(c, c->seg + c->seg_off, c->seg_len - c->seg_off);
    if (n == -1) {
      conn_close(l, c);
      return;
    }
    if (n < 0) {
      wait_for(l, c, wanted(n));
      return;
    }
    c->seg_off += (size_t)n;
    if (c->phase != P_HEAD) {
      c->sent += n;
    }
    due(l, c, l->cfg.timeout_ms);
  }
  /* all of it out */
  access_line(c);
  cserve_httpd_release(&c->rep);
  memset(&c->rep, 0, sizeof c->rep);
  if (!c->keep || l->stopping) {
    linger(l, c);
    return;
  }
  c->requests++;
  c->understood = 0;
  c->t0 = cserve_net_now();
  c->state = S_HEAD;
  due(l, c, l->cfg.idle_ms);
  wait_for(l, c, EPOLLIN);
  do_read(l, c); /* a request may be waiting already (pipelined) */
}

static void do_handshake(CSERVE_LOOP *l, CONN *c) {
  char err[256];
  int r = cserve_tls_step(c->tls, err, sizeof err);
  if (r == -1) {
    cserve_logf(CSERVE_LOG_WARN, "a TLS handshake (%s) refused: %s",
                family_text(c->family), err);
    conn_close(l, c);
    return;
  }
  if (r != 0) {
    wait_for(l, c, wanted(r));
    return;
  }
  c->state = S_HEAD;
  wait_for(l, c, EPOLLIN);
  do_read(l, c);
}

static void on_conn(CSERVE_LOOP *l, CONN *c, uint32_t ev) {
  /* a hang-up while nothing is read or written: no one to answer */
  if ((ev & EPOLLERR) ||
      ((ev & EPOLLHUP) && (c->state == S_WORK || c->state == S_PARKED))) {
    conn_close(l, c);
    return;
  }
  switch (c->state) {
  case S_HANDSHAKE:
    do_handshake(l, c);
    break;
  case S_HEAD:
  case S_BODY:
    do_read(l, c);
    break;
  case S_WRITE:
    do_write(l, c);
    break;
  case S_LINGER:
    do_linger(l, c);
    break;
  default:
    break;
  }
}

/* the handler's reply on its way */
static void send_reply(CSERVE_LOOP *l, CONN *c) {
  int keep =
      !l->stopping && cserve_httpd_keep(&c->req, &c->rep,
                                        c->requests + 1 < l->cfg.max_requests);
  start_reply(l, c, &c->req, keep);
}

static void on_pool(CSERVE_LOOP *l) {
  for (CONN *c; (c = cserve_pool_take(l->pool));) {
    free(c->body);
    c->body = NULL;
    c->state = S_WRITE; /* the pool's no longer */
    if (c->dead) {
      conn_close(l, c);
      continue;
    }
    c->understood = 1;
    if (c->rep.delay_ms > 0 && !l->stopping) {
      if (l->parked >= l->cfg.parked_max) {
        conn_close(l, c);
        continue;
      }
      /* held back: the connection waits, nothing else does */
      c->state = S_PARKED;
      l->parked++;
      due(l, c, c->rep.delay_ms);
      wait_for(l, c, 0);
      continue;
    }
    send_reply(l, c);
  }
}

static void on_deadline(CSERVE_LOOP *l, CONN *c) {
  if (c->state == S_PARKED) {
    l->parked--;
    c->state = S_WRITE;
    send_reply(l, c);
    return;
  }
  if (c->state == S_HEAD && c->frame.len > 0) {
    refuse(l, c, 400, "the head took too long", NULL);
    due(l, c, REFUSAL_MS);
    return;
  }
  conn_close(l, c);
}

/* the address's network (an IPv4 address, an IPv6 /64) into net: its
 * family, 4 or 6; 0 for anything else */
static int addr_net(const struct sockaddr_storage *sa, unsigned char net[16]) {
  memset(net, 0, 16);
  if (sa->ss_family == AF_INET) {
    memcpy(net, &((const struct sockaddr_in *)sa)->sin_addr, 4);
    return 4;
  }
  if (sa->ss_family == AF_INET6) {
    const struct in6_addr *a = &((const struct sockaddr_in6 *)sa)->sin6_addr;
    if (IN6_IS_ADDR_V4MAPPED(a)) {
      memcpy(net, a->s6_addr + 12, 4);
      return 4;
    }
    memcpy(net, a->s6_addr, 8);
    return 6;
  }
  return 0;
}

static int from_net(const CSERVE_LOOP *l, int family,
                    const unsigned char net[16]) {
  int n = 0;
  for (int i = 0; i < l->cfg.max_conns; i++) {
    const CONN *c = l->conns[i];
    n += c && c->family == family && !memcmp(c->net, net, 16);
  }
  return n;
}

static void on_accept(CSERVE_LOOP *l, int i) {
  for (;;) {
    struct sockaddr_storage sa = {0};
    socklen_t len = sizeof sa;
    int fd = accept4(l->ls[i].fd, (struct sockaddr *)&sa, &len,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      return; /* none left (or the next readiness tries again) */
    }
    unsigned char net[16];
    int family = addr_net(&sa, net);
    if (l->live >= l->cfg.max_conns || l->nfree == 0 ||
        from_net(l, family, net) >= l->cfg.per_addr) {
      close(fd);
      continue;
    }
    CONN *c = calloc(1, sizeof *c);
    if (!c) {
      close(fd);
      continue;
    }
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    c->timer = (CSERVE_HEAP_NODE)CSERVE_HEAP_NODE_INIT;
    c->fd = fd;
    c->family = family;
    memcpy(c->net, net, sizeof net);
    cserve_listen_peer(&sa, c->peer, sizeof c->peer);
    c->slot = l->free_slots[--l->nfree];
    c->gen = ++l->gen;
    l->conns[c->slot] = c;
    l->live++;
    c->state = S_HEAD;
    c->events = EPOLLIN;
    c->t0 = cserve_net_now();
    struct epoll_event ev = {.events = EPOLLIN,
                             .data.u64 = TAG(K_CONN, c->gen, c->slot)};
    char err[200];
    if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &ev) != 0 ||
        (l->ls[i].tls && !(c->tls = cserve_tls_server_start(
                               fd, l->ls[i].tls, err, sizeof err)))) {
      conn_close(l, c);
      continue;
    }
    if (c->tls) {
      c->state = S_HANDSHAKE;
    }
    due(l, c, l->cfg.timeout_ms);
  }
}

/* stop_fd turned readable: no more connections, and the idle ones go --
 * a held-back reply's too, which is closed rather than answered early */
static void begin_stop(CSERVE_LOOP *l, int stop_fd) {
  l->stopping = 1;
  epoll_ctl(l->ep, EPOLL_CTL_DEL, stop_fd, NULL);
  for (int i = 0; i < l->nls; i++) {
    epoll_ctl(l->ep, EPOLL_CTL_DEL, l->ls[i].fd, NULL);
    close(l->ls[i].fd);
    l->ls[i].fd = -1;
  }
  for (int i = 0; i < l->cfg.max_conns; i++) {
    CONN *c = l->conns[i];
    if (c && (c->state == S_HANDSHAKE || c->state == S_PARKED ||
              (c->state == S_HEAD && c->in_len == 0))) {
      conn_close(l, c);
    }
  }
}

/* --- the loop --- */

CSERVE_LOOP *cserve_loop_new(const CSERVE_LOOP_CONFIG *cfg, char *err,
                             size_t err_cap) {
  CSERVE_LOOP *l = calloc(1, sizeof *l);
  if (!l) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  l->cfg = *cfg;
  CSERVE_LOOP_CONFIG *c = &l->cfg;
  c->body_max = c->body_max > 0 ? c->body_max : 1 << 20;
  c->idle_ms = c->idle_ms > 0 ? c->idle_ms : 10000;
  c->timeout_ms = c->timeout_ms > 0 ? c->timeout_ms : 30000;
  c->max_requests = c->max_requests > 0 ? c->max_requests : 100;
  c->workers = c->workers > 0 ? c->workers : 4;
  c->queue = c->queue > 0 ? c->queue : 64;
  c->max_conns = c->max_conns > 0 ? c->max_conns : 1024;
  c->per_addr = c->per_addr > 0 ? c->per_addr : 32;
  c->parked_max = c->parked_max > 0 ? c->parked_max : 256;
  l->ep = -1;
  /* every connection is an fd, and a listener that can't accept for want
   * of one stays readable: the loop would spin. So there's room for all
   * of them, or the loop doesn't start. */
  struct rlimit rl;
  rlim_t need = (rlim_t)c->max_conns + 64;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < need) {
    rl.rlim_cur = rl.rlim_max < need ? rl.rlim_max : need;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur < need) {
      snprintf(err, err_cap,
               "%d connections need %lu open files, and the limit is %lu",
               c->max_conns, (unsigned long)need, (unsigned long)rl.rlim_cur);
      cserve_loop_free(l);
      return NULL;
    }
  }
  l->conns = calloc((size_t)c->max_conns, sizeof *l->conns);
  l->free_slots = calloc((size_t)c->max_conns, sizeof *l->free_slots);
  l->ep = epoll_create1(EPOLL_CLOEXEC);
  if (!l->conns || !l->free_slots || l->ep < 0 ||
      cserve_heap_init(&l->heap, c->max_conns) != 0) {
    snprintf(err, err_cap, "%s", l->ep < 0 ? strerror(errno) : "out of memory");
    cserve_loop_free(l);
    return NULL;
  }
  for (int i = c->max_conns - 1; i >= 0; i--) {
    l->free_slots[l->nfree++] = i;
  }
  if (!(l->pool =
            cserve_pool_new(c->workers, c->queue, work, l, err, err_cap))) {
    cserve_loop_free(l);
    return NULL;
  }
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = TAG(K_POOL, 0, 0)};
  if (epoll_ctl(l->ep, EPOLL_CTL_ADD, cserve_pool_fd(l->pool), &ev) != 0) {
    snprintf(err, err_cap, "epoll: %s", strerror(errno));
    cserve_loop_free(l);
    return NULL;
  }
  return l;
}

int cserve_loop_listen(CSERVE_LOOP *l, int fd, CSERVE_TLS_SERVER *tls,
                       char *err, size_t err_cap) {
  if (l->nls == LISTEN_MAX) {
    snprintf(err, err_cap, "more than %d listeners", LISTEN_MAX);
    return -1;
  }
  struct epoll_event ev = {.events = EPOLLIN,
                           .data.u64 = TAG(K_LISTEN, 0, l->nls)};
  if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
    snprintf(err, err_cap, "epoll: %s", strerror(errno));
    return -1;
  }
  l->ls[l->nls].fd = fd;
  l->ls[l->nls].tls = tls;
  l->nls++;
  return 0;
}

int cserve_loop_watch(CSERVE_LOOP *l, int fd, void (*fn)(void *ud), void *ud,
                      char *err, size_t err_cap) {
  if (l->nws == WATCH_MAX) {
    snprintf(err, err_cap, "more than %d watched fds", WATCH_MAX);
    return -1;
  }
  l->ws[l->nws].fn = fn;
  l->ws[l->nws].ud = ud;
  struct epoll_event ev = {.events = EPOLLIN,
                           .data.u64 = TAG(K_WATCH, 0, l->nws)};
  if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
    snprintf(err, err_cap, "epoll: %s", strerror(errno));
    return -1;
  }
  l->nws++;
  return 0;
}

int cserve_loop_run(CSERVE_LOOP *l, int stop_fd, int grace_ms, char *err,
                    size_t err_cap) {
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = TAG(K_STOP, 0, 0)};
  if (epoll_ctl(l->ep, EPOLL_CTL_ADD, stop_fd, &ev) != 0) {
    snprintf(err, err_cap, "epoll: %s", strerror(errno));
    return -1;
  }
  grace_ms = grace_ms > 0 ? grace_ms : 5000;
  long grace_until = 0;
  int ret = 0;
  for (;;) {
    long now = cserve_net_now();
    if (l->stopping && (l->live == 0 || now >= grace_until)) {
      break;
    }
    const CSERVE_HEAP_NODE *first = cserve_heap_min(&l->heap);
    long until = first ? first->at : -1;
    if (l->stopping && (until < 0 || grace_until < until)) {
      until = grace_until;
    }
    int wait = until < 0             ? -1
               : until <= now        ? 0
               : until - now > 60000 ? 60000
                                     : (int)(until - now);
    struct epoll_event evs[EVENTS];
    int n = epoll_wait(l->ep, evs, EVENTS, wait);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      snprintf(err, err_cap, "epoll: %s", strerror(errno));
      ret = -1;
      break;
    }
    for (int i = 0; i < n; i++) {
      uint64_t t = evs[i].data.u64;
      int kind = TAG_KIND(t), k = TAG_INDEX(t);
      if (kind == K_STOP && !l->stopping) {
        begin_stop(l, stop_fd);
        grace_until = cserve_net_now() + grace_ms;
      } else if (kind == K_LISTEN && !l->stopping) {
        on_accept(l, k);
      } else if (kind == K_POOL) {
        on_pool(l);
      } else if (kind == K_WATCH && k < l->nws) {
        l->ws[k].fn(l->ws[k].ud);
      } else if (kind == K_CONN && k < l->cfg.max_conns) {
        CONN *c = l->conns[k];
        if (c && c->fd >= 0 && (c->gen & 0xffffff) == TAG_GEN(t)) {
          on_conn(l, c, evs[i].events);
        }
      }
    }
    now = cserve_net_now();
    for (CSERVE_HEAP_NODE *m;
         (m = cserve_heap_min(&l->heap)) && m->at <= now;) {
      cserve_heap_remove(&l->heap, m);
      on_deadline(l, (CONN *)m);
    }
  }
  /* the grace is over: whatever's left is cut */
  for (int i = 0; i < l->cfg.max_conns; i++) {
    if (l->conns[i] && l->conns[i]->fd >= 0) {
      conn_close(l, l->conns[i]);
    }
  }
  return ret;
}

void cserve_loop_free(CSERVE_LOOP *l) {
  if (!l) {
    return;
  }
  /* the pool runs what it holds, then hands back every connection it
   * had: all of them dead by now */
  cserve_pool_free(l->pool);
  l->pool = NULL;
  for (int i = 0; l->conns && i < l->cfg.max_conns; i++) {
    CONN *c = l->conns[i];
    if (c) {
      c->state = S_WRITE;
      conn_close(l, c);
    }
  }
  for (int i = 0; i < l->nls; i++) {
    if (l->ls[i].fd >= 0) {
      close(l->ls[i].fd);
    }
  }
  cserve_heap_free(&l->heap);
  free(l->conns);
  free(l->free_slots);
  if (l->ep >= 0) {
    close(l->ep);
  }
  free(l);
}

int cserve_loop_conns(const CSERVE_LOOP *l) { return atomic_load(&l->live); }
