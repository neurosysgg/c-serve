#ifndef CSERVE_LOOP_CONN_H
#define CSERVE_LOOP_CONN_H

/* The loop's insides, shared by loop.c and stream.c alone: a
 * connection, the loop, and what each file calls in the other. Nothing
 * outside those two includes it (loop.h is the loop's interface). */

#include "heap.h"
#include "loop.h"
#include "pool.h"
#include "wake.h"

#include <stdatomic.h>
#include <stdint.h>

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

enum {
  S_HANDSHAKE,
  S_HEAD,
  S_BODY,
  S_WORK,
  S_PARKED,
  S_WRITE,
  S_STREAM, /* a stream with nothing to send: waiting for a wake */
  S_LINGER
};

/* the reply's pieces, in the order they go */
enum { P_HEAD, P_BODY, P_PULL, P_END };

/* what an event is for: kind, and for a connection its slot and the
 * generation it had when it was registered (a slot is reused; an event
 * still queued for the one that left must not land on the new one) */
enum { K_LISTEN = 1, K_POOL, K_STOP, K_CONN, K_WATCH, K_WAKE };
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
  int requests;  /* answered on it so far */
  int slow;      /* the pool has its request in the slow lane */
  int streaming; /* its reply is a stream (counted in streams) */
  long t0;       /* when the request's head was complete */
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
  int slow_out;      /* slow requests the pool has (the loop's thread only) */
  int streams;       /* replies streaming now */
  CSERVE_WAKE *wake; /* streams woken from other threads */
  atomic_int live;   /* read by cserve_loop_conns() from any thread */
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

/* in loop.c */
void cserve_loop_wait_for(CSERVE_LOOP *l, CONN *c, uint32_t events);
void cserve_loop_due(CSERVE_LOOP *l, CONN *c, long ms);
void cserve_loop_close(CSERVE_LOOP *l, CONN *c);
void cserve_loop_write(CSERVE_LOOP *l, CONN *c);
long cserve_loop_recv(CONN *c, char *buf, size_t n);

/* in stream.c */
void cserve_loop_stream_read(CSERVE_LOOP *l, CONN *c);
void cserve_loop_resume(CSERVE_LOOP *l, CONN *c);
void cserve_loop_on_wake(CSERVE_LOOP *l);

#endif
