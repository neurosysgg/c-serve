/* A loop's streams (loop.h, httpd.h): a reply that stays open, parked
 * while it has nothing to say, woken from any thread or by its heartbeat
 * and pulled again. A wake carries no news, only "look again", and names
 * its connection by slot and generation, so one for a stream that has
 * gone lands on nothing. The rest of the loop is loop.c. */
#include "loop_conn.h"

#include "tls.h"

#include <sys/epoll.h>

/* a waiting stream readable: the client went (or sent what a stream
 * doesn't take, which ends it too); a TLS record that was only the
 * protocol's own is waited past */
void cserve_loop_stream_read(CSERVE_LOOP *l, CONN *c) {
  char buf[512];
  long r = cserve_loop_recv(c, buf, sizeof buf);
  if (r == CSERVE_TLS_WANT_READ) {
    return;
  }
  cserve_loop_close(l, c);
}

/* a waiting stream pulled again: woken, or its heartbeat due */
void cserve_loop_resume(CSERVE_LOOP *l, CONN *c) {
  c->state = S_WRITE;
  cserve_loop_due(l, c, l->cfg.timeout_ms);
  cserve_loop_wait_for(l, c, EPOLLOUT);
  cserve_loop_write(l, c);
}

void cserve_stream_wake(CSERVE_STREAM s) {
  CSERVE_LOOP *l = s.loop;
  if (l && s.slot >= 0 && s.slot < l->cfg.max_conns) {
    cserve_wake_post(l->wake, TAG(K_CONN, s.gen, s.slot));
  }
}

/* the wakes posted since the last: each waiting stream they name pulled
 * again; a wake for a slot now someone else's, or one not waiting, lands
 * on nothing. Overflowed: every waiting stream is pulled. */
void cserve_loop_on_wake(CSERVE_LOOP *l) {
  uint64_t tags[256];
  int overflowed = 0, any_over = 0;
  for (size_t n; (n = cserve_wake_take(l->wake, tags, 256, &overflowed)) > 0 ||
                 overflowed;) {
    any_over |= overflowed;
    for (size_t i = 0; i < n; i++) {
      int k = TAG_INDEX(tags[i]);
      CONN *c = k < l->cfg.max_conns ? l->conns[k] : NULL;
      if (c && c->fd >= 0 && c->state == S_STREAM &&
          (c->gen & 0xffffff) == TAG_GEN(tags[i])) {
        cserve_loop_resume(l, c);
      }
    }
    if (n < 256) {
      break;
    }
  }
  for (int i = 0; any_over && i < l->cfg.max_conns; i++) {
    CONN *c = l->conns[i];
    if (c && c->fd >= 0 && c->state == S_STREAM) {
      cserve_loop_resume(l, c);
    }
  }
}
