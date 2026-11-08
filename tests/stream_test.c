/* loop.h's streams on a real loop: a reply that stays open, its head
 * and first piece out at once; news from another thread woken onto it;
 * the heartbeat pulling it when nothing comes; a client that leaves
 * (done() once, the slot freed); the cap (a 503 before any head); a stop
 * with a stream open; and a wake for a stream that's gone landing on
 * nothing, even when its slot is someone else's now. */
#define _GNU_SOURCE

#include "listen.h"
#include "loop.h"

#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* one stream's state, shared with the test's thread */
typedef struct {
  pthread_mutex_t lock;
  char news[256]; /* what the next pull says ("" nothing) */
  int greeted;    /* the first piece went */
  int pulls, done;
  int has_handle;
  CSERVE_STREAM handle;
} STATE;

static STATE g = {.lock = PTHREAD_MUTEX_INITIALIZER};

static long pull(void *ud, char *buf, size_t cap) {
  STATE *s = ud;
  pthread_mutex_lock(&s->lock);
  s->pulls++;
  long n = CSERVE_PULL_WAIT;
  const char *say = !s->greeted ? "hello\n" : s->news[0] ? s->news : NULL;
  if (say && strlen(say) < cap) {
    n = (long)strlen(say);
    memcpy(buf, say, (size_t)n);
    if (!s->greeted) {
      s->greeted = 1;
    } else {
      s->news[0] = '\0';
    }
  }
  pthread_mutex_unlock(&s->lock);
  return n;
}

static void done(void *ud) {
  STATE *s = ud;
  pthread_mutex_lock(&s->lock);
  s->done++;
  s->has_handle = 0;
  pthread_mutex_unlock(&s->lock);
}

static void opened(void *ud, CSERVE_STREAM h) {
  STATE *s = ud;
  pthread_mutex_lock(&s->lock);
  s->handle = h;
  s->has_handle = 1;
  pthread_mutex_unlock(&s->lock);
}

static void handler(const CSERVE_HTTPD_REQ *r, const char *body,
                    CSERVE_HTTPD_REPLY *rep, void *ud) {
  (void)body;
  (void)ud;
  if (!strcmp(r->path, "/stream")) {
    pthread_mutex_lock(&g.lock);
    g.greeted = 0;
    g.news[0] = '\0';
    pthread_mutex_unlock(&g.lock);
    rep->status = 200;
    rep->type = "text/event-stream";
    rep->pull = pull;
    rep->done = done;
    rep->pull_ud = &g;
    rep->stream = 1;
    rep->opened = opened;
  } else {
    cserve_httpd_text(rep, 200, "text/plain", "hi there", 8);
  }
}

typedef struct {
  CSERVE_LOOP *loop;
  pthread_t thread;
  int stop[2];
  int port;
} RUN;

static void *run_loop(void *arg) {
  RUN *r = arg;
  char err[200];
  (void)cserve_loop_run(r->loop, r->stop[0], 2000, err, sizeof err);
  return NULL;
}

static int start(RUN *r, CSERVE_LOOP_CONFIG cfg) {
  char err[200];
  cfg.handler = handler;
  memset(r, 0, sizeof *r);
  r->loop = cserve_loop_new(&cfg, err, sizeof err);
  int fd = r->loop
               ? cserve_listen_socket("127.0.0.1", 0, &r->port, err, sizeof err)
               : -1;
  if (fd < 0 || cserve_loop_listen(r->loop, fd, NULL, err, sizeof err) != 0 ||
      pipe(r->stop) != 0) {
    printf("    the loop: %s\n", err);
    return -1;
  }
  return pthread_create(&r->thread, NULL, run_loop, r);
}

static long ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void stop(RUN *r) {
  (void)!write(r->stop[1], "x", 1);
  pthread_join(r->thread, NULL);
  cserve_loop_free(r->loop);
  close(r->stop[0]);
  close(r->stop[1]);
}

static int dial(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static void say(int fd, const char *s) {
  (void)!send(fd, s, strlen(s), MSG_NOSIGNAL);
}

/* what fd says within ms, appended to buf (len so far): 1 once want is
 * in it, 0 when the time ran out or the connection closed first */
static int heard(int fd, char *buf, size_t cap, size_t *len, const char *want,
                 int ms) {
  long until = ms_now() + ms;
  while (!strstr(buf, want)) {
    long left = until - ms_now();
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (left <= 0 || poll(&p, 1, (int)left) <= 0) {
      return 0;
    }
    ssize_t n = recv(fd, buf + *len, cap - 1 - *len, 0);
    if (n <= 0) {
      return strstr(buf, want) != NULL;
    }
    *len += (size_t)n;
    buf[*len] = '\0';
  }
  return 1;
}

static int handle(CSERVE_STREAM *h) {
  pthread_mutex_lock(&g.lock);
  int has = g.has_handle;
  *h = g.handle;
  pthread_mutex_unlock(&g.lock);
  return has;
}

static void news(const char *text) {
  pthread_mutex_lock(&g.lock);
  snprintf(g.news, sizeof g.news, "%s", text);
  pthread_mutex_unlock(&g.lock);
}

/* until the stream has been pulled past its greeting -- the loop pulls
 * again right after a piece, and only a WAIT parks it -- (2 s at most) */
static void until_waiting(int pulls_before) {
  long until = ms_now() + 2000;
  for (;;) {
    pthread_mutex_lock(&g.lock);
    int pulls = g.pulls;
    pthread_mutex_unlock(&g.lock);
    if (pulls >= pulls_before + 2 || ms_now() > until) {
      return;
    }
    usleep(5000);
  }
}

static int pulls_now(void) {
  pthread_mutex_lock(&g.lock);
  int p = g.pulls;
  pthread_mutex_unlock(&g.lock);
  return p;
}

static int done_count(void) {
  pthread_mutex_lock(&g.lock);
  int d = g.done;
  pthread_mutex_unlock(&g.lock);
  return d;
}

/* a thread that wakes the stream: as a handler on a worker would */
static void *waker(void *arg) {
  CSERVE_STREAM *h = arg;
  news("news from elsewhere\n");
  cserve_stream_wake(*h);
  return NULL;
}

static void test_stream(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.heartbeat_ms = 60000};
  if (start(&r, cfg) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop for streams");
    return;
  }
  char buf[8192] = "";
  size_t len = 0;
  int fd = dial(r.port);
  say(fd, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
  CSERVE_TEST_ASSERT(heard(fd, buf, sizeof buf, &len, "hello\n", 2000) &&
                         strstr(buf, "Transfer-Encoding: chunked\r\n") &&
                         strstr(buf, "Connection: close\r\n"),
                     "a stream: its head and first piece at once, chunked, "
                     "the connection not kept");
  CSERVE_STREAM h;
  CSERVE_TEST_ASSERT(handle(&h), "opened() gave the handle");
  pthread_t t;
  pthread_create(&t, NULL, waker, &h);
  pthread_join(t, NULL);
  CSERVE_TEST_ASSERT(
      heard(fd, buf, sizeof buf, &len, "news from elsewhere", 2000),
      "a wake from another thread: the news follows");
  /* nothing more: no wake, no heartbeat for a minute -- it waits */
  size_t before = len;
  heard(fd, buf, sizeof buf, &len, "never said", 300);
  CSERVE_TEST_ASSERT(len == before && cserve_loop_conns(r.loop) == 1,
                     "nothing to say: it waits, still open");
  int other = dial(r.port);
  char got[512] = "";
  size_t glen = 0;
  say(other, "GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  CSERVE_TEST_ASSERT(heard(other, got, sizeof got, &glen, "hi there", 2000),
                     "and a page beside it is answered");
  close(other);
  close(fd);
  long until = ms_now() + 2000;
  while (done_count() < 1 && ms_now() < until) {
    usleep(10000);
  }
  usleep(50000);
  CSERVE_TEST_ASSERT(done_count() == 1 && cserve_loop_conns(r.loop) == 0,
                     "the client gone: done() once, the connection freed");

  /* a stale handle: the next stream likely has the same slot */
  CSERVE_STREAM stale = h;
  memset(buf, 0, sizeof buf);
  len = 0;
  int p0 = pulls_now();
  fd = dial(r.port);
  say(fd, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
  heard(fd, buf, sizeof buf, &len, "hello\n", 2000);
  until_waiting(p0);
  news("for the new one only when woken\n");
  cserve_stream_wake(stale);
  before = len;
  heard(fd, buf, sizeof buf, &len, "for the new one", 300);
  CSERVE_TEST_ASSERT(len == before,
                     "a wake for a stream that's gone: lands on nothing");
  CSERVE_STREAM now;
  handle(&now);
  cserve_stream_wake(now);
  CSERVE_TEST_ASSERT(heard(fd, buf, sizeof buf, &len, "for the new one", 2000),
                     "its own handle wakes it");
  /* a stop with the stream open: it ends, done() is called */
  int d = done_count();
  long t0 = ms_now();
  stop(&r);
  CSERVE_TEST_ASSERT(ms_now() - t0 < 1500 && done_count() == d + 1,
                     "a stop: the waiting stream closed at once, done() once");
  close(fd);
}

static void test_heartbeat(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.heartbeat_ms = 200};
  if (start(&r, cfg) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop with a short heartbeat");
    return;
  }
  char buf[4096] = "";
  size_t len = 0;
  int fd = dial(r.port);
  say(fd, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
  heard(fd, buf, sizeof buf, &len, "hello\n", 2000);
  pthread_mutex_lock(&g.lock);
  int p0 = g.pulls;
  pthread_mutex_unlock(&g.lock);
  usleep(700000);
  pthread_mutex_lock(&g.lock);
  int pulls = g.pulls - p0;
  pthread_mutex_unlock(&g.lock);
  CSERVE_TEST_ASSERT(pulls >= 2 && pulls <= 5,
                     "the heartbeat: pulled about every 200 ms (%d in 700)",
                     pulls);
  close(fd);
  stop(&r);
}

static void test_cap(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.streams_max = 1, .heartbeat_ms = 60000};
  if (start(&r, cfg) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop for one stream");
    return;
  }
  char a[4096] = "", b[4096] = "";
  size_t al = 0, bl = 0;
  int fa = dial(r.port), fb = dial(r.port);
  say(fa, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
  heard(fa, a, sizeof a, &al, "hello\n", 2000);
  say(fb, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
  CSERVE_TEST_ASSERT(heard(fb, b, sizeof b, &bl, "no room for another", 2000) &&
                         strstr(b, " 503 ") && strstr(b, "Retry-After"),
                     "past streams_max: a 503 before any head");
  close(fb);
  close(fa);
  stop(&r);
}

int main(void) {
  test_stream();
  test_heartbeat();
  test_cap();
  return cserve_test_summary();
}
