/* src/loop.c: the loop served in-process on port 0, with short deadlines,
 * and spoken to over raw sockets -- keep-alive and pipelining, a body in
 * pieces, pulled bodies (chunked, sized, cut short, under HEAD and
 * HTTP/1.0), the limits (413, 431, the pool's 503, per network), every
 * deadline (a head sent too slowly, an idle connection), a client gone
 * while the pool has its request, TLS with a client that reads slowly, a
 * stop with a request in flight, and the access log, which never names
 * an address. ASan (make check) watches every connection's memory. */
#define _GNU_SOURCE

#include "listen.h"
#include "log.h"
#include "loop.h"

#include "test.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BIG (1 << 20)
#define HUGE (8 << 20) /* past what the kernel buffers: the loop must wait */

/* --- the handler --- */

static pthread_mutex_t g_gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_gate_cond = PTHREAD_COND_INITIALIZER;
static int g_gate_open = 1;

static void gate(int open) {
  pthread_mutex_lock(&g_gate_lock);
  g_gate_open = open;
  pthread_cond_broadcast(&g_gate_cond);
  pthread_mutex_unlock(&g_gate_lock);
}

typedef struct {
  long long at, end; /* the pattern's bytes so far, and where it ends */
} PULLED;

static long pattern(void *ud, char *buf, size_t cap) {
  PULLED *p = ud;
  size_t n = 0;
  while (n < cap && p->at < p->end) {
    buf[n++] = (char)('a' + p->at++ % 26);
  }
  return (long)n;
}

static void pulled(CSERVE_HTTPD_REPLY *rep, long long end, long long length) {
  PULLED *p = calloc(1, sizeof *p);
  p->end = end;
  rep->status = 200;
  rep->type = "text/plain";
  rep->pull = pattern;
  rep->done = free;
  rep->pull_ud = p;
  rep->stream_length = length;
}

static void handler(const CSERVE_HTTPD_REQ *r, const char *body,
                    CSERVE_HTTPD_REPLY *rep, void *ud) {
  (void)ud;
  if (!strcmp(r->path, "/hi")) {
    cserve_httpd_text(rep, 200, "text/plain", "hi there", 8);
  } else if (!strcmp(r->path, "/echo")) {
    cserve_httpd_text(rep, 200, "text/plain", body ? body : "",
                      body ? (size_t)r->length : 0);
  } else if (!strcmp(r->path, "/big")) {
    pulled(rep, BIG, 0);
  } else if (!strcmp(r->path, "/huge")) {
    pulled(rep, HUGE, 0);
  } else if (!strcmp(r->path, "/sized")) {
    pulled(rep, 300000, 300000);
  } else if (!strcmp(r->path, "/short")) {
    pulled(rep, 50, 100);
  } else if (!strcmp(r->path, "/block")) {
    pthread_mutex_lock(&g_gate_lock);
    while (!g_gate_open) {
      pthread_cond_wait(&g_gate_cond, &g_gate_lock);
    }
    pthread_mutex_unlock(&g_gate_lock);
    cserve_httpd_text(rep, 200, "text/plain", "let through", 11);
  } else if (!strcmp(r->path, "/slow")) {
    struct timespec ts = {0, 200 * 1000000L};
    nanosleep(&ts, NULL);
    cserve_httpd_text(rep, 200, "text/plain", "slowly", 6);
  } else if (!strcmp(r->path, "/peer")) {
    char text[64];
    int n = snprintf(text, sizeof text, "%d %d.%d.%d.%d", r->peer_family,
                     r->peer_net[0], r->peer_net[1], r->peer_net[2],
                     r->peer_net[3]);
    cserve_httpd_text(rep, 200, "text/plain", text, (size_t)n);
  } else {
    cserve_httpd_text(rep, 404, "text/plain", "nope", 4);
  }
}

/* --- the access log, caught --- */

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_log[16384];
static size_t g_log_len;

static void catch_log(CSERVE_LOG_LEVEL level, const char *line, void *ud) {
  (void)ud;
  if (level != CSERVE_LOG_INFO) {
    fprintf(stderr, "    (the loop: %s)\n", line);
    return;
  }
  pthread_mutex_lock(&g_log_lock);
  int n = snprintf(g_log + g_log_len, sizeof g_log - g_log_len, "%s\n", line);
  if (n > 0 && g_log_len + (size_t)n < sizeof g_log) {
    g_log_len += (size_t)n;
  }
  pthread_mutex_unlock(&g_log_lock);
}

/* --- a loop on a thread of its own --- */

typedef struct {
  CSERVE_LOOP *loop;
  pthread_t thread;
  int stop[2];
  int port;
  int rc;
} RUN;

static void *run_loop(void *arg) {
  RUN *r = arg;
  char err[200];
  r->rc = cserve_loop_run(r->loop, r->stop[0], 2000, err, sizeof err);
  return NULL;
}

static int start(RUN *r, CSERVE_LOOP_CONFIG cfg, CSERVE_TLS_SERVER *tls) {
  char err[200];
  cfg.handler = handler;
  cfg.server = "test";
  memset(r, 0, sizeof *r);
  r->loop = cserve_loop_new(&cfg, err, sizeof err);
  int fd = r->loop
               ? cserve_listen_socket("127.0.0.1", 0, &r->port, err, sizeof err)
               : -1;
  if (fd < 0 || cserve_loop_listen(r->loop, fd, tls, err, sizeof err) != 0 ||
      pipe(r->stop) != 0) {
    printf("    the loop: %s\n", err);
    return -1;
  }
  return pthread_create(&r->thread, NULL, run_loop, r);
}

static void stop(RUN *r) {
  (void)!write(r->stop[1], "x", 1);
  pthread_join(r->thread, NULL);
  cserve_loop_free(r->loop);
  close(r->stop[0]);
  close(r->stop[1]);
}

/* --- a client --- */

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

/* everything until the server closes, or ms of quiet: the bytes
 * (malloc'd, NUL-terminated), their count in *len, and whether it closed
 * in *closed */
static char *drain(int fd, int ms, size_t *len, int *closed) {
  size_t cap = BIG + 65536;
  char *buf = malloc(cap + 1);
  *len = 0;
  *closed = 0;
  struct pollfd p = {.fd = fd, .events = POLLIN};
  while (*len < cap && poll(&p, 1, ms) > 0) {
    ssize_t r = recv(fd, buf + *len, cap - *len, 0);
    if (r <= 0) {
      *closed = 1;
      break;
    }
    *len += (size_t)r;
  }
  buf[*len] = '\0';
  return buf;
}

static int count(const char *hay, const char *needle) {
  int n = 0;
  for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle)) {
    n++;
  }
  return n;
}

/* a chunked body after the head decoded in place: its length, or -1 */
static long dechunk(const char *reply, char *out, size_t cap) {
  const char *p = strstr(reply, "\r\n\r\n");
  size_t n = 0;
  if (!p) {
    return -1;
  }
  for (p += 4;;) {
    char *end;
    unsigned long k = strtoul(p, &end, 16);
    if (end == p || strncmp(end, "\r\n", 2) != 0) {
      return -1;
    }
    p = end + 2;
    if (k == 0) {
      return strncmp(p, "\r\n", 2) == 0 ? (long)n : -1;
    }
    if (n + k > cap) {
      return -1;
    }
    memcpy(out + n, p, k);
    n += k;
    p += k;
    if (strncmp(p, "\r\n", 2) != 0) {
      return -1;
    }
    p += 2;
  }
}

static int is_pattern(const char *b, long long n) {
  for (long long i = 0; i < n; i++) {
    if (b[i] != (char)('a' + i % 26)) {
      return 0;
    }
  }
  return 1;
}

/* --- the cases --- */

static void test_http(int port) {
  size_t len;
  int closed;
  int fd = dial(port);
  say(fd, "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n"
          "GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  char *got = drain(fd, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(count(got, "hi there") == 2 && closed &&
                         count(got, "Connection: keep-alive") == 1,
                     "two requests in one write: both answered, in turn");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
          "Connection: close\r\n\r\nhello");
  struct timespec ts = {0, 50 * 1000000L};
  nanosleep(&ts, NULL);
  say(fd, " world");
  got = drain(fd, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, " 200 ") && strstr(got, "\r\n\r\nhello world"),
                     "a body sent in two pieces, read whole");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  char *body = malloc(BIG);
  long n = dechunk(got, body, BIG);
  CSERVE_TEST_ASSERT(strstr(got, "Transfer-Encoding: chunked\r\n") &&
                         n == BIG && is_pattern(body, BIG),
                     "a pulled body: chunked, a MiB of it, every byte right");
  free(got);
  free(body);
  close(fd);

  /* a small window and a slow reader: the loop's writes wait, and go on */
  fd = dial(port);
  int small = 4096;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
  say(fd, "GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  size_t slow_cap = BIG + 65536;
  char *slow = malloc(slow_cap + 1);
  len = 0;
  struct pollfd sp = {.fd = fd, .events = POLLIN};
  for (int k = 0; len < slow_cap && poll(&sp, 1, 3000) > 0; k++) {
    if (k % 64 == 0) {
      struct timespec pause = {0, 2 * 1000000L};
      nanosleep(&pause, NULL);
    }
    ssize_t r = recv(fd, slow + len, 4096, 0);
    if (r <= 0) {
      break;
    }
    len += (size_t)r;
  }
  slow[len] = '\0';
  body = malloc(BIG);
  n = dechunk(slow, body, BIG);
  CSERVE_TEST_ASSERT(n == BIG && is_pattern(body, BIG),
                     "to a slow reader with a small window: a MiB, every byte "
                     "(%zu came)",
                     len);
  free(slow);
  free(body);
  close(fd);

  fd = dial(port);
  say(fd, "GET /sized HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  const char *at = strstr(got, "\r\n\r\n");
  CSERVE_TEST_ASSERT(strstr(got, "Content-Length: 300000\r\n") && at &&
                         len - (size_t)(at + 4 - got) == 300000 &&
                         is_pattern(at + 4, 300000),
                     "a sized pull: Content-Length, no chunks");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "GET /short HTTP/1.1\r\nHost: x\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  at = strstr(got, "\r\n\r\n");
  CSERVE_TEST_ASSERT(closed && at && len - (size_t)(at + 4 - got) < 100,
                     "a sized pull that comes out short: cut off, closed");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "HEAD /big HTTP/1.1\r\nHost: x\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  at = strstr(got, "\r\n\r\n");
  CSERVE_TEST_ASSERT(closed && at && at[4] == '\0' &&
                         strstr(got, "Connection: close\r\n") &&
                         !strstr(got, "Transfer-Encoding"),
                     "HEAD of a pulled body: no framing, no body, closed");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "GET /big HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  at = strstr(got, "\r\n\r\n");
  CSERVE_TEST_ASSERT(closed && at && len - (size_t)(at + 4 - got) == BIG &&
                         !strstr(got, "chunked"),
                     "HTTP/1.0: the pulled body to the end, then closed");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 2000000\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, " 413 ") && closed, "a body past the limit: "
                                                     "413");
  free(got);
  close(fd);

  fd = dial(port);
  char *huge = malloc(20100);
  memcpy(huge, "GET / HTTP/1.1\r\nX: ", 19);
  memset(huge + 19, 'a', 20000);
  memcpy(huge + 20019, "\r\n\r\n", 5);
  say(fd, huge);
  free(huge);
  got = drain(fd, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, " 431 ") && closed, "a head past the limit: "
                                                     "431");
  free(got);
  close(fd);

  fd = dial(port);
  say(fd, "GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  got = drain(fd, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, "\r\n\r\n4 127.0.0.1"),
                     "the request knows the peer's family and network");
  free(got);
  close(fd);
}

static void test_deadlines(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.timeout_ms = 300, .idle_ms = 200};
  if (start(&r, cfg, NULL) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop with short deadlines started");
    return;
  }
  size_t len;
  int closed;
  long t = cserve_net_now();
  int fd = dial(r.port);
  say(fd, "GET /hi HTTP/1.1\r\nHost: x\r\n");
  char *got = drain(fd, 3000, &len, &closed);
  long took = cserve_net_now() - t;
  CSERVE_TEST_ASSERT(strstr(got, " 400 ") && closed && took >= 250 &&
                         took < 2000,
                     "a head cut off by its deadline: 400, then closed (%ld "
                     "ms)",
                     took);
  free(got);
  close(fd);

  fd = dial(r.port);
  got = drain(fd, 3000, &len, &closed);
  CSERVE_TEST_ASSERT(len == 0 && closed, "nothing sent: closed without a word");
  free(got);
  close(fd);

  t = cserve_net_now();
  fd = dial(r.port);
  say(fd, "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n");
  got = drain(fd, 3000, &len, &closed);
  took = cserve_net_now() - t;
  CSERVE_TEST_ASSERT(strstr(got, "hi there") && closed && took >= 150,
                     "kept alive, then closed once idle (%ld ms)", took);
  free(got);
  close(fd);
  /* the loop sees each client's close as it comes: a moment for that */
  int left = cserve_loop_conns(r.loop);
  for (int i = 0; i < 50 && left; i++) {
    struct timespec ts = {0, 20 * 1000000L};
    nanosleep(&ts, NULL);
    left = cserve_loop_conns(r.loop);
  }
  CSERVE_TEST_ASSERT(left == 0, "every connection gone again (%d left)", left);
  stop(&r);
}

static void test_limits(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.workers = 1, .queue = 1, .per_addr = 3};
  if (start(&r, cfg, NULL) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop with one worker started");
    return;
  }
  size_t len;
  int closed;
  gate(0);
  int a = dial(r.port), b = dial(r.port);
  say(a, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  struct timespec ts = {0, 100 * 1000000L};
  nanosleep(&ts, NULL);
  say(b, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  char *got = drain(b, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, " 503 ") &&
                         strstr(got, "Retry-After: 1\r\n") && closed,
                     "the pool full: 503, Retry-After");
  free(got);
  close(b);

  int c = dial(r.port), d = dial(r.port), e = dial(r.port);
  got = drain(e, 1000, &len, &closed);
  CSERVE_TEST_ASSERT(len == 0 && closed,
                     "a fourth connection from one network: closed at once");
  free(got);
  close(c);
  close(d);
  close(e);

  gate(1);
  got = drain(a, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, "let through"),
                     "the first, once its handler goes on: answered");
  free(got);
  close(a);

  /* a client gone while the pool has its request: the slot comes back */
  int f = dial(r.port);
  say(f, "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n");
  nanosleep(&ts, NULL);
  close(f);
  struct timespec rest = {0, 400 * 1000000L};
  nanosleep(&rest, NULL);
  CSERVE_TEST_ASSERT(cserve_loop_conns(r.loop) == 0,
                     "a client gone mid-request: its connection freed after");
  stop(&r);
}

/* the slow lane: /block counts as slow */
static int is_slow(const CSERVE_HTTPD_REQ *r, void *ud) {
  (void)ud;
  return !strcmp(r->path, "/block");
}

static void test_lane(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {.workers = 4, .slow = is_slow};
  if (start(&r, cfg, NULL) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop with a slow lane started");
    return;
  }
  size_t len;
  int closed;
  gate(0);
  /* two slow requests: the lane (half of four workers) is full */
  int a = dial(r.port), b = dial(r.port);
  say(a, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  say(b, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  struct timespec ts = {0, 100 * 1000000L};
  nanosleep(&ts, NULL);
  int c = dial(r.port);
  say(c, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  char *got = drain(c, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, " 503 ") && strstr(got, "busy with logins") &&
                         strstr(got, "Retry-After: 1\r\n") && closed,
                     "the lane full: a third slow request gets a 503 at once");
  free(got);
  close(c);
  int d = dial(r.port);
  say(d, "GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  got = drain(d, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, "hi there"),
                     "the lane full: a page still answered, by a free worker");
  free(got);
  close(d);
  gate(1);
  int answered = 0;
  for (int i = 0; i < 2; i++) {
    int fd = i ? b : a;
    got = drain(fd, 2000, &len, &closed);
    answered += strstr(got, "let through") != NULL;
    free(got);
    close(fd);
  }
  CSERVE_TEST_ASSERT(answered == 2,
                     "the two in the lane: answered once let go");
  int e = dial(r.port);
  say(e, "GET /block HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  got = drain(e, 2000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, "let through"),
                     "and the lane has room again after them");
  free(got);
  close(e);
  stop(&r);
}

static void test_tls(void) {
  char err[200];
  CSERVE_TLS_SERVER *srv =
      cserve_tls_server_new("tests/data/pki/server.crt",
                            "tests/data/pki/server.key", NULL, err, sizeof err);
  CSERVE_TLS_CLIENT *cl = cserve_tls_client_new("tests/data/pki/ca.crt", NULL,
                                                NULL, err, sizeof err);
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {0};
  if (!srv || !cl || start(&r, cfg, srv) != 0) {
    CSERVE_TEST_ASSERT(0, "a TLS loop started (%s)", err);
    cserve_tls_server_free(srv);
    cserve_tls_client_free(cl);
    return;
  }
  int fd = dial(r.port);
  /* tls.h's client wants it so: it waits in poll(), never in recv() */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  long deadline = cserve_net_now() + 30000;
  CSERVE_TLS *t =
      cserve_tls_connect(fd, "localhost", cl, deadline, err, sizeof err);
  const char req[] =
      "GET /huge HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
  size_t len = 0, cap = HUGE + 65536;
  char *got = malloc(cap + 1);
  if (t && cserve_tls_write(t, req, sizeof req - 1, deadline, err,
                            sizeof err) == 0) {
    /* nothing read for a while: the loop fills the kernel's buffer and
     * has to wait for the socket, then go on */
    struct timespec ts = {0, 500 * 1000000L};
    nanosleep(&ts, NULL);
    for (;;) {
      ssize_t n =
          cserve_tls_read(t, got + len, cap - len, deadline, err, sizeof err);
      if (n <= 0) {
        break;
      }
      len += (size_t)n;
    }
  }
  got[len] = '\0';
  char *body = malloc(HUGE);
  long n = dechunk(got, body, HUGE);
  if (n != HUGE) {
    printf("    %zu bytes came (%s)\n", len, err);
  }
  CSERVE_TEST_ASSERT(t && n == HUGE && is_pattern(body, HUGE),
                     "over TLS to a reader that waits: 8 MiB, every byte "
                     "right");
  free(got);
  free(body);
  cserve_tls_close(t);
  close(fd);

  fd = dial(r.port);
  say(fd, "GET /hi HTTP/1.1\r\n\r\n");
  size_t plain;
  int closed;
  got = drain(fd, 2000, &plain, &closed);
  CSERVE_TEST_ASSERT(closed && !strstr(got, "hi there"),
                     "plain HTTP to the TLS listener: refused, closed");
  free(got);
  close(fd);
  stop(&r);
  cserve_tls_server_free(srv);
  cserve_tls_client_free(cl);
}

static void test_stop(void) {
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {0};
  if (start(&r, cfg, NULL) != 0) {
    CSERVE_TEST_ASSERT(0, "a loop to stop started");
    return;
  }
  int idle = dial(r.port), busy = dial(r.port);
  say(busy, "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n");
  struct timespec ts = {0, 50 * 1000000L};
  nanosleep(&ts, NULL);
  (void)!write(r.stop[1], "x", 1);
  size_t len;
  int closed;
  char *got = drain(busy, 3000, &len, &closed);
  CSERVE_TEST_ASSERT(strstr(got, "slowly") &&
                         strstr(got, "Connection: close\r\n") && closed,
                     "stopping: the request in flight still answered, closed");
  free(got);
  got = drain(idle, 3000, &len, &closed);
  CSERVE_TEST_ASSERT(len == 0 && closed, "and the idle one let go");
  free(got);
  pthread_join(r.thread, NULL);
  CSERVE_TEST_ASSERT(r.rc == 0 && dial(r.port) < 0,
                     "the loop returned; nothing listens any more");
  cserve_loop_free(r.loop);
  close(r.stop[0]);
  close(r.stop[1]);
  close(idle);
  close(busy);
}

int main(void) {
  cserve_log_set(catch_log, NULL);
  RUN r;
  CSERVE_LOOP_CONFIG cfg = {0};
  if (start(&r, cfg, NULL) != 0) {
    CSERVE_TEST_ASSERT(0, "the loop started");
    return cserve_test_summary();
  }
  test_http(r.port);
  stop(&r);
  test_deadlines();
  test_limits();
  test_lane();
  test_tls();
  test_stop();
  pthread_mutex_lock(&g_log_lock);
  CSERVE_TEST_ASSERT(strstr(g_log, "GET /hi 200 8 ") &&
                         strstr(g_log, "POST /echo 200 11 ") &&
                         strstr(g_log, " v4\n") && !strstr(g_log, "127.0.0.1"),
                     "the access log: method, path, status, bytes, family -- "
                     "and no address");
  pthread_mutex_unlock(&g_log_lock);
  return cserve_test_summary();
}
