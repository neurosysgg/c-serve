/* getaddrinfo() and friends are POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "conn.h"

#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct CTUI_WM_CONN {
  int fd;
  long deadline;
  CTUI_WM_TLS *tls; /* NULL: plain */
  /* what line() read past its line: in[off, len) */
  char *in;
  size_t off, len, cap;
};

long ctui_wm_net_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int ctui_wm_net_wait(int fd, short events, long deadline, char *err,
                     size_t err_cap) {
  for (;;) {
    long left = deadline - ctui_wm_net_now();
    if (left <= 0) {
      snprintf(err, err_cap, "timed out");
      return -1;
    }
    struct pollfd pfd = {.fd = fd, .events = events};
    int r = poll(&pfd, 1, left > 60000 ? 60000 : (int)left);
    if (r < 0 && errno != EINTR) {
      snprintf(err, err_cap, "poll: %s", strerror(errno));
      return -1;
    }
    /* an error or hangup: the read/write/connect result says which */
    if (r > 0) {
      return 0;
    }
  }
}

/* one address, connected before deadline: its fd, or -1 with why in err */
static int connect_one(const struct addrinfo *ai, long deadline, char *err,
                       size_t err_cap) {
  int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                  ai->ai_protocol);
  if (fd < 0) {
    snprintf(err, err_cap, "socket: %s", strerror(errno));
    return -1;
  }
  if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
    if (errno != EINPROGRESS) {
      snprintf(err, err_cap, "connecting: %s", strerror(errno));
      close(fd);
      return -1;
    }
    if (ctui_wm_net_wait(fd, POLLOUT, deadline, err, err_cap) != 0) {
      close(fd);
      return -1;
    }
    int soerr = 0;
    socklen_t len = sizeof soerr;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len);
    if (soerr) {
      snprintf(err, err_cap, "connecting: %s", strerror(soerr));
      close(fd);
      return -1;
    }
  }
  return fd;
}

CTUI_WM_CONN *ctui_wm_conn_open(const CTUI_WM_URL *u, long deadline, char *err,
                                size_t err_cap) {
  struct addrinfo hints = {.ai_family = AF_UNSPEC,
                           .ai_socktype = SOCK_STREAM,
                           .ai_flags = AI_ADDRCONFIG};
  struct addrinfo *res = NULL;
  int gai = getaddrinfo(u->host, u->port, &hints, &res);
  if (gai != 0) {
    snprintf(err, err_cap, "resolving %s: %s", u->host,
             gai == EAI_SYSTEM ? strerror(errno) : gai_strerror(gai));
    return NULL;
  }
  int fd = -1;
  for (const struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
    fd = connect_one(ai, deadline, err, err_cap);
  }
  freeaddrinfo(res);
  if (fd < 0) {
    return NULL;
  }
  CTUI_WM_CONN *c = calloc(1, sizeof *c);
  if (!c) {
    snprintf(err, err_cap, "out of memory");
    close(fd);
    return NULL;
  }
  c->fd = fd;
  c->deadline = deadline;
  if (u->tls) {
    c->tls = ctui_wm_tls_open(fd, u->host, deadline, err, err_cap);
    if (!c->tls) {
      close(fd);
      free(c);
      return NULL;
    }
  }
  return c;
}

int ctui_wm_conn_write(CTUI_WM_CONN *c, const char *buf, size_t n, char *err,
                       size_t err_cap) {
  if (c->tls) {
    return ctui_wm_tls_write(c->tls, buf, n, c->deadline, err, err_cap);
  }
  while (n > 0) {
    ssize_t w = send(c->fd, buf, n, MSG_NOSIGNAL);
    if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
      if (ctui_wm_net_wait(c->fd, POLLOUT, c->deadline, err, err_cap) != 0) {
        return -1;
      }
      continue;
    }
    if (w < 0) {
      snprintf(err, err_cap, "sending: %s", strerror(errno));
      return -1;
    }
    buf += w;
    n -= (size_t)w;
  }
  return 0;
}

/* the socket (or TLS) straight, past the buffer */
static ssize_t raw_read(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
                        size_t err_cap) {
  if (c->tls) {
    return ctui_wm_tls_read(c->tls, buf, n, c->deadline, err, err_cap);
  }
  for (;;) {
    ssize_t r = recv(c->fd, buf, n, 0);
    if (r >= 0) {
      return r;
    }
    if (errno != EAGAIN && errno != EINTR) {
      snprintf(err, err_cap, "receiving: %s", strerror(errno));
      return -1;
    }
    if (ctui_wm_net_wait(c->fd, POLLIN, c->deadline, err, err_cap) != 0) {
      return -1;
    }
  }
}

ssize_t ctui_wm_conn_read(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
                          size_t err_cap) {
  if (c->off < c->len) {
    size_t k = c->len - c->off < n ? c->len - c->off : n;
    memcpy(buf, c->in + c->off, k);
    c->off += k;
    return (ssize_t)k;
  }
  return raw_read(c, buf, n, err, err_cap);
}

void ctui_wm_conn_close(CTUI_WM_CONN *c) {
  if (!c) {
    return;
  }
  if (c->tls) {
    ctui_wm_tls_close(c->tls);
  }
  close(c->fd);
  free(c->in);
  free(c);
}

void ctui_wm_conn_deadline(CTUI_WM_CONN *c, long deadline) {
  c->deadline = deadline;
}

void ctui_wm_conn_keepalive(CTUI_WM_CONN *c, int idle_s) {
  int on = 1, intvl = 30, cnt = 4;
  setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
  setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_s, sizeof idle_s);
  setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
  setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
}

int ctui_wm_conn_starttls(CTUI_WM_CONN *c, const char *host, char *err,
                          size_t err_cap) {
  if (c->tls) {
    snprintf(err, err_cap, "TLS already");
    return -1;
  }
  /* anything the server sent after its go-ahead would be plaintext
   * injected ahead of the handshake (CVE-2011-0411's class) */
  if (c->off < c->len) {
    snprintf(err, err_cap, "the server sent more before TLS started");
    return -1;
  }
  c->tls = ctui_wm_tls_open(c->fd, host, c->deadline, err, err_cap);
  return c->tls ? 0 : -1;
}

CTUI_WM_CONN *ctui_wm_conn_adopt(int fd, long deadline) {
  CTUI_WM_CONN *c = calloc(1, sizeof *c);
  if (!c) {
    close(fd);
    return NULL;
  }
  c->fd = fd;
  c->deadline = deadline;
  return c;
}

int ctui_wm_conn_accept_tls(CTUI_WM_CONN *c, CTUI_WM_TLS_SERVER *srv, char *err,
                            size_t err_cap) {
  if (c->tls) {
    snprintf(err, err_cap, "TLS already");
    return -1;
  }
  /* commands pipelined behind STARTTLS would be plaintext taken as if
   * they came over TLS (the client-side check's mirror) */
  if (c->off < c->len) {
    snprintf(err, err_cap, "the client sent more before TLS started");
    return -1;
  }
  c->tls = ctui_wm_tls_accept(c->fd, srv, c->deadline, err, err_cap);
  return c->tls ? 0 : -1;
}

int ctui_wm_conn_tls(const CTUI_WM_CONN *c) { return c->tls != NULL; }

int ctui_wm_conn_peer_cert(const CTUI_WM_CONN *c, char *cn, size_t cn_cap,
                           char fpr[65]) {
  if (!c->tls) {
    if (cn_cap) {
      cn[0] = '\0';
    }
    fpr[0] = '\0';
    return -1;
  }
  return ctui_wm_tls_peer(c->tls, cn, cn_cap, fpr);
}

int ctui_wm_conn_fd(const CTUI_WM_CONN *c) { return c->fd; }

int ctui_wm_conn_idle_ok(const CTUI_WM_CONN *c) {
  if (c->off < c->len) {
    return 0;
  }
  struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
  if (poll(&pfd, 1, 0) < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
    return 0;
  }
  /* plainly nothing comes unasked: that's the server's close (or junk).
   * Over TLS it may be a session ticket; a closed one shows when the
   * request finds nothing */
  return !(pfd.revents & POLLIN) || c->tls != NULL;
}

int ctui_wm_conn_pending(const CTUI_WM_CONN *c) {
  return c->off < c->len || (c->tls && ctui_wm_tls_pending(c->tls) > 0);
}

ssize_t ctui_wm_conn_line(CTUI_WM_CONN *c, const char **line, size_t max,
                          char *err, size_t err_cap) {
  /* the last line handed out is used up: keep only what follows it */
  if (c->off > 0) {
    memmove(c->in, c->in + c->off, c->len - c->off);
    c->len -= c->off;
    c->off = 0;
  }
  size_t scanned = 0;
  for (;;) {
    char *lf = c->len > scanned
                   ? memchr(c->in + scanned, '\n', c->len - scanned)
                   : NULL;
    if (lf) {
      size_t n = (size_t)(lf - c->in);
      c->off = n + 1;
      if (n > 0 && c->in[n - 1] == '\r') {
        n--;
      }
      c->in[n] = '\0';
      *line = c->in;
      return (ssize_t)n;
    }
    scanned = c->len;
    if (c->len > max) {
      snprintf(err, err_cap, "a line over %zu bytes", max);
      return -1;
    }
    if (c->cap - c->len < 4096) {
      size_t cap = c->cap ? c->cap * 2 : 8192;
      char *in = realloc(c->in, cap);
      if (!in) {
        snprintf(err, err_cap, "out of memory");
        return -1;
      }
      c->in = in;
      c->cap = cap;
    }
    /* one byte kept back for the NUL a line gets */
    ssize_t r = raw_read(c, c->in + c->len, c->cap - c->len - 1, err, err_cap);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      snprintf(err, err_cap, "the server closed the connection");
      return -1;
    }
    c->len += (size_t)r;
  }
}

int ctui_wm_conn_bytes(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
                       size_t err_cap) {
  while (n > 0) {
    ssize_t r = ctui_wm_conn_read(c, buf, n, err, err_cap);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      snprintf(err, err_cap, "the server closed the connection");
      return -1;
    }
    buf += r;
    n -= (size_t)r;
  }
  return 0;
}
