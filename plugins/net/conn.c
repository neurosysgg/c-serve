/* getaddrinfo() and friends are POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "conn.h"

#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
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
  CTUI_WM_TLS *tls; /* NULL: plain http */
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

CTUI_WM_CONN *ctui_wm_conn_open(const CTUI_WM_URL *u, long deadline,
                                char *err, size_t err_cap) {
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

ssize_t ctui_wm_conn_read(CTUI_WM_CONN *c, char *buf, size_t n, char *err,
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

void ctui_wm_conn_close(CTUI_WM_CONN *c) {
  if (!c) {
    return;
  }
  if (c->tls) {
    ctui_wm_tls_close(c->tls);
  }
  close(c->fd);
  free(c);
}
