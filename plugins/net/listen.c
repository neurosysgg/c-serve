#define _GNU_SOURCE /* accept4() */
#include "listen.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  CTUI_WM_LISTEN pub;
  atomic_int running;
} LISTENER;

typedef struct {
  LISTENER *l;
  int fd;
  char peer[64];
} JOB;

static atomic_int g_active;

CTUI_WM_LISTEN *ctui_wm_listen_new(const char *host, int port,
                                   CTUI_WM_LISTEN_FN handler, void *ud,
                                   char *err, size_t err_cap) {
  char service[8];
  snprintf(service, sizeof service, "%d", port);
  struct addrinfo hints = {.ai_family = AF_UNSPEC,
                           .ai_socktype = SOCK_STREAM,
                           .ai_flags = AI_PASSIVE | AI_NUMERICSERV};
  struct addrinfo *res = NULL;
  int gai = getaddrinfo(host, service, &hints, &res);
  if (gai != 0) {
    snprintf(err, err_cap, "resolving %s: %s", host,
             gai == EAI_SYSTEM ? strerror(errno) : gai_strerror(gai));
    return NULL;
  }
  int fd = -1;
  for (const struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                ai->ai_protocol);
    if (fd < 0) {
      snprintf(err, err_cap, "socket: %s", strerror(errno));
      continue;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0 || listen(fd, 64) != 0) {
      snprintf(err, err_cap, "listening on %s:%d: %s", host, port,
               strerror(errno));
      close(fd);
      fd = -1;
    }
  }
  freeaddrinfo(res);
  if (fd < 0) {
    return NULL;
  }
  LISTENER *l = calloc(1, sizeof *l);
  if (!l) {
    snprintf(err, err_cap, "out of memory");
    close(fd);
    return NULL;
  }
  struct sockaddr_storage sa = {0};
  socklen_t len = sizeof sa;
  if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
    sa.ss_family = AF_UNSPEC;
  }
  l->pub.port = sa.ss_family == AF_UNSPEC
                    ? port
                    : ntohs(sa.ss_family == AF_INET6
                                ? ((struct sockaddr_in6 *)&sa)->sin6_port
                                : ((struct sockaddr_in *)&sa)->sin_port);
  l->pub.fd = fd;
  l->pub.handler = handler;
  l->pub.ud = ud;
  l->pub.max = 64;
  l->pub.timeout_ms = 30000;
  return &l->pub;
}

void ctui_wm_listen_free(CTUI_WM_LISTEN *l) {
  if (l) {
    close(l->fd);
    free(l);
  }
}

int ctui_wm_listen_active(void) { return atomic_load(&g_active); }

static void peer_text(const struct sockaddr_storage *sa, char *out,
                      size_t cap) {
  char ip[INET6_ADDRSTRLEN] = "?";
  if (sa->ss_family == AF_INET6) {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
    inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
    snprintf(out, cap, "[%s]:%d", ip, ntohs(s6->sin6_port));
  } else {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
    inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
    snprintf(out, cap, "%s:%d", ip, ntohs(s4->sin_port));
  }
}

static void *job_run(void *arg) {
  JOB *j = arg;
  LISTENER *l = j->l;
  CTUI_WM_CONN *c =
      ctui_wm_conn_adopt(j->fd, ctui_wm_net_now() + l->pub.timeout_ms);
  if (c) {
    l->pub.handler(c, j->peer, l->pub.ud);
  }
  free(j);
  atomic_fetch_sub(&l->running, 1);
  atomic_fetch_sub(&g_active, 1);
  return NULL;
}

/* every connection waiting on l accepted and handed to a thread */
static void accept_all(LISTENER *l) {
  for (;;) {
    struct sockaddr_storage sa = {0};
    socklen_t len = sizeof sa;
    int fd = accept4(l->pub.fd, (struct sockaddr *)&sa, &len,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      return; /* EAGAIN: none left; anything else: the next poll again */
    }
    if (atomic_load(&l->running) >= l->pub.max) {
      close(fd);
      continue;
    }
    if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6) {
      /* a reply's head and body are separate writes: with Nagle the body
       * waits for the head's ACK, which the peer delays (~40 ms a reply) */
      int on = 1;
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    }
    JOB *j = malloc(sizeof *j);
    if (!j) {
      close(fd);
      continue;
    }
    j->l = l;
    j->fd = fd;
    peer_text(&sa, j->peer, sizeof j->peer);
    atomic_fetch_add(&l->running, 1);
    atomic_fetch_add(&g_active, 1);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    if (pthread_create(&t, &attr, job_run, j) != 0) {
      atomic_fetch_sub(&l->running, 1);
      atomic_fetch_sub(&g_active, 1);
      close(fd);
      free(j);
    }
    pthread_attr_destroy(&attr);
  }
}

int ctui_wm_listen_serve(CTUI_WM_LISTEN *const *ls, int n, int stop_fd,
                         char *err, size_t err_cap) {
  struct pollfd *pfd = calloc((size_t)n + 1, sizeof *pfd);
  if (!pfd) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  for (int i = 0; i < n; i++) {
    pfd[i] = (struct pollfd){.fd = ls[i]->fd, .events = POLLIN};
  }
  pfd[n] = (struct pollfd){.fd = stop_fd, .events = POLLIN};
  int ret = 0;
  for (;;) {
    if (poll(pfd, (nfds_t)n + 1, -1) < 0) {
      if (errno == EINTR) {
        continue;
      }
      snprintf(err, err_cap, "poll: %s", strerror(errno));
      ret = -1;
      break;
    }
    if (pfd[n].revents) {
      break;
    }
    for (int i = 0; i < n; i++) {
      if (pfd[i].revents & POLLIN) {
        accept_all((LISTENER *)ls[i]);
      }
    }
  }
  free(pfd);
  return ret;
}
