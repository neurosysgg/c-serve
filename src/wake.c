/* tags from any thread to the loop's (wake.h): a mutex, a ring, an
 * eventfd -- the pool's way of handing back finished jobs, for tags */
#define _GNU_SOURCE /* eventfd's flags */
#include "wake.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct CSERVE_WAKE {
  pthread_mutex_t lock;
  uint64_t *ring;
  size_t cap, head, n;
  int overflowed;
  int fd;
};

CSERVE_WAKE *cserve_wake_new(size_t cap, char *err, size_t err_cap) {
  CSERVE_WAKE *w = calloc(1, sizeof *w);
  if (w) {
    w->ring = calloc(cap ? cap : 1, sizeof *w->ring);
    w->cap = cap ? cap : 1;
    w->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  }
  if (!w || !w->ring || w->fd < 0) {
    snprintf(err, err_cap, "%s",
             w && w->ring ? strerror(errno) : "out of memory");
    cserve_wake_free(w);
    return NULL;
  }
  pthread_mutex_init(&w->lock, NULL);
  return w;
}

void cserve_wake_free(CSERVE_WAKE *w) {
  if (!w) {
    return;
  }
  if (w->fd >= 0) {
    close(w->fd);
    pthread_mutex_destroy(&w->lock);
  }
  free(w->ring);
  free(w);
}

int cserve_wake_fd(const CSERVE_WAKE *w) { return w->fd; }

void cserve_wake_post(CSERVE_WAKE *w, uint64_t tag) {
  pthread_mutex_lock(&w->lock);
  int first = w->n == 0 && !w->overflowed;
  if (w->n == w->cap) {
    w->overflowed = 1;
  } else {
    w->ring[(w->head + w->n) % w->cap] = tag;
    w->n++;
  }
  pthread_mutex_unlock(&w->lock);
  if (first) {
    uint64_t one = 1;
    (void)!write(w->fd, &one, sizeof one);
  }
}

size_t cserve_wake_take(CSERVE_WAKE *w, uint64_t *out, size_t cap,
                        int *overflowed) {
  pthread_mutex_lock(&w->lock);
  size_t k = 0;
  while (k < cap && w->n > 0) {
    out[k++] = w->ring[w->head];
    w->head = (w->head + 1) % w->cap;
    w->n--;
  }
  *overflowed = w->overflowed;
  w->overflowed = 0;
  if (w->n == 0) {
    uint64_t v;
    (void)!read(w->fd, &v, sizeof v);
  }
  pthread_mutex_unlock(&w->lock);
  return k;
}
