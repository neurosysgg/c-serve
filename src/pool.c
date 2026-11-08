#define _GNU_SOURCE /* eventfd's flags */
#include "pool.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

/* a ring of job pointers: at most cap in it */
typedef struct {
  void **v;
  int cap, head, n;
} RING;

static void ring_put(RING *r, void *job) {
  r->v[(r->head + r->n++) % r->cap] = job;
}

static void *ring_get(RING *r) {
  if (r->n == 0) {
    return NULL;
  }
  void *job = r->v[r->head];
  r->head = (r->head + 1) % r->cap;
  r->n--;
  return job;
}

struct CSERVE_POOL {
  CSERVE_POOL_FN run;
  void *ud;
  pthread_mutex_t lock;
  pthread_cond_t work;
  RING queued, finished; /* each holds limit at most: out <= limit */
  int out, limit, stopping;
  int fd; /* eventfd: counts finished jobs not yet taken */
  int nthreads;
  pthread_t *threads;
};

static void *worker(void *arg) {
  CSERVE_POOL *p = arg;
  pthread_mutex_lock(&p->lock);
  for (;;) {
    void *job = ring_get(&p->queued);
    if (!job) {
      if (p->stopping) {
        break;
      }
      pthread_cond_wait(&p->work, &p->lock);
      continue;
    }
    pthread_mutex_unlock(&p->lock);
    p->run(job, p->ud);
    pthread_mutex_lock(&p->lock);
    ring_put(&p->finished, job);
    uint64_t one = 1;
    (void)!write(p->fd, &one, sizeof one);
  }
  pthread_mutex_unlock(&p->lock);
  return NULL;
}

CSERVE_POOL *cserve_pool_new(int workers, int limit, CSERVE_POOL_FN run,
                             void *ud, char *err, size_t err_cap) {
  workers = workers > 0 ? workers : 1;
  limit = limit < workers ? workers : limit;
  CSERVE_POOL *p = calloc(1, sizeof *p);
  if (!p) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  p->run = run;
  p->ud = ud;
  p->limit = limit;
  p->queued = (RING){.v = calloc((size_t)limit, sizeof(void *)), .cap = limit};
  p->finished =
      (RING){.v = calloc((size_t)limit, sizeof(void *)), .cap = limit};
  p->threads = calloc((size_t)workers, sizeof *p->threads);
  p->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (!p->queued.v || !p->finished.v || !p->threads || p->fd < 0) {
    snprintf(err, err_cap, "%s", p->fd < 0 ? strerror(errno) : "out of memory");
    if (p->fd >= 0) {
      close(p->fd);
    }
    free(p->queued.v);
    free(p->finished.v);
    free(p->threads);
    free(p);
    return NULL;
  }
  pthread_mutex_init(&p->lock, NULL);
  pthread_cond_init(&p->work, NULL);
  for (int i = 0; i < workers; i++) {
    int e = pthread_create(&p->threads[i], NULL, worker, p);
    if (e != 0) {
      snprintf(err, err_cap, "starting a worker: %s", strerror(e));
      cserve_pool_free(p);
      return NULL;
    }
    p->nthreads++;
  }
  return p;
}

int cserve_pool_submit(CSERVE_POOL *p, void *job) {
  pthread_mutex_lock(&p->lock);
  int ok = p->out < p->limit && !p->stopping;
  if (ok) {
    p->out++;
    ring_put(&p->queued, job);
    pthread_cond_signal(&p->work);
  }
  pthread_mutex_unlock(&p->lock);
  return ok ? 0 : -1;
}

int cserve_pool_fd(const CSERVE_POOL *p) { return p->fd; }

void *cserve_pool_take(CSERVE_POOL *p) {
  pthread_mutex_lock(&p->lock);
  void *job = ring_get(&p->finished);
  if (job) {
    p->out--;
    if (p->finished.n == 0) {
      /* nothing left: the fd quiet again until the next one */
      uint64_t n;
      (void)!read(p->fd, &n, sizeof n);
    }
  }
  pthread_mutex_unlock(&p->lock);
  return job;
}

int cserve_pool_out(CSERVE_POOL *p) {
  pthread_mutex_lock(&p->lock);
  int out = p->out;
  pthread_mutex_unlock(&p->lock);
  return out;
}

void cserve_pool_free(CSERVE_POOL *p) {
  if (!p) {
    return;
  }
  pthread_mutex_lock(&p->lock);
  p->stopping = 1;
  pthread_cond_broadcast(&p->work);
  pthread_mutex_unlock(&p->lock);
  for (int i = 0; i < p->nthreads; i++) {
    pthread_join(p->threads[i], NULL);
  }
  pthread_cond_destroy(&p->work);
  pthread_mutex_destroy(&p->lock);
  close(p->fd);
  free(p->queued.v);
  free(p->finished.v);
  free(p->threads);
  free(p);
}
