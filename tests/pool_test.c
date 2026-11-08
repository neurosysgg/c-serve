/* src/pool.c: jobs run on the workers and come back through the fd, at
 * most limit out at once, and freeing runs what was queued. TSan (make
 * check) is the other half: every job's fields are written by a worker
 * and read by the taker, ordered only by the pool's lock. */
#include "pool.h"

#include "test.h"

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

typedef struct {
  int in, out; /* in set by the test, out by run() */
  pthread_t by;
} JOB;

static atomic_int g_ran;
static pthread_mutex_t g_gate = PTHREAD_MUTEX_INITIALIZER;

static void run(void *job, void *ud) {
  (void)ud;
  JOB *j = job;
  /* the gate held: every worker waits here (the limit test) */
  pthread_mutex_lock(&g_gate);
  pthread_mutex_unlock(&g_gate);
  j->out = j->in * 2;
  j->by = pthread_self();
  atomic_fetch_add(&g_ran, 1);
}

static int readable(int fd, int ms) {
  struct pollfd p = {.fd = fd, .events = POLLIN};
  return poll(&p, 1, ms) == 1;
}

static void test_round_trip(void) {
  char err[200];
  CSERVE_POOL *p = cserve_pool_new(4, 64, run, NULL, err, sizeof err);
  JOB jobs[64];
  int ok = p != NULL;
  for (int i = 0; ok && i < 64; i++) {
    jobs[i] = (JOB){.in = i};
    ok = cserve_pool_submit(p, &jobs[i]) == 0;
  }
  int taken = 0, right = 1;
  while (ok && taken < 64 && readable(cserve_pool_fd(p), 5000)) {
    for (JOB *j; (j = cserve_pool_take(p));) {
      right =
          right && j->out == j->in * 2 && !pthread_equal(j->by, pthread_self());
      taken++;
    }
  }
  CSERVE_TEST_ASSERT(ok && taken == 64 && right,
                     "64 jobs run on the workers, each handed back once");
  CSERVE_TEST_ASSERT(p && cserve_pool_out(p) == 0 &&
                         !readable(cserve_pool_fd(p), 0),
                     "with everything taken, none are out and the fd is quiet");
  cserve_pool_free(p);
}

static void test_limit(void) {
  char err[200];
  pthread_mutex_lock(&g_gate);
  CSERVE_POOL *p = cserve_pool_new(2, 3, run, NULL, err, sizeof err);
  JOB jobs[4] = {{.in = 1}, {.in = 2}, {.in = 3}, {.in = 4}};
  int ok = p && cserve_pool_submit(p, &jobs[0]) == 0 &&
           cserve_pool_submit(p, &jobs[1]) == 0 &&
           cserve_pool_submit(p, &jobs[2]) == 0;
  CSERVE_TEST_ASSERT(ok && cserve_pool_submit(p, &jobs[3]) == -1 &&
                         cserve_pool_out(p) == 3,
                     "past the limit a job is refused (the loop's 503)");
  pthread_mutex_unlock(&g_gate);
  int taken = 0;
  while (p && taken < 3 && readable(cserve_pool_fd(p), 5000)) {
    while (cserve_pool_take(p)) {
      taken++;
    }
  }
  CSERVE_TEST_ASSERT(taken == 3 && cserve_pool_submit(p, &jobs[3]) == 0,
                     "taken back, there's room again");
  while (p && !cserve_pool_take(p)) {
    readable(cserve_pool_fd(p), 5000);
  }
  cserve_pool_free(p);
}

static void test_free_runs_the_queue(void) {
  char err[200];
  atomic_store(&g_ran, 0);
  pthread_mutex_lock(&g_gate);
  CSERVE_POOL *p = cserve_pool_new(1, 8, run, NULL, err, sizeof err);
  JOB jobs[8];
  for (int i = 0; p && i < 8; i++) {
    jobs[i] = (JOB){.in = i};
    (void)cserve_pool_submit(p, &jobs[i]);
  }
  pthread_mutex_unlock(&g_gate);
  cserve_pool_free(p);
  CSERVE_TEST_ASSERT(p && atomic_load(&g_ran) == 8,
                     "freeing runs every job still queued before it joins");
}

int main(void) {
  test_round_trip();
  test_limit();
  test_free_runs_the_queue();
  return cserve_test_summary();
}
