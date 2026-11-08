/* src/heap.c: the loop's timers, checked against the plainest reference
 * there is -- every node's deadline in an array, the minimum found by
 * looking at all of them -- over many random sequences of sets, moves
 * and removals, with the heap's own invariants checked after each step */
#include "heap.h"

#include "test.h"

#include <stdlib.h>

#define NODES 64
#define STEPS 20000

/* every parent due no later than its children, every node where its
 * index says */
static int sound(const CSERVE_HEAP *h) {
  for (int i = 0; i < h->n; i++) {
    if (h->v[i]->index != i) {
      return 0;
    }
    if (i > 0 && h->v[(i - 1) / 2]->at > h->v[i]->at) {
      return 0;
    }
  }
  return 1;
}

static unsigned g_seed = 12345;
static unsigned next(void) {
  g_seed = g_seed * 1103515245u + 12345u;
  return (g_seed >> 8) & 0xffffff;
}

static void test_random(void) {
  CSERVE_HEAP h;
  CSERVE_HEAP_NODE nodes[NODES];
  int in[NODES] = {0};
  long ref[NODES] = {0};
  for (int i = 0; i < NODES; i++) {
    nodes[i] = (CSERVE_HEAP_NODE)CSERVE_HEAP_NODE_INIT;
  }
  int ok = cserve_heap_init(&h, NODES) == 0, bad_step = -1;
  for (int step = 0; ok && step < STEPS; step++) {
    int k = (int)(next() % NODES);
    unsigned op = next() % 4;
    if (op < 3) {
      /* a small range of deadlines, so ties come up often */
      long at = (long)(next() % 50);
      ok = cserve_heap_set(&h, &nodes[k], at) == 0;
      in[k] = 1;
      ref[k] = at;
    } else {
      cserve_heap_remove(&h, &nodes[k]);
      in[k] = 0;
    }
    int count = 0;
    long min = 0;
    for (int i = 0; i < NODES; i++) {
      if (in[i]) {
        min = count++ == 0 || ref[i] < min ? ref[i] : min;
      }
      ok = ok && (in[i] ? nodes[i].index >= 0 && nodes[i].at == ref[i]
                        : nodes[i].index == -1);
    }
    const CSERVE_HEAP_NODE *m = cserve_heap_min(&h);
    ok = ok && sound(&h) && h.n == count &&
         (count ? m && m->at == min : m == NULL);
    if (!ok) {
      bad_step = step;
    }
  }
  CSERVE_TEST_ASSERT(ok,
                     "%d random sets, moves and removals match the "
                     "reference (first wrong at step %d)",
                     STEPS, bad_step);
  cserve_heap_free(&h);
}

static void test_drain_in_order(void) {
  CSERVE_HEAP h;
  CSERVE_HEAP_NODE nodes[NODES];
  int ok = cserve_heap_init(&h, NODES) == 0;
  for (int i = 0; ok && i < NODES; i++) {
    nodes[i] = (CSERVE_HEAP_NODE)CSERVE_HEAP_NODE_INIT;
    ok = cserve_heap_set(&h, &nodes[i], (long)(next() % 1000)) == 0;
  }
  long last = -1;
  int taken = 0;
  for (CSERVE_HEAP_NODE *m; ok && (m = cserve_heap_min(&h));) {
    ok = m->at >= last;
    last = m->at;
    cserve_heap_remove(&h, m);
    ok = ok && m->index == -1 && sound(&h);
    taken++;
  }
  CSERVE_TEST_ASSERT(ok && taken == NODES,
                     "taking the minimum each time drains in deadline order");
  cserve_heap_free(&h);
}

static void test_limits(void) {
  CSERVE_HEAP h;
  CSERVE_HEAP_NODE a = CSERVE_HEAP_NODE_INIT, b = CSERVE_HEAP_NODE_INIT,
                   c = CSERVE_HEAP_NODE_INIT;
  int ok = cserve_heap_init(&h, 2) == 0 && cserve_heap_set(&h, &a, 5) == 0 &&
           cserve_heap_set(&h, &b, 3) == 0;
  CSERVE_TEST_ASSERT(ok && cserve_heap_set(&h, &c, 1) == -1 && c.index == -1 &&
                         cserve_heap_min(&h) == &b,
                     "a full heap refuses a new node and is left as it was");
  CSERVE_TEST_ASSERT(cserve_heap_set(&h, &a, 1) == 0 &&
                         cserve_heap_min(&h) == &a,
                     "a full heap still moves a node it holds");
  cserve_heap_remove(&h, &c);
  CSERVE_TEST_ASSERT(h.n == 2, "removing a node it doesn't hold does nothing");
  cserve_heap_free(&h);
  CSERVE_TEST_ASSERT(a.index == -1 && b.index == -1,
                     "freeing the heap leaves its nodes in none");
}

int main(void) {
  test_random();
  test_drain_in_order();
  test_limits();
  return cserve_test_summary();
}
