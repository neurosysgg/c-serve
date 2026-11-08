#ifndef CSERVE_HEAP_H
#define CSERVE_HEAP_H

/* The loop's timers (loop.h): a binary min-heap of deadlines, each node
 * kept inside what it times (a connection) and knowing its own place, so
 * a deadline moves or goes in O(log n). One node is one deadline; a node
 * is in the heap or not (index -1). The heap holds at most cap nodes and
 * never grows: the loop sizes it to its connection limit. Not locked:
 * the loop's thread alone touches it. */

typedef struct {
  long at;   /* the deadline (CLOCK_MONOTONIC ms) */
  int index; /* its place in the heap; -1 when it isn't in it */
} CSERVE_HEAP_NODE;

typedef struct {
  CSERVE_HEAP_NODE **v;
  int n, cap;
} CSERVE_HEAP;

/* room for cap nodes: 0, or -1 (out of memory) */
int cserve_heap_init(CSERVE_HEAP *h, int cap);
void cserve_heap_free(CSERVE_HEAP *h);

/* node due at at: put in, or moved when it's in already. 0, or -1 when
 * the heap is full (node left as it was) */
int cserve_heap_set(CSERVE_HEAP *h, CSERVE_HEAP_NODE *node, long at);
/* node out of the heap (nothing when it isn't in it) */
void cserve_heap_remove(CSERVE_HEAP *h, CSERVE_HEAP_NODE *node);
/* the node due first, or NULL when the heap is empty */
CSERVE_HEAP_NODE *cserve_heap_min(const CSERVE_HEAP *h);

/* a fresh node: in no heap */
#define CSERVE_HEAP_NODE_INIT {.at = 0, .index = -1}

#endif
