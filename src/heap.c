#include "heap.h"

#include <stdlib.h>

int cserve_heap_init(CSERVE_HEAP *h, int cap) {
  h->n = 0;
  h->cap = cap > 0 ? cap : 1;
  h->v = calloc((size_t)h->cap, sizeof *h->v);
  return h->v ? 0 : -1;
}

void cserve_heap_free(CSERVE_HEAP *h) {
  for (int i = 0; i < h->n; i++) {
    h->v[i]->index = -1;
  }
  free(h->v);
  h->v = NULL;
  h->n = h->cap = 0;
}

static void place(CSERVE_HEAP *h, int i, CSERVE_HEAP_NODE *node) {
  h->v[i] = node;
  node->index = i;
}

/* node, at i, moved up while it's due before its parent */
static void up(CSERVE_HEAP *h, int i) {
  CSERVE_HEAP_NODE *node = h->v[i];
  while (i > 0) {
    int parent = (i - 1) / 2;
    if (h->v[parent]->at <= node->at) {
      break;
    }
    place(h, i, h->v[parent]);
    i = parent;
  }
  place(h, i, node);
}

/* node, at i, moved down while a child is due before it */
static void down(CSERVE_HEAP *h, int i) {
  CSERVE_HEAP_NODE *node = h->v[i];
  for (;;) {
    int child = 2 * i + 1;
    if (child >= h->n) {
      break;
    }
    if (child + 1 < h->n && h->v[child + 1]->at < h->v[child]->at) {
      child++;
    }
    if (node->at <= h->v[child]->at) {
      break;
    }
    place(h, i, h->v[child]);
    i = child;
  }
  place(h, i, node);
}

int cserve_heap_set(CSERVE_HEAP *h, CSERVE_HEAP_NODE *node, long at) {
  if (node->index < 0) {
    if (h->n == h->cap) {
      return -1;
    }
    node->at = at;
    place(h, h->n++, node);
    up(h, node->index);
    return 0;
  }
  long was = node->at;
  node->at = at;
  if (at < was) {
    up(h, node->index);
  } else {
    down(h, node->index);
  }
  return 0;
}

void cserve_heap_remove(CSERVE_HEAP *h, CSERVE_HEAP_NODE *node) {
  int i = node->index;
  if (i < 0 || i >= h->n || h->v[i] != node) {
    return;
  }
  node->index = -1;
  CSERVE_HEAP_NODE *last = h->v[--h->n];
  if (i == h->n) {
    return;
  }
  /* the last one takes its place, and goes whichever way it must */
  place(h, i, last);
  if (i > 0 && h->v[(i - 1) / 2]->at > last->at) {
    up(h, i);
  } else {
    down(h, i);
  }
}

CSERVE_HEAP_NODE *cserve_heap_min(const CSERVE_HEAP *h) {
  return h->n > 0 ? h->v[0] : NULL;
}
