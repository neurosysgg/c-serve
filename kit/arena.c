#include "arena.h"

#include <stdalign.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK 16384

typedef struct CHUNK_HEAD {
  struct CHUNK_HEAD *next;
  size_t used, cap;
  alignas(max_align_t) unsigned char data[];
} CHUNK_HEAD;

struct CSERVE_ARENA {
  CHUNK_HEAD *head;
  char error[512];
  int failed;
};

CSERVE_ARENA *cserve_arena_new(void) { return calloc(1, sizeof(CSERVE_ARENA)); }

void cserve_arena_free(CSERVE_ARENA *a) {
  if (!a) {
    return;
  }
  for (CHUNK_HEAD *c = a->head, *next; c; c = next) {
    next = c->next;
    free(c);
  }
  free(a);
}

void *cserve_arena_alloc(CSERVE_ARENA *a, size_t n) {
  const size_t align = alignof(max_align_t);
  if (n > ((size_t)-1 >> 1)) {
    cserve_arena_fail(a, "an allocation of %zu bytes", n);
    return NULL;
  }
  n = n ? (n + align - 1) / align * align : align;
  CHUNK_HEAD *c = a->head;
  if (!c || c->cap - c->used < n) {
    size_t cap = n > CHUNK ? n : CHUNK;
    if (!(c = malloc(sizeof *c + cap))) {
      cserve_arena_fail(a, "out of memory (%zu bytes)", n);
      return NULL;
    }
    c->used = 0;
    c->cap = cap;
    /* a big one goes behind the current chunk, which keeps its room */
    if (a->head && cap > CHUNK) {
      c->next = a->head->next;
      a->head->next = c;
    } else {
      c->next = a->head;
      a->head = c;
    }
  }
  void *p = c->data + c->used;
  c->used += n;
  memset(p, 0, n);
  return p;
}

char *cserve_arena_strndup(CSERVE_ARENA *a, const char *s, size_t n) {
  char *p = n < (size_t)-1 ? cserve_arena_alloc(a, n + 1) : NULL;
  if (!p) {
    return "";
  }
  memcpy(p, s, n);
  return p;
}

char *cserve_arena_strdup(CSERVE_ARENA *a, const char *s) {
  return cserve_arena_strndup(a, s, strlen(s));
}

char *cserve_arena_printf(CSERVE_ARENA *a, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  char *p = n >= 0 ? cserve_arena_alloc(a, (size_t)n + 1) : NULL;
  if (!p) {
    if (n < 0) {
      cserve_arena_fail(a, "an unformattable \"%s\"", fmt);
    }
    return "";
  }
  va_start(ap, fmt);
  vsnprintf(p, (size_t)n + 1, fmt, ap);
  va_end(ap);
  return p;
}

void cserve_arena_fail(CSERVE_ARENA *a, const char *fmt, ...) {
  if (a->failed) {
    return;
  }
  a->failed = 1;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(a->error, sizeof a->error, fmt, ap);
  va_end(ap);
}

const char *cserve_arena_error(const CSERVE_ARENA *a) {
  return a->failed ? a->error : NULL;
}
