#ifndef CSERVE_ARENA_H
#define CSERVE_ARENA_H

#include <stddef.h>

/* One request's memory: a bump allocator in malloc'd chunks, freed whole
 * when the request is done. Every node, string and phrase a page is built
 * of lives in one, so a builder never frees and a handler frees once.
 *
 * It also carries the request's first error. A builder that's refused
 * (children for a void tag, a URL the page may not emit, a phrase missing
 * an argument) says why here and hands back something harmless; render
 * then fails, and the page is a 500 with why in the log -- what a throw
 * is in phpanta. Running out of memory is an error the same way. */

typedef struct CSERVE_ARENA CSERVE_ARENA;

/* NULL: out of memory */
CSERVE_ARENA *cserve_arena_new(void);
void cserve_arena_free(CSERVE_ARENA *a);

/* n bytes, zeroed, aligned for anything; NULL only when memory ran out,
 * and the arena has failed then */
void *cserve_arena_alloc(CSERVE_ARENA *a, size_t n);
/* a copy of s (n bytes of it, NUL-terminated); "" when memory ran out */
char *cserve_arena_strndup(CSERVE_ARENA *a, const char *s, size_t n);
char *cserve_arena_strdup(CSERVE_ARENA *a, const char *s);
char *cserve_arena_printf(CSERVE_ARENA *a, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* the request's first error, said once: later ones are dropped (the first
 * is the cause, the rest its consequences) */
void cserve_arena_fail(CSERVE_ARENA *a, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* the first error, or NULL */
const char *cserve_arena_error(const CSERVE_ARENA *a);

#endif
