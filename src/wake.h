#ifndef CSERVE_WAKE_H
#define CSERVE_WAKE_H

#include <stddef.h>
#include <stdint.h>

/* Tags handed to the loop's thread from any other: post() puts one in a
 * locked ring and makes the fd readable; the loop drains them with
 * take(). A ring that fills says so (overflowed) rather than block or
 * drop silently: the loop then treats every waiter as woken. How a
 * stream (loop.h) is woken by a thread that has news for it. */

typedef struct CSERVE_WAKE CSERVE_WAKE;

/* a ring of cap tags, or NULL with why in err */
CSERVE_WAKE *cserve_wake_new(size_t cap, char *err, size_t err_cap);
void cserve_wake_free(CSERVE_WAKE *w);
/* readable while a tag waits (or the ring overflowed) */
int cserve_wake_fd(const CSERVE_WAKE *w);
/* tag queued, from any thread */
void cserve_wake_post(CSERVE_WAKE *w, uint64_t tag);
/* up to cap tags into out, the fd drained once it's empty: how many;
 * *overflowed set (and cleared in the ring) when tags were lost since
 * the last take */
size_t cserve_wake_take(CSERVE_WAKE *w, uint64_t *out, size_t cap,
                        int *overflowed);

#endif
