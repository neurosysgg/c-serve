#ifndef CSERVE_POOL_H
#define CSERVE_POOL_H

#include <stddef.h>

/* The loop's workers (loop.h): a fixed number of threads running jobs
 * the loop hands them, so nothing an app does -- a PBKDF2 check, a file
 * opened, a page rendered -- ever runs on the loop's thread. A job is
 * the caller's pointer, run by run(job, ud) on some worker, then handed
 * back through take(); the pool's fd turns readable when one is waiting,
 * so the loop polls it with its sockets. At most limit jobs are out at
 * once (handed in and not yet taken back): submit() refuses the next,
 * and the loop answers 503. */

typedef struct CSERVE_POOL CSERVE_POOL;

typedef void (*CSERVE_POOL_FN)(void *job, void *ud);

/* workers threads running run (limit: jobs out at once, at least
 * workers), or NULL with why in err */
CSERVE_POOL *cserve_pool_new(int workers, int limit, CSERVE_POOL_FN run,
                             void *ud, char *err, size_t err_cap);
/* job queued for a worker: 0, or -1 when limit jobs are out already */
int cserve_pool_submit(CSERVE_POOL *p, void *job);
/* readable while a finished job waits to be taken */
int cserve_pool_fd(const CSERVE_POOL *p);
/* a finished job, or NULL when none is waiting */
void *cserve_pool_take(CSERVE_POOL *p);
/* jobs handed in and not yet taken back */
int cserve_pool_out(CSERVE_POOL *p);
/* every queued job run, the workers joined, then freed. Finished jobs
 * not taken are the caller's to have taken before (out() says) */
void cserve_pool_free(CSERVE_POOL *p);

#endif
