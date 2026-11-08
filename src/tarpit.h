#ifndef CSERVE_TARPIT_H
#define CSERVE_TARPIT_H

#include <stddef.h>

/* The brake on guessing (docs/research/comms.md in neurosys, "The
 * tarpit"): a failed login makes its key wait, and the wait doubles with
 * every failure. The host owns the one table, and an app reaches it
 * through its init()'s env (app.h; kit/tarpit.h wraps it), so it holds
 * however many apps a host serves and goes off with one flag.
 *
 * A key is a network -- an IPv4 address, an IPv6 /64 (httpd.h's
 * peer_family, peer_net) -- with the account tried, and the network on
 * its own too, counted with a higher threshold, so guesses spread over
 * many accounts are slowed as well. Never the account alone: a stranger
 * could lock a friend out with it.
 *
 *   wait = base * 2^(failures - 1), at most cap
 *
 * The network's own count waits only past PREFIX_FREE failures. A count
 * drops by one for each DECAY_MS without a failure, and a success clears
 * the account's (not the network's).
 *
 * The table is fixed: sets of 8 entries, a key's set picked by a SHA-256
 * of a secret drawn at start and the key, so nobody can aim keys at one
 * set. A full set gives up the entry with the least wait left -- never
 * the oldest, which a flood of junk keys could use to wash a penalty
 * away. Locked: every worker calls it. */

typedef struct CSERVE_TARPIT CSERVE_TARPIT;

/* what an app is handed (env->tarpit): the table and its three calls.
 * Each takes the request's peer family and network and the account (NUL-
 * terminated, any bytes), and the time is the host's own clock. */
typedef struct {
  CSERVE_TARPIT *t;
  /* ms the key must still wait (0: none). extend: a request during the
   * wait, which makes it longer by the base step (up to the cap) */
  long (*waiting)(CSERVE_TARPIT *t, int family, const unsigned char *net,
                  const char *account, int extend);
  /* a failure counted: the ms its answer is held back */
  long (*failed)(CSERVE_TARPIT *t, int family, const unsigned char *net,
                 const char *account);
  /* a success: the account's count cleared */
  void (*passed)(CSERVE_TARPIT *t, int family, const unsigned char *net,
                 const char *account);
} CSERVE_TARPIT_API;

#define CSERVE_TARPIT_BASE_MS 1000
#define CSERVE_TARPIT_CAP_MS (5 * 60 * 1000)
#define CSERVE_TARPIT_DECAY_MS (10 * 60 * 1000)
#define CSERVE_TARPIT_PREFIX_FREE 8

/* a table of (about) entries keys, on clock now (NULL: CLOCK_MONOTONIC
 * ms; a test's own), or NULL with why in err */
CSERVE_TARPIT *cserve_tarpit_new(int entries, long (*now)(void), char *err,
                                 size_t err_cap);
void cserve_tarpit_free(CSERVE_TARPIT *t);
/* the API over t */
CSERVE_TARPIT_API cserve_tarpit_api(CSERVE_TARPIT *t);

#endif
