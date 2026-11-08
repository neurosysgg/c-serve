#define _GNU_SOURCE /* getrandom() */
#include "tarpit.h"

#include "conn.h"

#include <psa/crypto.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define WAYS 8

typedef struct {
  unsigned char key[16];
  int used;
  int fails;
  long until; /* the wait ends */
  long last;  /* the last failure (the decay counts from it) */
} ENTRY;

struct CSERVE_TARPIT {
  pthread_mutex_t lock;
  long (*now)(void);
  unsigned char secret[32];
  int nsets;
  ENTRY *e; /* nsets * WAYS */
};

/* which of a request's two keys */
enum { K_ACCOUNT = 'a', K_NETWORK = 'n' };

CSERVE_TARPIT *cserve_tarpit_new(int entries, long (*now)(void), char *err,
                                 size_t err_cap) {
  CSERVE_TARPIT *t = calloc(1, sizeof *t);
  int sets = entries / WAYS > 0 ? entries / WAYS : 1;
  if (!t || !(t->e = calloc((size_t)sets * WAYS, sizeof *t->e))) {
    free(t);
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  if (getrandom(t->secret, sizeof t->secret, 0) != (ssize_t)sizeof t->secret ||
      psa_crypto_init() != PSA_SUCCESS) {
    free(t->e);
    free(t);
    snprintf(err, err_cap, "the tarpit's secret: no randomness, or no crypto");
    return NULL;
  }
  t->nsets = sets;
  t->now = now ? now : cserve_net_now;
  pthread_mutex_init(&t->lock, NULL);
  return t;
}

void cserve_tarpit_free(CSERVE_TARPIT *t) {
  if (!t) {
    return;
  }
  pthread_mutex_destroy(&t->lock);
  free(t->e);
  free(t);
}

/* the key's 16 bytes and its set: a SHA-256 of the secret, which key it
 * is, the network and (for the account's) the account. A hash, not a
 * MAC: nobody ever sees one, so what's hidden is the secret alone. */
static int key_of(const CSERVE_TARPIT *t, int kind, int family,
                  const unsigned char *net, const char *account,
                  unsigned char key[16]) {
  size_t alen = kind == K_ACCOUNT && account ? strlen(account) : 0;
  size_t n = sizeof t->secret + 2 + 16 + alen;
  unsigned char *in = malloc(n);
  if (!in) {
    return -1;
  }
  memcpy(in, t->secret, sizeof t->secret);
  in[32] = (unsigned char)kind;
  in[33] = (unsigned char)family;
  memcpy(in + 34, net, 16);
  memcpy(in + 50, account ? account : "", alen);
  unsigned char h[32];
  size_t hl = 0;
  psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, in, n, h, sizeof h, &hl);
  free(in);
  if (st != PSA_SUCCESS) {
    return -1;
  }
  memcpy(key, h, 16);
  unsigned set = (unsigned)h[16] << 24 | (unsigned)h[17] << 16 |
                 (unsigned)h[18] << 8 | h[19];
  return (int)(set % (unsigned)t->nsets);
}

/* the failures a quiet stretch has taken off */
static void decay(ENTRY *e, long now) {
  long drops = e->fails > 0 ? (now - e->last) / CSERVE_TARPIT_DECAY_MS : 0;
  if (drops > 0) {
    e->fails = drops >= e->fails ? 0 : e->fails - (int)drops;
    e->last += drops * CSERVE_TARPIT_DECAY_MS;
  }
}

/* the wait fails earn, past the free ones */
static long wait_for(int fails, int grace) {
  int n = fails - grace;
  if (n <= 0) {
    return 0;
  }
  if (n - 1 >= 20) {
    return CSERVE_TARPIT_CAP_MS;
  }
  long ms = (long)CSERVE_TARPIT_BASE_MS << (n - 1);
  return ms < CSERVE_TARPIT_CAP_MS ? ms : CSERVE_TARPIT_CAP_MS;
}

static ENTRY *find(CSERVE_TARPIT *t, int set, const unsigned char key[16]) {
  ENTRY *s = t->e + (size_t)set * WAYS;
  for (int i = 0; i < WAYS; i++) {
    if (s[i].used && !memcmp(s[i].key, key, 16)) {
      return &s[i];
    }
  }
  return NULL;
}

/* key's entry, or a new one: a free one, else the one with the least
 * wait left (and of those, the fewest failures) */
static ENTRY *claim(CSERVE_TARPIT *t, int set, const unsigned char key[16],
                    long now) {
  ENTRY *e = find(t, set, key);
  if (e) {
    return e;
  }
  ENTRY *s = t->e + (size_t)set * WAYS, *pick = NULL;
  for (int i = 0; i < WAYS && !(pick && !pick->used); i++) {
    if (s[i].used) {
      decay(&s[i], now);
    }
    long left = s[i].until > now ? s[i].until - now : 0;
    long pick_left = pick && pick->until > now ? pick->until - now : 0;
    if (!pick || !s[i].used || left < pick_left ||
        (left == pick_left && s[i].fails < pick->fails)) {
      pick = &s[i];
    }
  }
  *pick = (ENTRY){.used = 1};
  memcpy(pick->key, key, 16);
  return pick;
}

static long api_waiting(CSERVE_TARPIT *t, int family, const unsigned char *net,
                        const char *account, int extend) {
  unsigned char ka[16], kn[16];
  int sa = key_of(t, K_ACCOUNT, family, net, account, ka);
  int sn = key_of(t, K_NETWORK, family, net, NULL, kn);
  if (sa < 0 || sn < 0) {
    return 0;
  }
  pthread_mutex_lock(&t->lock);
  long now = t->now(), left = 0;
  ENTRY *both[2] = {find(t, sa, ka), find(t, sn, kn)};
  for (int i = 0; i < 2; i++) {
    ENTRY *e = both[i];
    if (!e || e->until <= now) {
      continue;
    }
    if (extend) {
      long until = e->until + CSERVE_TARPIT_BASE_MS;
      e->until = until < now + CSERVE_TARPIT_CAP_MS
                     ? until
                     : now + CSERVE_TARPIT_CAP_MS;
    }
    left = e->until - now > left ? e->until - now : left;
  }
  pthread_mutex_unlock(&t->lock);
  return left;
}

static long api_failed(CSERVE_TARPIT *t, int family, const unsigned char *net,
                       const char *account) {
  unsigned char ka[16], kn[16];
  int sa = key_of(t, K_ACCOUNT, family, net, account, ka);
  int sn = key_of(t, K_NETWORK, family, net, NULL, kn);
  if (sa < 0 || sn < 0) {
    return CSERVE_TARPIT_BASE_MS; /* no key: at least the first step */
  }
  pthread_mutex_lock(&t->lock);
  long now = t->now(), left = 0;
  const int sets[2] = {sa, sn};
  const unsigned char *keys[2] = {ka, kn};
  const int grace[2] = {0, CSERVE_TARPIT_PREFIX_FREE};
  for (int i = 0; i < 2; i++) {
    ENTRY *e = claim(t, sets[i], keys[i], now);
    decay(e, now);
    e->fails++;
    e->last = now;
    long until = now + wait_for(e->fails, grace[i]);
    e->until = until > e->until ? until : e->until;
    left = e->until - now > left ? e->until - now : left;
  }
  pthread_mutex_unlock(&t->lock);
  return left;
}

static void api_passed(CSERVE_TARPIT *t, int family, const unsigned char *net,
                       const char *account) {
  unsigned char ka[16];
  int sa = key_of(t, K_ACCOUNT, family, net, account, ka);
  if (sa < 0) {
    return;
  }
  pthread_mutex_lock(&t->lock);
  ENTRY *e = find(t, sa, ka);
  if (e) {
    *e = (ENTRY){0};
  }
  pthread_mutex_unlock(&t->lock);
}

CSERVE_TARPIT_API cserve_tarpit_api(CSERVE_TARPIT *t) {
  return (CSERVE_TARPIT_API){.t = t,
                             .waiting = api_waiting,
                             .failed = api_failed,
                             .passed = api_passed};
}
