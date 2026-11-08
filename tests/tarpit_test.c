/* src/tarpit.c on a clock the test moves: the wait doubling to its cap,
 * a request during the wait making it longer, the decay, a success
 * clearing the account and not the network, keys apart by account and
 * by network (an IPv6 /64 as one), the network's own count past its free
 * failures, and a full table giving up the entry with the least wait --
 * so a flood of junk keys can't wash a real penalty away. kit/login.c on
 * top: the 429 and its Retry-After, the reply held back, a peer nobody
 * named left alone. */
#include "tarpit.h"

#include "login.h"

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long g_now = 1000000;
static long now(void) { return g_now; }

static const unsigned char NET_A[16] = {192, 0, 2, 1};
static const unsigned char NET_B[16] = {192, 0, 2, 2};
static const unsigned char NET6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1};

#define BASE CSERVE_TARPIT_BASE_MS
#define CAP CSERVE_TARPIT_CAP_MS

static void test_doubling(void) {
  char err[200];
  CSERVE_TARPIT *t = cserve_tarpit_new(1024, now, err, sizeof err);
  CSERVE_TARPIT_API a = cserve_tarpit_api(t);
  long w1 = a.failed(t, 4, NET_A, "demo");
  g_now += w1;
  long w2 = a.failed(t, 4, NET_A, "demo");
  g_now += w2;
  long w3 = a.failed(t, 4, NET_A, "demo");
  CSERVE_TEST_ASSERT(w1 == BASE && w2 == 2 * BASE && w3 == 4 * BASE,
                     "each failure doubles the wait: %ld, %ld, %ld", w1, w2,
                     w3);
  CSERVE_TEST_ASSERT(a.waiting(t, 4, NET_A, "demo", 0) == w3 &&
                         a.waiting(t, 4, NET_A, "other", 0) == 0 &&
                         a.waiting(t, 4, NET_B, "demo", 0) == 0,
                     "the wait is the key's: another account, another network "
                     "free");
  long ext = a.waiting(t, 4, NET_A, "demo", 1);
  CSERVE_TEST_ASSERT(ext == w3 + BASE,
                     "asking during the wait makes it a step longer (%ld)",
                     ext);
  for (int i = 0; i < 30; i++) {
    g_now += CAP;
    (void)a.failed(t, 4, NET_A, "demo");
  }
  CSERVE_TEST_ASSERT(a.waiting(t, 4, NET_A, "demo", 0) == CAP &&
                         a.waiting(t, 4, NET_A, "demo", 1) == CAP,
                     "the wait stops at its cap, extended or not");
  a.passed(t, 4, NET_A, "demo");
  g_now += CAP;
  CSERVE_TEST_ASSERT(a.failed(t, 4, NET_A, "demo") == CAP,
                     "a success clears the account, not the network's count");
  cserve_tarpit_free(t);
}

static void test_decay(void) {
  char err[200];
  CSERVE_TARPIT *t = cserve_tarpit_new(1024, now, err, sizeof err);
  CSERVE_TARPIT_API a = cserve_tarpit_api(t);
  for (int i = 0; i < 4; i++) {
    g_now += CAP;
    (void)a.failed(t, 4, NET_B, "x");
  }
  g_now += 2 * CSERVE_TARPIT_DECAY_MS;
  long w = a.failed(t, 4, NET_B, "x");
  CSERVE_TEST_ASSERT(w == 4 * BASE,
                     "two quiet stretches take two failures off (%ld)", w);
  cserve_tarpit_free(t);
}

static void test_network(void) {
  char err[200];
  CSERVE_TARPIT *t = cserve_tarpit_new(1024, now, err, sizeof err);
  CSERVE_TARPIT_API a = cserve_tarpit_api(t);
  char account[16];
  long w = 0;
  for (int i = 0; i < CSERVE_TARPIT_PREFIX_FREE; i++) {
    snprintf(account, sizeof account, "acct%d", i);
    g_now += CAP;
    w = a.failed(t, 6, NET6, account);
  }
  CSERVE_TEST_ASSERT(w == BASE,
                     "spread over accounts, the network's free failures cost "
                     "the account's first step only");
  g_now += CAP;
  w = a.failed(t, 6, NET6, "fresh");
  unsigned char same64[16];
  memcpy(same64, NET6, 16);
  CSERVE_TEST_ASSERT(w == BASE && a.waiting(t, 6, same64, "untried", 0) == BASE,
                     "past them the network waits too, for every account");
  cserve_tarpit_free(t);
}

static void test_flood(void) {
  char err[200];
  /* one set: every key competes for 8 entries */
  CSERVE_TARPIT *t = cserve_tarpit_new(8, now, err, sizeof err);
  CSERVE_TARPIT_API a = cserve_tarpit_api(t);
  for (int i = 0; i < 5; i++) {
    g_now += CAP;
    (void)a.failed(t, 4, NET_A, "target");
  }
  long before = a.waiting(t, 4, NET_A, "target", 0);
  unsigned char junk[16] = {10};
  char account[16];
  for (int i = 0; i < 200; i++) {
    junk[1] = (unsigned char)i;
    snprintf(account, sizeof account, "j%d", i);
    (void)a.failed(t, 4, junk, account);
  }
  CSERVE_TEST_ASSERT(before == 16 * BASE &&
                         a.waiting(t, 4, NET_A, "target", 0) == before,
                     "200 junk keys in a full table: the real penalty stays");
  cserve_tarpit_free(t);
}

static void test_kit(void) {
  char err[200];
  CSERVE_TARPIT *t = cserve_tarpit_new(1024, now, err, sizeof err);
  CSERVE_TARPIT_API a = cserve_tarpit_api(t);
  cserve_login_use(&a);
  CSERVE_HTTPD_REQ *r = calloc(1, sizeof *r);
  r->peer_family = 4;
  memcpy(r->peer_net, NET_B, 16);
  CSERVE_HTTPD_REPLY rep = {0};
  g_now += CAP;
  CSERVE_TEST_ASSERT(cserve_login_check(r, "k", &rep) == 0 && !rep.status,
                     "a key that needn't wait: through");
  cserve_httpd_text(&rep, 401, "text/plain", "", 0);
  cserve_login_fail(r, "k", &rep);
  CSERVE_TEST_ASSERT(rep.delay_ms == BASE, "a failure: its 401 held back");
  cserve_httpd_release(&rep);
  memset(&rep, 0, sizeof rep);
  g_now += 200;
  CSERVE_TEST_ASSERT(cserve_login_check(r, "k", &rep) == 1 &&
                         rep.status == 429 &&
                         strstr(rep.headers, "Retry-After: 2\r\n") &&
                         strstr(rep.headers, "Cache-Control: no-store"),
                     "during the wait: 429, Retry-After in whole seconds, "
                     "made longer (%s)",
                     rep.headers);
  cserve_httpd_release(&rep);
  memset(&rep, 0, sizeof rep);
  r->peer_family = 0;
  CSERVE_TEST_ASSERT(cserve_login_check(r, "k", &rep) == 0,
                     "a peer the server didn't name: left alone");
  cserve_login_fail(r, "k", &rep);
  CSERVE_TEST_ASSERT(rep.delay_ms == 0, "and never held back");
  cserve_login_use(NULL);
  r->peer_family = 4;
  CSERVE_TEST_ASSERT(cserve_login_check(r, "k", &rep) == 0,
                     "no tarpit at all (--no-tarpit): every call does nothing");
  free(r);
  cserve_tarpit_free(t);
}

int main(void) {
  test_doubling();
  test_decay();
  test_network();
  test_flood();
  test_kit();
  return cserve_test_summary();
}
