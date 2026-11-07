/* kit/password.c: a PBKDF2 digest read as phpanta's PasswordHash reads
 * it, and a password matched against it -- every case's answer is
 * Phpanta's own (data/goldens.h); bcrypt, which PHP alone still reads,
 * is no digest here */
#include "password.h"

#include "data/goldens.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof *(a))

static void test_goldens(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_PASSWORD); i++) {
    const char *d = GOLD_PASSWORD[i].digest, *p = GOLD_PASSWORD[i].password;
    int valid = cserve_password_valid(d);
    int match = cserve_password_matches(d, p, strlen(p));
    if (valid != GOLD_PASSWORD[i].valid || match != GOLD_PASSWORD[i].match) {
      printf("    %s / %s: valid %d match %d\n", d, p, valid, match);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "digests and passwords as PasswordHash decides (%zu)",
                     N(GOLD_PASSWORD));
}

static void test_unmatchable(void) {
  const char *u = cserve_password_unmatchable();
  CSERVE_TEST_ASSERT(
      cserve_password_valid(u) && !strncmp(u, "$pbkdf2-sha256$600000$", 22) &&
          !cserve_password_matches(u, "", 0) &&
          !cserve_password_matches(u, u, strlen(u)),
      "the unmatchable digest is a real one at the default cost, matching "
      "nothing");
  CSERVE_TEST_ASSERT(!cserve_password_matches(NULL, "x", 1),
                     "no digest matches nothing");
}

int main(void) {
  printf("password_test\n");
  test_goldens();
  test_unmatchable();
  return cserve_test_summary();
}
