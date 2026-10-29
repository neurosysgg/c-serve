#ifndef CSERVE_TEST_H
#define CSERVE_TEST_H

/* The suites' one assertion and their tally (ctui's ctui_test.h, the part
 * that isn't about a screen). A suite's main() ends in
 * `return cserve_test_summary();`, so `make test` reads exit statuses. */

#include <stdio.h>

static int cserve_test_pass_count = 0;
static int cserve_test_fail_count = 0;

#define CSERVE_TEST_ASSERT(cond, ...)                                          \
  do {                                                                         \
    if (cond) {                                                                \
      cserve_test_pass_count++;                                                \
      printf("  ok  " __VA_ARGS__);                                            \
      printf("\n");                                                            \
    } else {                                                                   \
      cserve_test_fail_count++;                                                \
      printf("FAIL  " __VA_ARGS__);                                            \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                               \
    }                                                                          \
  } while (0)

/* the tally printed; 0 if everything passed, 1 otherwise */
static inline int cserve_test_summary(void) {
  printf("%d passed, %d failed\n", cserve_test_pass_count,
         cserve_test_fail_count);
  return cserve_test_fail_count == 0 ? 0 : 1;
}

#endif
