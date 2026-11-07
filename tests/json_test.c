/* kit/json.c: a file an app reads, as a tree -- the grammar strict (no
 * comments, no trailing commas, no key twice), strings decoded and UTF-8,
 * numbers read whole or refused */
#include "json.h"

#include "test.h"

#include <stdio.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof *(a))

static void test_tree(void) {
  char err[128];
  CSERVE_JSON *v = cserve_json_parse(
      " {\"a\": {\"title\": \"t\\u00fc\\ud834\\udd1e\", \"n\": [1, 2.5, -0]},"
      " \"b\": true, \"c\": null}\n",
      err, sizeof err);
  CSERVE_TEST_ASSERT(v && v->type == CSERVE_JSON_OBJECT && v->count == 3,
                     "an object, its members in file order");
  const CSERVE_JSON *a = cserve_json_get(v, "a");
  const CSERVE_JSON *n = cserve_json_get(a, "n");
  long long one = 0, zero = 7, half = 0;
  CSERVE_TEST_ASSERT(
      a && !strcmp(cserve_json_str(cserve_json_get(a, "title")),
                   "t\xC3\xBC\xF0\x9D\x84\x9E"),
      "a string's escapes decoded, a surrogate pair as one character");
  CSERVE_TEST_ASSERT(
      n && n->count == 3 && cserve_json_whole(&n->items[0], 0, 9, &one) == 0 &&
          one == 1 && cserve_json_whole(&n->items[2], 0, 9, &zero) == 0 &&
          zero == 0 && cserve_json_whole(&n->items[1], 0, 9, &half) == -1 &&
          cserve_json_whole(&n->items[0], 2, 9, &one) == -1,
      "a whole number read inside its bounds, a fraction or one outside not");
  CSERVE_TEST_ASSERT(!cserve_json_get(v, "z") && !cserve_json_str(n) &&
                         !cserve_json_get(n, "a") &&
                         cserve_json_whole(NULL, 0, 1, &one) == -1,
                     "a member it hasn't, a string that isn't one: NULL");
  cserve_json_free(v);
}

static void test_refused(void) {
  static const char *const BAD[] = {
      "",
      "{",
      "{\"a\": 1,}",
      "[1, 2,]",
      "// c\n{}",
      "{} /* c */",
      "{\"a\": 1, \"a\": 2}",
      "{a: 1}",
      "\"\xFF\"",
      "\"\xC0\x80\"",
      "\"a\nb\"",
      "\"\\x\"",
      "\"\\u12\"",
      "01",
      "1.",
      ".5",
      "1e",
      "+1",
      "1e999",
      "NaN",
      "tru",
      "{} {}",
      "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
      "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
  };
  int bad = 0;
  for (size_t i = 0; i < N(BAD); i++) {
    char err[128] = "";
    CSERVE_JSON *v = cserve_json_parse(BAD[i], err, sizeof err);
    if (v || strncmp(err, "line ", 5) != 0) {
      printf("    took %s\n", BAD[i]);
      bad++;
    }
    cserve_json_free(v);
  }
  CSERVE_TEST_ASSERT(!bad, "what isn't strict JSON refused, and where said");
  char err[128];
  CSERVE_JSON *v = cserve_json_parse("\"\\u0000\\udc00\"", err, sizeof err);
  CSERVE_TEST_ASSERT(
      v && !strcmp(cserve_json_str(v), "\xEF\xBF\xBD\xEF\xBF\xBD"),
      "a NUL and a lone surrogate as U+FFFD");
  cserve_json_free(v);
}

int main(void) {
  printf("json_test\n");
  test_tree();
  test_refused();
  return cserve_test_summary();
}
