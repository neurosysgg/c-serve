#ifndef CSERVE_FUZZ_H
#define CSERVE_FUZZ_H

/* libFuzzer harnesses for the parsers that read what other programs
 * write (`make FUZZ=1 fuzz-NAME`, tools/fuzz.py, which documents them).
 * Each tools/fuzz/NAME.c is one LLVMFuzzerTestOneInput; the input is cut
 * into NUL-separated parts where a parser takes several strings. */

#define _GNU_SOURCE /* strdup, strsep under -std=c11 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer's entry, each target's one function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* a property of the parser's that the input broke: says which (the
 * first line tools/fuzz.py --triage groups by), then crashes */
#define FUZZ_CHECK(cond, ...)                                                  \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "check failed: " __VA_ARGS__);                           \
      fprintf(stderr, "\n");                                                   \
      abort();                                                                 \
    }                                                                          \
  } while (0)

/* data cut at NUL bytes into up to n malloc'd strings (the last takes the
 * rest, NULs and all cut off at its first); missing ones are "". Free
 * with fuzz_free(). */
static inline void fuzz_split(const uint8_t *data, size_t size, char **part,
                              int n) {
  size_t at = 0;
  for (int i = 0; i < n; i++) {
    size_t end = at;
    while (end < size && data[end] != 0) {
      end++;
    }
    part[i] = malloc(end - at + 1);
    memcpy(part[i], data + at, end - at);
    part[i][end - at] = '\0';
    at = end < size ? end + 1 : size;
  }
}

static inline void fuzz_free(char **part, int n) {
  for (int i = 0; i < n; i++) {
    free(part[i]);
  }
}

/* the whole input as one string (cut at its first NUL) */
static inline char *fuzz_str(const uint8_t *data, size_t size) {
  char *s = malloc(size + 1);
  memcpy(s, data, size);
  s[size] = '\0';
  return s;
}

/* s[0..n) is well-formed UTF-8 */
static inline int fuzz_utf8_ok(const char *s, size_t n) {
  const unsigned char *u = (const unsigned char *)s;
  for (size_t i = 0; i < n;) {
    unsigned char c = u[i];
    size_t len = c < 0x80                 ? 1
                 : c >= 0xc2 && c <= 0xdf ? 2
                 : c >= 0xe0 && c <= 0xef ? 3
                 : c >= 0xf0 && c <= 0xf4 ? 4
                                          : 0;
    if (!len || i + len > n) {
      return 0;
    }
    for (size_t k = 1; k < len; k++) {
      if ((u[i + k] & 0xc0) != 0x80) {
        return 0;
      }
    }
    i += len;
  }
  return 1;
}

#endif
