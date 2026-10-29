/* kit/headers.c, src/policy.c and kit/arena.c: a header by name, and one
 * that would end itself refused; the security headers exactly as
 * phpanta sends neurosys.gg's, and a source that isn't one refused; the
 * arena's big allocations and its first error */
#include "arena.h"
#include "headers.h"
#include "policy.h"

#include "test.h"

#include <stdio.h>
#include <string.h>

static void test_headers(void) {
  CSERVE_HTTPD_REPLY rep = {0};
  CSERVE_TEST_ASSERT(
      cserve_header(&rep, CSERVE_H_VARY, "Cookie") == 0 &&
          cserve_header(&rep, CSERVE_H_ETAG, "\"x\"") == 0 &&
          !strcmp(rep.headers, "Vary: Cookie\r\nETag: \"x\"\r\n"),
      "headers by name, in the order set");
  CSERVE_TEST_ASSERT(cserve_header(&rep, CSERVE_H_LOCATION, "/a\r\nX: y") ==
                             -1 &&
                         !strstr(rep.headers, "X: y"),
                     "a value that would end its header is refused");
  CSERVE_TEST_ASSERT(cserve_header_has(&rep, CSERVE_H_ETAG) &&
                         !cserve_header_has(&rep, CSERVE_H_CACHE_CONTROL),
                     "whether a reply has a header");
  char big[5000];
  memset(big, 'x', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  size_t before = strlen(rep.headers);
  CSERVE_TEST_ASSERT(cserve_header(&rep, CSERVE_H_X_ROBOTS_TAG, big) == -1 &&
                         strlen(rep.headers) == before,
                     "one past the buffer is refused, and leaves it as it was");
  CSERVE_TEST_ASSERT(
      !strcmp(cserve_cache_value(CSERVE_CACHE_NO_STORE), "no-store, private") &&
          !strcmp(cserve_cache_value(CSERVE_CACHE_NO_CACHE), "no-cache"),
      "Cache-Control's two values");
}

static void test_policy(void) {
  static const char *const IMG[] = {"https://my.hidrive.com", NULL};
  static const char *const FRAME[] = {"https://w.soundcloud.com", NULL};
  CSERVE_SECURITY site = {.img = IMG, .frame = FRAME};
  char out[2048], err[128];
  /* what SecurityHeaders::all() sends for neurosys.gg */
  static const char WANT[] =
      "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
      "Content-Security-Policy: default-src 'self'; script-src 'self'; "
      "style-src 'self'; img-src 'self' https://my.hidrive.com; frame-src "
      "https://w.soundcloud.com; base-uri 'self'; form-action 'self'; "
      "frame-ancestors 'none'; object-src 'none'\r\n"
      "Referrer-Policy: strict-origin-when-cross-origin\r\n"
      "X-Content-Type-Options: nosniff\r\n"
      "Permissions-Policy: geolocation=(), camera=(), microphone=(), "
      "payment=(), usb=(), midi=()\r\n"
      "Cross-Origin-Opener-Policy: same-origin\r\n"
      "Cross-Origin-Resource-Policy: same-origin\r\n";
  int rc = cserve_security_headers(&site, out, sizeof out, err, sizeof err);
  CSERVE_TEST_ASSERT(rc == 0 && !strcmp(out, WANT),
                     "neurosys.gg's security headers, as phpanta sends them");
  if (rc != 0 || strcmp(out, WANT)) {
    printf("%s\n", rc ? err : out);
  }
  static const char *const MEDIA[] = {"https://media.example", NULL};
  CSERVE_SECURITY more = {.media = MEDIA};
  CSERVE_TEST_ASSERT(
      cserve_security_headers(&more, out, sizeof out, err, sizeof err) == 0 &&
          strstr(out, "frame-src 'none'; media-src 'self' "
                      "https://media.example; base-uri"),
      "no frames named: 'none'; a directive with hosts appears in its place");
  static const char *const BAD[] = {"https://x; script-src *", NULL};
  CSERVE_SECURITY bad = {.img = BAD};
  CSERVE_TEST_ASSERT(
      cserve_security_headers(&bad, out, sizeof out, err, sizeof err) == -1 &&
          strstr(err, "isn't a source") && !out[0],
      "a source that would start a directive of its own is refused");
  CSERVE_TEST_ASSERT(
      cserve_security_headers(&site, out, 100, err, sizeof err) == -1,
      "a buffer too small is refused");
}

static void test_arena(void) {
  CSERVE_ARENA *a = cserve_arena_new();
  char *small = cserve_arena_strdup(a, "small");
  char *big = cserve_arena_alloc(a, 1 << 20);
  memset(big, 1, 1 << 20);
  char *after = cserve_arena_strdup(a, "after");
  CSERVE_TEST_ASSERT(!strcmp(small, "small") && !strcmp(after, "after") &&
                         !cserve_arena_error(a),
                     "a big allocation, and the small ones around it");
  CSERVE_TEST_ASSERT(cserve_arena_alloc(a, (size_t)-1) == NULL &&
                         cserve_arena_error(a),
                     "one that can't be made: NULL, and the arena failed");
  cserve_arena_fail(a, "a second");
  CSERVE_TEST_ASSERT(!strstr(cserve_arena_error(a), "second"),
                     "the first error is the one kept");
  CSERVE_TEST_ASSERT(!strcmp(cserve_arena_printf(a, "%d-%s", 7, "x"), "7-x"),
                     "printf into the arena");
  cserve_arena_free(a);
}

int main(void) {
  printf("headers_test\n");
  test_headers();
  test_policy();
  test_arena();
  return cserve_test_summary();
}
