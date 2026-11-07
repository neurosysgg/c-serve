/* kit/reading.c: a query parameter, a cookie, Accept-Language, If-None-
 * Match and Range read as phpanta reads them -- every case's answer is
 * Phpanta's own, printed into data/goldens.h by neurosys's
 * test/cserve/goldens.php -- and UTF-8 told from what isn't */
#include "reading.h"

#include "data/goldens.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof *(a))

static void test_utf8(void) {
  struct {
    const char *s;
    int valid;
  } T[] = {
      {"", 1},
      {"ascii", 1},
      {"\xC3\xBC", 1},
      {"\xE2\x82\xAC", 1},
      {"\xF0\x9D\x84\x9E", 1},
      {"\xF4\x8F\xBF\xBF", 1},
      {"\xC3", 0},
      {"\xC0\x80", 0},
      {"\xE0\x80\x80", 0},
      {"\xED\xA0\x80", 0},
      {"\xF0\x80\x80\x80", 0},
      {"\xF4\x90\x80\x80", 0},
      {"\xFF", 0},
      {"\x80", 0},
  };
  int bad = 0;
  for (size_t i = 0; i < N(T); i++) {
    bad += cserve_utf8_valid(T[i].s, strlen(T[i].s)) != T[i].valid;
  }
  CSERVE_TEST_ASSERT(!bad,
                     "UTF-8: shortest forms only, no surrogates, "
                     "nothing past U+10FFFF (%d wrong)",
                     bad);
}

static void test_query(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_QUERY); i++) {
    char v[256], err[128];
    int rc = cserve_query_get(GOLD_QUERY[i].query, "a", v, sizeof v, err,
                              sizeof err);
    if (rc != GOLD_QUERY[i].rc || (rc == 0 && strcmp(v, GOLD_QUERY[i].value))) {
      printf("    query \"%s\": %d \"%s\", phpanta %d \"%s\"\n",
             GOLD_QUERY[i].query, rc, rc == 0 ? v : "", GOLD_QUERY[i].rc,
             GOLD_QUERY[i].value);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "a query's a, as Input::fromUrlEncoded reads it "
                     "(%zu cases, %d wrong)",
                     N(GOLD_QUERY), bad);
  char v[4], err[128];
  CSERVE_TEST_ASSERT(
      cserve_query_get("a=12345", "a", v, sizeof v, err, sizeof err) == -1 &&
          err[0],
      "a value past what it may be: unreadable, and why");
  CSERVE_TEST_ASSERT(
      cserve_query_get(NULL, "a", v, sizeof v, err, sizeof err) == 1,
      "no query: not there");
}

static void test_cookie(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_COOKIE); i++) {
    char v[256];
    int rc = cserve_cookie_get(GOLD_COOKIE[i].cookie, "lang", v, sizeof v);
    if (rc != GOLD_COOKIE[i].rc ||
        (rc == 0 && strcmp(v, GOLD_COOKIE[i].value))) {
      printf("    cookie \"%s\": %d \"%s\", phpanta %d \"%s\"\n",
             GOLD_COOKIE[i].cookie, rc, rc == 0 ? v : "", GOLD_COOKIE[i].rc,
             GOLD_COOKIE[i].value);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "the lang cookie, as RequestCookies reads it "
                     "(%zu cases, %d wrong)",
                     N(GOLD_COOKIE), bad);
  char v[2];
  CSERVE_TEST_ASSERT(cserve_cookie_get("lang=de", "lang", v, sizeof v) == -1,
                     "a value past what it may be: -1");
}

static void test_accept_language(void) {
  static const char *const OFFERED[] = {"en", "de"};
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_ACCEPT_LANGUAGE); i++) {
    int l = cserve_accept_language(GOLD_ACCEPT_LANGUAGE[i].header, OFFERED, 2);
    if (l != GOLD_ACCEPT_LANGUAGE[i].lang) {
      printf("    Accept-Language \"%s\": %d, phpanta %d\n",
             GOLD_ACCEPT_LANGUAGE[i].header, l, GOLD_ACCEPT_LANGUAGE[i].lang);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "Accept-Language against en, de, as "
                     "AcceptedLanguages chooses (%zu cases, %d wrong)",
                     N(GOLD_ACCEPT_LANGUAGE), bad);
  CSERVE_TEST_ASSERT(cserve_accept_language(NULL, OFFERED, 2) == 0,
                     "no header: the default");
}

static void test_etag(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_ETAG); i++) {
    int m = cserve_etag_matches(GOLD_ETAG[i].header, GOLD_ETAG_FINGERPRINT);
    if (m != GOLD_ETAG[i].match) {
      printf("    If-None-Match \"%s\": %d, phpanta %d\n", GOLD_ETAG[i].header,
             m, GOLD_ETAG[i].match);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "If-None-Match, as ETag::matches reads it "
                     "(%zu cases, %d wrong)",
                     N(GOLD_ETAG), bad);
  CSERVE_TEST_ASSERT(!cserve_etag_matches(NULL, "x"), "no header: no match");
}

static void test_range(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_RANGE); i++) {
    long long first = -1, last = -1;
    CSERVE_RANGE k =
        cserve_range(GOLD_RANGE[i].header, GOLD_RANGE[i].size, &first, &last);
    if ((int)k != GOLD_RANGE[i].kind ||
        (k == CSERVE_RANGE_PARTIAL &&
         (first != GOLD_RANGE[i].first || last != GOLD_RANGE[i].last))) {
      printf("    Range \"%s\" of %lld: %d %lld-%lld, phpanta %d %lld-%lld\n",
             GOLD_RANGE[i].header, GOLD_RANGE[i].size, (int)k, first, last,
             GOLD_RANGE[i].kind, GOLD_RANGE[i].first, GOLD_RANGE[i].last);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "Range against four sizes, as ByteRange parses it "
                     "(%zu cases, %d wrong)",
                     N(GOLD_RANGE), bad);
}

static void test_basic(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_BASIC); i++) {
    char user[256], pass[256];
    cserve_basic_credentials(GOLD_BASIC[i].header, user, sizeof user, pass,
                             sizeof pass);
    if (strcmp(user, GOLD_BASIC[i].user) || strcmp(pass, GOLD_BASIC[i].pass)) {
      printf("    %s: \"%s\" \"%s\"\n", GOLD_BASIC[i].header, user, pass);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad, "Basic credentials as AuthScheme reads them (%zu)",
                     N(GOLD_BASIC));
  char user[4], pass[4];
  CSERVE_TEST_ASSERT(
      cserve_basic_credentials("Basic ZGVtbzpwdw==", user, sizeof user, pass,
                               sizeof pass) == 1 &&
          !*user && !*pass &&
          cserve_basic_credentials("Basic AGE6Yg==", user, sizeof user, pass,
                                   sizeof pass) == 1 &&
          cserve_basic_credentials(NULL, user, sizeof user, pass,
                                   sizeof pass) == 1,
      "a credential too long, holding a NUL, or none: both empty");
}

int main(void) {
  printf("reading_test\n");
  test_utf8();
  test_query();
  test_cookie();
  test_accept_language();
  test_etag();
  test_range();
  test_basic();
  return cserve_test_summary();
}
