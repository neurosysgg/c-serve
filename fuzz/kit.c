/* the toolkit's readers of outside input (kit/reading.c) and its render
 * (kit/markup.c). First byte: 0 = a query, its parameter "a": a value
 * read is UTF-8 and fits; 1 = a Cookie header, its "lang": the value
 * holds no ';'; 2 = Accept-Language against three languages: a choice
 * among them; 3 = If-None-Match: any header with the validator added
 * matches it; 4 = Range (the next two bytes the file's size): a part is
 * inside the file; 5 = text and an address (NUL-separated) rendered as
 * <p>text</p> and <a href>: the text's escaping leaves no &<>"' of its
 * own, what comes out is UTF-8, and an address let through is https:,
 * mailto: or stays on the origin; 6 = a JSON file (kit/json.c): a tree
 * read has strings that are UTF-8, keys said once; 7 = an Authorization
 * header's Basic credentials: both fit, neither holds a NUL; 8 = a
 * password digest's grammar (kit/password.c; read only -- matching costs
 * 100 000 iterations a run); 9 = a realm made of rawurlencode(): every
 * one is a challenge. Any other first byte: as 5. */
#include "fuzz.h"

#include "headers.h"
#include "html.h"
#include "json.h"
#include "markup.h"
#include "password.h"
#include "reading.h"

#include <strings.h>

static void query(const uint8_t *data, size_t size) {
  char *q = fuzz_str(data, size), v[64], err[128];
  int rc = cserve_query_get(q, "a", v, sizeof v, err, sizeof err);
  FUZZ_CHECK(rc >= -1 && rc <= 1, "query: %d", rc);
  FUZZ_CHECK(rc != 0 || cserve_utf8_valid(v, strlen(v)),
             "a value read that isn't UTF-8");
  FUZZ_CHECK(rc != -1 || err[0], "unreadable, and no why");
  free(q);
}

static void cookie(const uint8_t *data, size_t size) {
  char *h = fuzz_str(data, size), v[64];
  int rc = cserve_cookie_get(h, "lang", v, sizeof v);
  FUZZ_CHECK(rc >= -1 && rc <= 1, "cookie: %d", rc);
  FUZZ_CHECK(rc != 0 || !strchr(v, ';'), "a cookie's value with a ';'");
  free(h);
}

static void accept_language(const uint8_t *data, size_t size) {
  static const char *const OFFERED[] = {"en", "de", "fr"};
  char *h = fuzz_str(data, size);
  int l = cserve_accept_language(h, OFFERED, 3);
  FUZZ_CHECK(l >= 0 && l < 3, "a language chosen out of range: %d", l);
  free(h);
}

static void etag(const uint8_t *data, size_t size) {
  static const char FP[] = "0123456789abcdef0123456789abcdef";
  char *h = fuzz_str(data, size);
  (void)cserve_etag_matches(h, FP);
  size_t n = strlen(h);
  char *with = malloc(n + sizeof FP + 8);
  /* after a ", " every quote of h's is closed or the list's own */
  snprintf(with, n + sizeof FP + 8, "%s%s\"%s\"", h, strchr(h, '"') ? "\"" : "",
           FP);
  int quotes = 0;
  for (const char *p = with; *p; p++) {
    quotes += *p == '"';
  }
  FUZZ_CHECK(quotes % 2 || cserve_etag_matches(with, FP),
             "a header holding the validator doesn't match it: %s", with);
  free(with);
  free(h);
}

static void range(const uint8_t *data, size_t size) {
  if (size < 2) {
    return;
  }
  long long fsize = data[0] << 8 | data[1], first = -1, last = -1;
  char *h = fuzz_str(data + 2, size - 2);
  CSERVE_RANGE k = cserve_range(h, fsize, &first, &last);
  FUZZ_CHECK(k != CSERVE_RANGE_PARTIAL ||
                 (first >= 0 && first <= last && last < fsize),
             "a part outside the file: %lld-%lld of %lld", first, last, fsize);
  free(h);
}

static const CSERVE_LANGUAGES LANGS = {{"en"}, 1};

static void render(const uint8_t *data, size_t size) {
  char *part[2];
  fuzz_split(data, size, part, 2);
  CSERVE_ARENA *a = cserve_arena_new();
  char *out;
  size_t len;
  int rc = cserve_render(a,
                         cserve_containing(a, cserve_el(a, &cserve_tag_p),
                                           cserve_text(a, part[0])),
                         &LANGS, 0, &out, &len);
  FUZZ_CHECK(rc == 0, "a text that didn't render: %s", cserve_arena_error(a));
  FUZZ_CHECK(len >= 7 && !strncmp(out, "<p>", 3) &&
                 !strcmp(out + len - 4, "</p>"),
             "a paragraph that isn't one");
  for (const char *c = out + 3; c < out + len - 4; c++) {
    FUZZ_CHECK(!strchr("<>\"'", *c), "text escaped with markup left in it: %s",
               out);
  }
  FUZZ_CHECK(fuzz_utf8_ok(out, len), "rendered text that isn't UTF-8");
  free(out);
  cserve_arena_free(a);

  a = cserve_arena_new();
  rc = cserve_render(
      a,
      cserve_attr(a, cserve_el(a, &cserve_tag_a), &cserve_attr_href, part[1]),
      &LANGS, 0, &out, &len);
  if (rc == 0) {
    const char *u = part[1];
    int origin = (*u == '/' || *u == '#') && cserve_stays_on_origin(u);
    FUZZ_CHECK(origin || !strncasecmp(u, "https:", 6) ||
                   !strncasecmp(u, "mailto:", 7),
               "an address let through: %s", u);
    FUZZ_CHECK(!strchr(out + 9, '"') || strchr(out + 9, '"') == out + len - 6,
               "an attribute value that ends early: %s", out);
    free(out);
  }
  /* whatever starts with two slashes once a parser has read it leaves */
  const char *p = part[1];
  while (*p && (unsigned char)*p <= 0x20) {
    p++;
  }
  char first[2] = {0};
  for (int n = 0; *p && n < 2; p++) {
    if (*p != '\t' && *p != '\n' && *p != '\r') {
      first[n++] = *p;
    }
  }
  FUZZ_CHECK(!(strchr("/\\", first[0]) && first[0] && first[1] &&
               strchr("/\\", first[1])) ||
                 !cserve_stays_on_origin(part[1]),
             "an address of another host stays: %s", part[1]);
  cserve_arena_free(a);
  fuzz_free(part, 2);
}

/* every string and key under v is UTF-8, every object's keys distinct */
static void json_walk(const CSERVE_JSON *v) {
  FUZZ_CHECK(v->type != CSERVE_JSON_STRING ||
                 cserve_utf8_valid(v->string, strlen(v->string)),
             "a string read that isn't UTF-8");
  for (int i = 0; i < v->count; i++) {
    if (v->type == CSERVE_JSON_OBJECT) {
      for (int k = 0; k < i; k++) {
        FUZZ_CHECK(strcmp(v->keys[i], v->keys[k]) != 0, "a key read twice");
      }
    }
    json_walk(&v->items[i]);
  }
}

static void json(const uint8_t *data, size_t size) {
  char *t = fuzz_str(data, size), err[128] = "";
  CSERVE_JSON *v = cserve_json_parse(t, err, sizeof err);
  FUZZ_CHECK(v || !strncmp(err, "line ", 5), "refused, and not said where");
  if (v) {
    json_walk(v);
  }
  cserve_json_free(v);
  free(t);
}

static void basic(const uint8_t *data, size_t size) {
  char *h = fuzz_str(data, size), user[16], pass[16];
  int rc = cserve_basic_credentials(h, user, sizeof user, pass, sizeof pass);
  FUZZ_CHECK(rc == 0 || (rc == 1 && !*user && !*pass),
             "no credential, but something kept: %d", rc);
  FUZZ_CHECK(strlen(user) < sizeof user && strlen(pass) < sizeof pass &&
                 !strchr(user, ':'),
             "a user with a ':', or past its buffer");
  free(h);
}

static void digest(const uint8_t *data, size_t size) {
  char *d = fuzz_str(data, size);
  int valid = cserve_password_valid(d);
  FUZZ_CHECK(!valid || !strncmp(d, "$pbkdf2-sha256$", 15),
             "a digest read that isn't one: %s", d);
  free(d);
}

static void realm(const uint8_t *data, size_t size) {
  char *s = fuzz_str(data, size), enc[512], r[600];
  if (cserve_rawurlencode(s, enc, sizeof enc) == 0) {
    CSERVE_HTTPD_REPLY rep = {0};
    snprintf(r, sizeof r, "x: %s", enc);
    FUZZ_CHECK(cserve_basic_challenge(&rep, r) == 0,
               "rawurlencode() made a realm qdtext refuses: %s", r);
    FUZZ_CHECK(!strpbrk(enc, "\"\\ "), "an encoding with a quote");
  }
  free(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  switch (data[0]) {
  case 0:
    query(data + 1, size - 1);
    break;
  case 1:
    cookie(data + 1, size - 1);
    break;
  case 2:
    accept_language(data + 1, size - 1);
    break;
  case 3:
    etag(data + 1, size - 1);
    break;
  case 4:
    range(data + 1, size - 1);
    break;
  case 6:
    json(data + 1, size - 1);
    break;
  case 7:
    basic(data + 1, size - 1);
    break;
  case 8:
    digest(data + 1, size - 1);
    break;
  case 9:
    realm(data + 1, size - 1);
    break;
  default:
    render(data + 1, size - 1);
  }
  return 0;
}
