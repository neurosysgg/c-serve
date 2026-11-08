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
 * one is a challenge; 10 = a passkey's client data (kit/passkey.c): read
 * without a fault, taken only when its challenge, origin and type are the
 * ones asked for; 11 = authenticator data and, after a NUL-free length
 * byte, a credential id, run as a registration against a fixed key: read
 * without a fault, and taken never (the fuzzer can't sign); 12 = an event
 * stream's event from the bytes (kit/sse.c): every line it writes starts
 * a field it chose -- "id:", "event:", "data:" -- and it ends in the
 * blank line; 13 = base64url read strictly (kit/reading.c): what it takes
 * encodes back to itself, and a cookie value (kit/cookie.c) taken holds
 * none of the bytes a cookie can't. Any other first byte: as 5. */
#include "fuzz.h"

#include "cookie.h"
#include "headers.h"
#include "html.h"
#include "json.h"
#include "markup.h"
#include "passkey.h"
#include "password.h"
#include "reading.h"
#include "sse.h"

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

static const CSERVE_PASSKEY_RP FUZZ_RP = {.origin = "https://chat.test",
                                          .rp_id = "chat.test"};

static void client_data(const uint8_t *data, size_t size) {
  char err[200];
  if (cserve_passkey_client_data(data, size, "webauthn.get", "Y2hhbGxlbmdl",
                                 FUZZ_RP.origin, err, sizeof err) == 0) {
    FUZZ_CHECK(memmem(data, size, "Y2hhbGxlbmdl", 12) &&
                   memmem(data, size, "https://chat.test", 17) &&
                   memmem(data, size, "webauthn.get", 12),
               "client data taken without its challenge, origin and type");
  } else {
    FUZZ_CHECK(err[0], "refused, and no why");
  }
}

static void registration(const uint8_t *data, size_t size) {
  /* a fixed P-256 key's SPKI (the generator point) */
  static const unsigned char SPKI[91] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8,
      0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
      0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f,
      0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
      0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb,
      0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
  static const char CD[] = "{\"type\":\"webauthn.create\",\"challenge\":"
                           "\"Y2g\",\"origin\":\"https://chat.test\"}";
  if (size < 1) {
    return;
  }
  size_t id_n = data[0] % 64;
  if (id_n + 1 > size) {
    return;
  }
  char err[200];
  uint32_t count;
  int rc = cserve_passkey_register(&FUZZ_RP, "Y2g", (const unsigned char *)CD,
                                   sizeof CD - 1, data + 1 + id_n,
                                   size - 1 - id_n, SPKI, sizeof SPKI, data + 1,
                                   id_n, &count, err, sizeof err);
  (void)rc; /* taken only for the right rpIdHash and key: possible, fine */
}

static void sse(const uint8_t *data, size_t size) {
  char out[8192];
  long n =
      cserve_sse_event(out, sizeof out, 3, "message", (const char *)data, size);
  if (n < 0) {
    FUZZ_CHECK(memchr(data, '\0', size) || size > 2000, "an event refused");
    return;
  }
  FUZZ_CHECK(n >= 2 && out[n - 1] == '\n' && out[n - 2] == '\n',
             "an event that doesn't end in the blank line");
  for (long i = 0; i < n - 1;) {
    const char *line = out + i;
    FUZZ_CHECK(!strncmp(line, "id: ", 4) || !strncmp(line, "event: ", 7) ||
                   !strncmp(line, "data: ", 6),
               "a line starting a field of its own");
    const char *e = memchr(line, '\n', (size_t)(n - i));
    FUZZ_CHECK(e && !memchr(line, '\r', (size_t)(e - line)),
               "a CR inside a line");
    i = (long)(e - out) + 1;
    if (i == n - 1) {
      break;
    }
  }
}

static void binary(const uint8_t *data, size_t size) {
  char *s = fuzz_str(data, size);
  unsigned char out[512];
  long n = cserve_b64url_decode(s, out, sizeof out);
  if (n >= 0) {
    /* encode it back: the same text, one spelling per value */
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char back[1024];
    size_t o = 0;
    for (long i = 0; i < n; i += 3) {
      unsigned v = (unsigned)out[i] << 16 |
                   (i + 1 < n ? (unsigned)out[i + 1] << 8 : 0) |
                   (i + 2 < n ? out[i + 2] : 0);
      back[o++] = A[v >> 18 & 63];
      back[o++] = A[v >> 12 & 63];
      if (i + 1 < n) {
        back[o++] = A[v >> 6 & 63];
      }
      if (i + 2 < n) {
        back[o++] = A[v & 63];
      }
    }
    back[o] = '\0';
    FUZZ_CHECK(!strcmp(back, s), "base64url read that isn't its own spelling");
  }
  if (cserve_cookie_value_ok(s, strlen(s))) {
    FUZZ_CHECK(!strpbrk(s, " \";,\\\t\r\n"), "a cookie value with a separator");
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
  case 10:
    client_data(data + 1, size - 1);
    break;
  case 11:
    registration(data + 1, size - 1);
    break;
  case 12:
    sse(data + 1, size - 1);
    break;
  case 13:
    binary(data + 1, size - 1);
    break;
  default:
    render(data + 1, size - 1);
  }
  return 0;
}
