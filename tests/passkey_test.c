/* kit/passkey.h against a software authenticator made here (a PSA key,
 * its SPKI, authenticator data with the attested credential and its COSE
 * key, the client data a browser writes, a DER signature): each ceremony
 * taken when it's right and refused for each thing that can be wrong.
 * Then the kit's other pieces a login and a chat need: base64url read
 * strictly, a cookie set, an event stream's events, a JSON string. */
#define _GNU_SOURCE

#include "arena.h"
#include "cookie.h"
#include "json.h"
#include "passkey.h"
#include "reading.h"
#include "sse.h"

#include "test.h"

#include <mbedtls/pk.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const CSERVE_PASSKEY_RP RP = {.origin = "https://chat.test",
                                     .rp_id = "chat.test"};
static const char CHALLENGE[] = "Q2hhbGxlbmdlLW1pbnRlZC1ieS10aGUtc2VydmVy";

/* --- a software authenticator --- */

typedef struct {
  mbedtls_svc_key_id_t key;
  unsigned char spki[91];
  unsigned char id[16];
} DEVICE;

static int device(DEVICE *d, unsigned char seed) {
  psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(&a, 256);
  psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
  memset(d->id, seed, sizeof d->id);
  unsigned char pub[65];
  size_t n = 0;
  if (psa_generate_key(&a, &d->key) != PSA_SUCCESS ||
      psa_export_public_key(d->key, pub, sizeof pub, &n) != PSA_SUCCESS ||
      n != 65) {
    return -1;
  }
  static const unsigned char PREFIX[] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
      0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
  memcpy(d->spki, PREFIX, sizeof PREFIX);
  memcpy(d->spki + sizeof PREFIX, pub, 65);
  return 0;
}

/* client data as a browser writes it */
static size_t client_data(char *out, size_t cap, const char *type,
                          const char *challenge, const char *origin,
                          const char *extra) {
  return (size_t)snprintf(
      out, cap, "{\"type\":\"%s\",\"challenge\":\"%s\",\"origin\":\"%s\"%s}",
      type, challenge, origin, extra ? extra : "");
}

/* authenticator data: rpIdHash, flags, count, and on registration the
 * attested credential (d's id, d's key as a COSE key) */
static size_t auth_data(unsigned char *out, const char *rp_id, unsigned flags,
                        uint32_t count, const DEVICE *d) {
  size_t hl;
  psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)rp_id, strlen(rp_id),
                   out, 32, &hl);
  out[32] = (unsigned char)flags;
  out[33] = (unsigned char)(count >> 24);
  out[34] = (unsigned char)(count >> 16);
  out[35] = (unsigned char)(count >> 8);
  out[36] = (unsigned char)count;
  size_t n = 37;
  if (d) {
    memset(out + n, 0xaa, 16); /* the aaguid */
    n += 16;
    out[n++] = 0;
    out[n++] = sizeof d->id;
    memcpy(out + n, d->id, sizeof d->id);
    n += sizeof d->id;
    static const unsigned char HEAD[] = {0xa5, 0x01, 0x02, 0x03, 0x26,
                                         0x20, 0x01, 0x21, 0x58, 0x20};
    memcpy(out + n, HEAD, sizeof HEAD);
    n += sizeof HEAD;
    memcpy(out + n, d->spki + 27, 32);
    n += 32;
    out[n++] = 0x22;
    out[n++] = 0x58;
    out[n++] = 0x20;
    memcpy(out + n, d->spki + 59, 32);
    n += 32;
  }
  return n;
}

/* d's DER signature over authData || SHA-256(clientData) */
static size_t sign(const DEVICE *d, const unsigned char *ad, size_t ad_n,
                   const char *cd, size_t cd_n, unsigned char *der) {
  unsigned char msg[512], raw[64];
  size_t hl, sl = 0, dl = 0;
  memcpy(msg, ad, ad_n);
  psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)cd, cd_n, msg + ad_n,
                   32, &hl);
  if (psa_sign_message(d->key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, ad_n + 32,
                       raw, sizeof raw, &sl) != PSA_SUCCESS ||
      mbedtls_ecdsa_raw_to_der(256, raw, sl, der, 80, &dl) != 0) {
    return 0;
  }
  return dl;
}

/* --- the ceremonies --- */

static void test_register(const DEVICE *d, const DEVICE *other) {
  char err[200], cd[512];
  unsigned char ad[300];
  uint32_t count = 99;
  size_t cn =
      client_data(cd, sizeof cd, "webauthn.create", CHALLENGE, RP.origin, NULL);
  size_t an = auth_data(ad, RP.rp_id, 0x45, 0, d);
#define REG(cdp, cdn, adp, adn, key, id, idn)                                  \
  cserve_passkey_register(&RP, CHALLENGE, (const unsigned char *)(cdp), cdn,   \
                          adp, adn, key, 91, id, idn, &count, err, sizeof err)
  CSERVE_TEST_ASSERT(REG(cd, cn, ad, an, d->spki, d->id, sizeof d->id) == 0 &&
                         count == 0,
                     "register: taken, its count 0 (%s)", err);
  CSERVE_TEST_ASSERT(
      REG(cd, cn, ad, an, d->spki, other->id, sizeof other->id) != 0 &&
          strstr(err, "not the credential posted"),
      "register: another credential id posted: refused");
  CSERVE_TEST_ASSERT(REG(cd, cn, ad, an, other->spki, d->id, sizeof d->id) !=
                             0 &&
                         strstr(err, "not the one posted"),
                     "register: another key posted: refused");
  unsigned char longer[320];
  memcpy(longer, ad, an);
  longer[an] = 0xa0;
  CSERVE_TEST_ASSERT(
      REG(cd, cn, longer, an + 1, d->spki, d->id, sizeof d->id) != 0 &&
          strstr(err, "after the key"),
      "register: bytes after the key without ED: refused");
  size_t bare = auth_data(longer, RP.rp_id, 0x05, 0, NULL);
  CSERVE_TEST_ASSERT(REG(cd, cn, longer, bare, d->spki, d->id, sizeof d->id) !=
                         0,
                     "register: no attested credential (no AT): refused");
  unsigned char bad[91];
  memcpy(bad, d->spki, sizeof bad);
  bad[60] ^= 0x55;
  CSERVE_TEST_ASSERT(REG(cd, cn, ad, an, bad, d->id, sizeof d->id) != 0,
                     "register: a point not on the curve: refused");
  char get[512];
  size_t gn =
      client_data(get, sizeof get, "webauthn.get", CHALLENGE, RP.origin, NULL);
  CSERVE_TEST_ASSERT(REG(get, gn, ad, an, d->spki, d->id, sizeof d->id) != 0,
                     "register: client data of a login: refused");
#undef REG
}

static void test_assert(const DEVICE *d, const DEVICE *other) {
  char err[200], cd[512];
  unsigned char ad[64], sig[80];
  uint32_t count = 0;
  size_t cn =
      client_data(cd, sizeof cd, "webauthn.get", CHALLENGE, RP.origin, NULL);
  size_t an = auth_data(ad, RP.rp_id, 0x05, 7, NULL);
  size_t sn = sign(d, ad, an, cd, cn, sig);
#define ASSERT_WITH(cdp, cdn, adp, adn, s, slen, spki, stored)                 \
  cserve_passkey_assert(&RP, CHALLENGE, (const unsigned char *)(cdp), cdn,     \
                        adp, adn, s, slen, spki, 91, stored, &count, err,      \
                        sizeof err)
  CSERVE_TEST_ASSERT(
      sn > 0 && ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 6) == 0 &&
          count == 7,
      "assert: taken, the new count 7 (%s)", err);
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 7) != 0 &&
                         strstr(err, "count"),
                     "assert: a count that didn't rise: refused");
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, other->spki, 6) !=
                             0 &&
                         strstr(err, "doesn't verify"),
                     "assert: checked against another key: refused");
  char changed[512];
  memcpy(changed, cd, cn);
  changed[cn - 2] ^= 1; /* a byte of the origin: still well formed? no */
  size_t xn = client_data(changed, sizeof changed, "webauthn.get", CHALLENGE,
                          RP.origin, ",\"x\":1");
  CSERVE_TEST_ASSERT(ASSERT_WITH(changed, xn, ad, an, sig, sn, d->spki, 6) != 0,
                     "assert: client data other than what was signed: "
                     "refused");
  sig[sn - 1] ^= 1;
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 6) != 0,
                     "assert: a signature off by a bit: refused");
  /* an authenticator with no count: 0 and 0 is fine */
  an = auth_data(ad, RP.rp_id, 0x05, 0, NULL);
  sn = sign(d, ad, an, cd, cn, sig);
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 0) == 0,
                     "assert: both counts 0 (none kept): taken");
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 3) != 0,
                     "assert: 0 after 3: refused");
  an = auth_data(ad, RP.rp_id, 0x01, 8, NULL);
  sn = sign(d, ad, an, cd, cn, sig);
  CSERVE_TEST_ASSERT(ASSERT_WITH(cd, cn, ad, an, sig, sn, d->spki, 7) != 0 &&
                         strstr(err, "lack"),
                     "assert: present but not verified (no UV): refused");
#undef ASSERT_WITH
}

static void test_client_data(void) {
  char err[200], cd[512];
  static const struct {
    const char *type, *challenge, *origin, *extra, *why;
  } BAD[] = {
      {"webauthn.create", CHALLENGE, "https://chat.test", NULL, "type"},
      {"webauthn.get", "Q2hhbGxlbmdl", "https://chat.test", NULL, "challenge"},
      {"webauthn.get", CHALLENGE, "https://evil.test", NULL, "origin"},
      {"webauthn.get", CHALLENGE, "https://chat.test:8443", NULL, "origin"},
      {"webauthn.get", CHALLENGE, "http://chat.test", NULL, "origin"},
      {"webauthn.get", CHALLENGE, "https://chat.test", ",\"crossOrigin\":true",
       "cross-origin"},
      {"webauthn.get", CHALLENGE, "https://chat.test",
       ",\"crossOrigin\":\"false\"", "cross-origin"},
      {"webauthn.get", CHALLENGE, "https://chat.test", ",\"type\":\"x\"",
       "client data"},
  };
  for (size_t i = 0; i < sizeof BAD / sizeof *BAD; i++) {
    size_t n = client_data(cd, sizeof cd, BAD[i].type, BAD[i].challenge,
                           BAD[i].origin, BAD[i].extra);
    err[0] = '\0';
    CSERVE_TEST_ASSERT(cserve_passkey_client_data(
                           (const unsigned char *)cd, n, "webauthn.get",
                           CHALLENGE, RP.origin, err, sizeof err) != 0 &&
                           strstr(err, BAD[i].why),
                       "client data refused: %s (%s)", BAD[i].why, err);
  }
  size_t n = client_data(cd, sizeof cd, "webauthn.get", CHALLENGE, RP.origin,
                         ",\"crossOrigin\":false,\"topOrigin\":\"x\"");
  CSERVE_TEST_ASSERT(
      cserve_passkey_client_data((const unsigned char *)cd, n, "webauthn.get",
                                 CHALLENGE, RP.origin, err, sizeof err) == 0,
      "client data: crossOrigin false and fields it doesn't "
      "know taken");
  CSERVE_TEST_ASSERT(cserve_passkey_client_data(
                         (const unsigned char *)"{\0}", 3, "webauthn.get",
                         CHALLENGE, RP.origin, err, sizeof err) != 0,
                     "client data with a NUL: refused");
}

static void test_auth_data(void) {
  char err[200];
  unsigned char ad[64];
  uint32_t count;
  size_t n = auth_data(ad, "other.test", 0x05, 1, NULL);
  CSERVE_TEST_ASSERT(cserve_passkey_auth_data(ad, n, RP.rp_id, 0x05, &count,
                                              err, sizeof err) != 0 &&
                         strstr(err, "rpIdHash"),
                     "authenticator data for another rp: refused");
  CSERVE_TEST_ASSERT(cserve_passkey_auth_data(ad, 36, RP.rp_id, 0x05, &count,
                                              err, sizeof err) != 0,
                     "authenticator data of 36 bytes: refused");
  n = auth_data(ad, RP.rp_id, 0x05, 0x01020304, NULL);
  CSERVE_TEST_ASSERT(cserve_passkey_auth_data(ad, n, RP.rp_id, 0x05, &count,
                                              err, sizeof err) == 0 &&
                         count == 0x01020304,
                     "authenticator data: its count read big-endian");
}

/* --- the kit's other pieces --- */

static void test_b64url(void) {
  unsigned char out[16];
  static const struct {
    const char *in, *out;
  } OK[] = {{"", ""},
            {"Zg", "f"},
            {"Zm8", "fo"},
            {"Zm9v", "foo"},
            {"Zm9vYmFy", "foobar"}};
  for (size_t i = 0; i < sizeof OK / sizeof *OK; i++) {
    long n = cserve_b64url_decode(OK[i].in, out, sizeof out);
    CSERVE_TEST_ASSERT(n == (long)strlen(OK[i].out) &&
                           !memcmp(out, OK[i].out, (size_t)n),
                       "base64url \"%s\" read", OK[i].in);
  }
  static const char *const BAD[] = {"Zh",   "Zm9",  "Z",
                                    "Zg==", "Zg=",  "Z+8",
                                    "Z/8",  "Zg Z", "Zm9vYmFyYmF6YmF6YmF6YmF6"};
  for (size_t i = 0; i < sizeof BAD / sizeof *BAD; i++) {
    /* "Zm9": bits left over that aren't zero ("fo" is "Zm8"); the last
     * one is 18 bytes, past the 16 there's room for */
    CSERVE_TEST_ASSERT(cserve_b64url_decode(BAD[i], out, sizeof out) < 0,
                       "base64url \"%s\" refused", BAD[i]);
  }
}

static void test_cookie(void) {
  CSERVE_HTTPD_REPLY rep = {0};
  CSERVE_TEST_ASSERT(
      cserve_cookie_set(&rep, "__Host-s", "abc-_123", 3600,
                        CSERVE_SAMESITE_STRICT, 0) == 0 &&
          strstr(rep.headers, "Set-Cookie: __Host-s=abc-_123; Max-Age=3600; "
                              "Path=/; Secure; HttpOnly; SameSite=Strict\r\n"),
      "a cookie: Max-Age, Path=/, Secure, HttpOnly, SameSite (%s)",
      rep.headers);
  rep.headers[0] = '\0';
  CSERVE_TEST_ASSERT(
      cserve_cookie_clear(&rep, "__Host-s", CSERVE_SAMESITE_STRICT) == 0 &&
          strstr(rep.headers, "__Host-s=; Max-Age=0; "),
      "a cookie cleared: empty, Max-Age=0");
  rep.headers[0] = '\0';
  CSERVE_TEST_ASSERT(cserve_cookie_set(&rep, "lang", "de", -1,
                                       CSERVE_SAMESITE_LAX,
                                       CSERVE_COOKIE_SCRIPT) == 0 &&
                         strstr(rep.headers, "lang=de; Path=/; Secure; "
                                             "SameSite=Lax\r\n"),
                     "a session cookie a script reads: no Max-Age, no "
                     "HttpOnly");
  static const char *const VALUES[] = {"a b",  "a;b",       "a,b", "a\"b",
                                       "a\\b", "a\r\nX: y", "\x7f"};
  for (size_t i = 0; i < sizeof VALUES / sizeof *VALUES; i++) {
    CSERVE_TEST_ASSERT(cserve_cookie_set(&rep, "n", VALUES[i], 1,
                                         CSERVE_SAMESITE_STRICT, 0) != 0,
                       "a cookie value with a byte it can't hold: refused");
  }
  CSERVE_TEST_ASSERT(
      !cserve_cookie_name_ok("a=b") && !cserve_cookie_name_ok("") &&
          !cserve_cookie_name_ok("a b") && cserve_cookie_name_ok("__Host-x"),
      "a cookie name: a token or refused");
}

static void test_sse(void) {
  char out[256];
  long n = cserve_sse_event(out, sizeof out, 7, "message", "hi", 2);
  CSERVE_TEST_ASSERT(n > 0 &&
                         !strcmp(out, "id: 7\nevent: message\ndata: hi\n\n"),
                     "an event: id, event, data, the blank line");
  n = cserve_sse_event(out, sizeof out, -1, NULL, "a\nb\r\nc\rd",
                       strlen("a\nb\r\nc\rd"));
  CSERVE_TEST_ASSERT(
      n > 0 && !strcmp(out, "data: a\ndata: b\ndata: c\ndata: d\n\n"),
      "every line break in data a data line of its own (%s)", out);
  static const char EVIL[] = "x\n\nid: 9\nevent: evil";
  n = cserve_sse_event(out, sizeof out, -1, NULL, EVIL, strlen(EVIL));
  CSERVE_TEST_ASSERT(
      n > 0 && !strstr(out, "\nid: 9") && !strstr(out, "\nevent: evil"),
      "data that tries to start fields: they stay data (%s)", out);
  CSERVE_TEST_ASSERT(cserve_sse_event(out, sizeof out, 1, "a b", "x", 1) < 0 &&
                         cserve_sse_event(out, sizeof out, 1, NULL, "x\0y", 3) <
                             0 &&
                         cserve_sse_event(out, 8, 1, NULL, "xxxxxxxx", 8) < 0,
                     "a bad event name, a NUL, no room: refused");
  CSERVE_HTTPD_REQ r = {0};
  char head[] = "GET / HTTP/1.1\r\nLast-Event-ID: 42";
  char err[64];
  long long id = -1;
  cserve_httpd_parse(head, &r, err, sizeof err);
  CSERVE_TEST_ASSERT(cserve_sse_last_id(&r, &id) == 1 && id == 42,
                     "Last-Event-ID read");
  char head2[] = "GET / HTTP/1.1\r\nLast-Event-ID: 4x";
  cserve_httpd_parse(head2, &r, err, sizeof err);
  CSERVE_TEST_ASSERT(cserve_sse_last_id(&r, &id) == 0,
                     "a Last-Event-ID that isn't a number: none");
}

static void test_json_writer(void) {
  CSERVE_ARENA *a = cserve_arena_new();
  const char *q = cserve_json_string(a, "a\"b\\c\n\x01");
  CSERVE_TEST_ASSERT(!strcmp(q, "\"a\\\"b\\\\c\\u000a\\u0001\""),
                     "a JSON string: quotes, backslashes, control bytes (%s)",
                     q);
  cserve_arena_free(a);
}

int main(void) {
  psa_crypto_init();
  DEVICE d, other;
  if (device(&d, 1) != 0 || device(&other, 2) != 0) {
    CSERVE_TEST_ASSERT(0, "two software devices made");
    return cserve_test_summary();
  }
  CSERVE_TEST_ASSERT(cserve_passkey_spki_ok(d.spki, sizeof d.spki),
                     "a device's SPKI: a P-256 key");
  test_register(&d, &other);
  test_assert(&d, &other);
  test_client_data();
  test_auth_data();
  test_b64url();
  test_cookie();
  test_sse();
  test_json_writer();
  psa_destroy_key(d.key);
  psa_destroy_key(other.key);
  return cserve_test_summary();
}
