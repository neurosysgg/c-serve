/* acme.h's client pieces: base64url against RFC 4648's vectors, a JSON
 * string's quoting, a key made, written and read back as the same JWK
 * (an RSA one refused), a JWS whose protected header says what RFC 8555
 * wants and whose signature verifies over exactly what it signs, a CSR
 * that parses back with its name, and the readers of the server's
 * objects, each refusing what RFC 8555 doesn't allow. The whole exchange
 * is held to Pebble by tools/acme.sh. */
#define _GNU_SOURCE

#include "acme.h"
#include "json.h"

#include "test.h"

#include <mbedtls/x509_csr.h>
#include <psa/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* base64url (no padding) back to bytes: their count, or -1 */
static long unb64url(const char *s, unsigned char *out, size_t cap) {
  unsigned acc = 0;
  int bits = 0;
  size_t n = 0;
  for (; *s; s++) {
    const char *A =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char *p = strchr(A, *s);
    if (!p) {
      return -1;
    }
    acc = acc << 6 | (unsigned)(p - A);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n == cap) {
        return -1;
      }
      out[n++] = (unsigned char)(acc >> bits);
    }
  }
  return (long)n;
}

static void test_b64url(void) {
  static const char *const T[][2] = {{"", ""},
                                     {"f", "Zg"},
                                     {"fo", "Zm8"},
                                     {"foo", "Zm9v"},
                                     {"foob", "Zm9vYg"},
                                     {"fooba", "Zm9vYmE"},
                                     {"foobar", "Zm9vYmFy"}};
  char out[32];
  for (size_t i = 0; i < sizeof T / sizeof *T; i++) {
    long n = cserve_b64url((const unsigned char *)T[i][0], strlen(T[i][0]), out,
                           sizeof out);
    CSERVE_TEST_ASSERT(n == (long)strlen(T[i][1]) && !strcmp(out, T[i][1]),
                       "base64url \"%s\": %s", T[i][0], T[i][1]);
  }
  static const unsigned char URL[] = {0xfb, 0xff};
  CSERVE_TEST_ASSERT(cserve_b64url(URL, 2, out, sizeof out) == 3 &&
                         !strcmp(out, "-_8"),
                     "base64url: '-' and '_' for 62 and 63, no padding");
  CSERVE_TEST_ASSERT(
      cserve_b64url((const unsigned char *)"foobar", 6, out, 8) == -1 &&
          cserve_b64url((const unsigned char *)"foobar", 6, out, 9) == 8,
      "base64url: refused without room for it and its NUL");
}

static void test_quote(void) {
  char out[64];
  CSERVE_TEST_ASSERT(cserve_json_quote("a\"b\\c", out, sizeof out) == 9 &&
                         !strcmp(out, "\"a\\\"b\\\\c\""),
                     "quote: a quote and a backslash escaped");
  CSERVE_TEST_ASSERT(cserve_json_quote("\x01\n", out, sizeof out) > 0 &&
                         !strcmp(out, "\"\\u0001\\u000a\""),
                     "quote: control bytes as \\u00XX");
  CSERVE_TEST_ASSERT(cserve_json_quote("abc", out, 5) == -1 &&
                         cserve_json_quote("abc", out, 6) == 5,
                     "quote: refused without room");
}

static void test_keys(CSERVE_ACME_KEY *k) {
  char err[200];
  CSERVE_TEST_ASSERT(cserve_acme_key_new(k, err, sizeof err) == 0,
                     "a key made (%s)", err);
  CSERVE_JSON *jwk = cserve_json_parse(k->jwk, err, sizeof err);
  const char *x = cserve_json_str(cserve_json_get(jwk, "x"));
  unsigned char raw[40];
  CSERVE_TEST_ASSERT(
      jwk && jwk->count == 4 && !strcmp(jwk->keys[0], "crv") &&
          !strcmp(jwk->keys[1], "kty") && !strcmp(jwk->keys[2], "x") &&
          !strcmp(jwk->keys[3], "y") && x &&
          unb64url(x, raw, sizeof raw) == 32 &&
          !strcmp(cserve_json_str(cserve_json_get(jwk, "crv")), "P-256"),
      "its JWK: crv, kty, x, y in RFC 7638's order, 32-byte coordinates");
  cserve_json_free(jwk);
  unsigned char hash[32];
  size_t hl;
  char want[48];
  psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)k->jwk,
                   strlen(k->jwk), hash, sizeof hash, &hl);
  cserve_b64url(hash, hl, want, sizeof want);
  CSERVE_TEST_ASSERT(!strcmp(k->thumbprint, want) && strlen(want) == 43,
                     "its thumbprint: base64url of the JWK's SHA-256");
  char path[] = "/tmp/cserve-acme-key-XXXXXX";
  int fd = mkstemp(path);
  if (fd >= 0) {
    (void)!write(fd, k->pem, strlen(k->pem));
    close(fd);
  }
  CSERVE_ACME_KEY again;
  int rc = cserve_acme_key_load(&again, path, err, sizeof err);
  CSERVE_TEST_ASSERT(rc == 0 && !strcmp(again.jwk, k->jwk),
                     "written and read back: the same key (%s)", err);
  cserve_acme_key_free(&again);
  unlink(path);
  err[0] = '\0';
  CSERVE_TEST_ASSERT(cserve_acme_key_load(&again,
                                          "tests/data/names/rsa/a.test/key.pem",
                                          err, sizeof err) != 0 &&
                         strstr(err, "not a P-256 key"),
                     "an RSA key refused (%s)", err);
  CSERVE_TEST_ASSERT(
      cserve_acme_key_load(&again, "/nonexistent", err, sizeof err) != 0,
      "no key file: refused");
}

/* the JWS's protected header, decoded and parsed, or NULL */
static CSERVE_JSON *header_of(const CSERVE_JSON *jws) {
  const char *p = cserve_json_str(cserve_json_get(jws, "protected"));
  unsigned char raw[2048];
  long n = p ? unb64url(p, raw, sizeof raw - 1) : -1;
  if (n < 0) {
    return NULL;
  }
  raw[n] = '\0';
  char err[100];
  return cserve_json_parse((const char *)raw, err, sizeof err);
}

static void test_jws(const CSERVE_ACME_KEY *k) {
  char err[200];
  char *s = cserve_acme_jws(k, NULL, "n0nce-_", "https://acme.test/new-acct",
                            "{\"termsOfServiceAgreed\":true}", err, sizeof err);
  CSERVE_JSON *jws = s ? cserve_json_parse(s, err, sizeof err) : NULL;
  CSERVE_JSON *h = header_of(jws);
  CSERVE_TEST_ASSERT(
      jws && jws->count == 3 && h &&
          !strcmp(cserve_json_str(cserve_json_get(h, "alg")), "ES256") &&
          cserve_json_get(h, "jwk") && !cserve_json_get(h, "kid") &&
          !strcmp(cserve_json_str(cserve_json_get(h, "nonce")), "n0nce-_") &&
          !strcmp(cserve_json_str(cserve_json_get(h, "url")),
                  "https://acme.test/new-acct"),
      "a JWS with no kid: alg, jwk, nonce, url");
  const char *p64 = cserve_json_str(cserve_json_get(jws, "protected"));
  const char *l64 = cserve_json_str(cserve_json_get(jws, "payload"));
  const char *s64 = cserve_json_str(cserve_json_get(jws, "signature"));
  unsigned char sig[80], payload[80];
  long sn = s64 ? unb64url(s64, sig, sizeof sig) : -1;
  long pn = l64 ? unb64url(l64, payload, sizeof payload - 1) : -1;
  char input[2048] = "";
  if (p64 && l64) {
    snprintf(input, sizeof input, "%s.%s", p64, l64);
  }
  CSERVE_TEST_ASSERT(
      sn == 64 && pn == 29 &&
          !memcmp(payload, "{\"termsOfServiceAgreed\":true}", 29) &&
          psa_verify_message(k->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             (const unsigned char *)input, strlen(input), sig,
                             64) == PSA_SUCCESS,
      "its signature: 64 bytes of r||s, verifying over protected.payload");
  input[strlen(input) - 1] ^= 1;
  CSERVE_TEST_ASSERT(psa_verify_message(k->key_id,
                                        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                        (const unsigned char *)input,
                                        strlen(input), sig, 64) != PSA_SUCCESS,
                     "and not over anything else");
  cserve_json_free(h);
  cserve_json_free(jws);
  free(s);

  s = cserve_acme_jws(k, "https://acme.test/acct/1", "n", "https://acme.test/o",
                      "", err, sizeof err);
  jws = s ? cserve_json_parse(s, err, sizeof err) : NULL;
  h = header_of(jws);
  CSERVE_TEST_ASSERT(
      h && !cserve_json_get(h, "jwk") &&
          !strcmp(cserve_json_str(cserve_json_get(h, "kid")),
                  "https://acme.test/acct/1") &&
          !strcmp(cserve_json_str(cserve_json_get(jws, "payload")), ""),
      "a POST-as-GET with a kid: kid, no jwk, an empty payload");
  cserve_json_free(h);
  cserve_json_free(jws);
  free(s);
  s = cserve_acme_jws(k, NULL, "n\"},\"alg\":\"none", "https://x/", "", err,
                      sizeof err);
  jws = s ? cserve_json_parse(s, err, sizeof err) : NULL;
  h = header_of(jws);
  CSERVE_TEST_ASSERT(
      h && h->count == 4 &&
          !strcmp(cserve_json_str(cserve_json_get(h, "alg")), "ES256"),
      "a nonce that tries to close the header: quoted, the "
      "header still four members");
  cserve_json_free(h);
  cserve_json_free(jws);
  free(s);
}

static void test_csr(const CSERVE_ACME_KEY *k) {
  char err[200], b64[1500];
  int rc = cserve_acme_csr(k, "a.test", b64, sizeof b64, err, sizeof err);
  unsigned char der[1200];
  long n = rc == 0 ? unb64url(b64, der, sizeof der) : -1;
  mbedtls_x509_csr csr;
  mbedtls_x509_csr_init(&csr);
  char subject[128] = "";
  int parsed = n > 0 && mbedtls_x509_csr_parse_der(&csr, der, (size_t)n) == 0;
  if (parsed) {
    mbedtls_x509_dn_gets(subject, sizeof subject, &csr.subject);
  }
  int san = 0;
  for (const mbedtls_x509_sequence *s = &csr.subject_alt_names; parsed && s;
       s = s->next) {
    san |= s->buf.len == 6 && !memcmp(s->buf.p, "a.test", 6);
  }
  CSERVE_TEST_ASSERT(parsed && !strcmp(subject, "CN=a.test") && san,
                     "a CSR: parses back, CN and subjectAltName a.test (%s)",
                     subject);
  mbedtls_x509_csr_free(&csr);
  CSERVE_TEST_ASSERT(
      cserve_acme_csr(k, "A.test", b64, sizeof b64, err, sizeof err) != 0 &&
          cserve_acme_csr(k, "a.test,CN=x", b64, sizeof b64, err, sizeof err) !=
              0,
      "a CSR for no lowercase DNS name: refused");
}

static void test_readers(void) {
  char err[200];
  CSERVE_ACME_DIRECTORY d;
  CSERVE_TEST_ASSERT(
      cserve_acme_directory("{\"newNonce\":\"https://a/n\",\"newAccount\":"
                            "\"https://a/a\",\"newOrder\":\"https://a/o\","
                            "\"meta\":{}}",
                            &d, err, sizeof err) == 0 &&
          !strcmp(d.new_order, "https://a/o"),
      "the directory: read");
  CSERVE_TEST_ASSERT(
      cserve_acme_directory("{\"newNonce\":\"http://a/n\",\"newAccount\":"
                            "\"https://a/a\",\"newOrder\":\"https://a/o\"}",
                            &d, err, sizeof err) != 0 &&
          cserve_acme_directory("{\"newNonce\":\"https://a/ n\",\"newAccount\":"
                                "\"https://a/a\",\"newOrder\":\"https://a/o\"}",
                                &d, err, sizeof err) != 0 &&
          cserve_acme_directory("[1]", &d, err, sizeof err) != 0 &&
          cserve_acme_directory("{", &d, err, sizeof err) != 0,
      "the directory: http://, a space, no object, no JSON: refused");
  CSERVE_ACME_ORDER o;
  CSERVE_TEST_ASSERT(
      cserve_acme_order("{\"status\":\"valid\",\"finalize\":\"https://a/f\","
                        "\"certificate\":\"https://a/c\",\"authorizations\":"
                        "[\"https://a/z1\",\"https://a/z2\"]}",
                        &o, err, sizeof err) == 0 &&
          !strcmp(o.status, "valid") && o.nauthz == 2 &&
          !strcmp(o.authz[1], "https://a/z2") &&
          !strcmp(o.certificate, "https://a/c"),
      "an order: read");
  CSERVE_TEST_ASSERT(
      cserve_acme_order("{\"status\":\"pending\",\"finalize\":\"https://a/f\","
                        "\"authorizations\":[]}",
                        &o, err, sizeof err) != 0 &&
          cserve_acme_order(
              "{\"status\":\"pending\",\"finalize\":\"https://a/f\","
              "\"authorizations\":[\"https://1\",\"https://2\",\"https://3\","
              "\"https://4\",\"https://5\",\"https://6\",\"https://7\","
              "\"https://8\",\"https://9\"]}",
              &o, err, sizeof err) != 0 &&
          cserve_acme_order("{\"status\":7,\"finalize\":\"https://a/f\","
                            "\"authorizations\":[\"https://a\"]}",
                            &o, err, sizeof err) != 0 &&
          cserve_acme_order("{\"status\":\"ready\",\"finalize\":\"https://a/f"
                            "\",\"certificate\":\"ftp://x\",\"authorizations"
                            "\":[\"https://a\"]}",
                            &o, err, sizeof err) != 0,
      "an order: no authorizations, nine, a status no string, a "
      "certificate no https URL: refused");
  CSERVE_ACME_AUTHZ a;
  const char *az =
      "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":"
      "\"a.test\"},\"challenges\":[{\"type\":\"dns-01\",\"url\":"
      "\"https://a/c1\",\"token\":\"t1\",\"status\":\"pending\"},{\"type\":"
      "\"http-01\",\"url\":\"https://a/c2\",\"token\":\"tok_EN-2\","
      "\"status\":\"pending\"}]}";
  CSERVE_TEST_ASSERT(cserve_acme_authz(az, &a, err, sizeof err) == 0 &&
                         !strcmp(a.name, "a.test") &&
                         !strcmp(a.url, "https://a/c2") &&
                         !strcmp(a.token, "tok_EN-2"),
                     "an authorization: its http-01 challenge picked");
  CSERVE_TEST_ASSERT(
      cserve_acme_authz(
          "{\"status\":\"pending\",\"identifier\":{\"value\":\"a.test\"},"
          "\"challenges\":[{\"type\":\"dns-01\",\"url\":\"https://a/c1\","
          "\"token\":\"t1\",\"status\":\"pending\"}]}",
          &a, err, sizeof err) != 0 &&
          strstr(err, "no http-01"),
      "an authorization with no http-01: refused (%s)", err);
  CSERVE_TEST_ASSERT(
      cserve_acme_authz(
          "{\"status\":\"pending\",\"identifier\":{\"value\":\"a.test\"},"
          "\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://a/c\","
          "\"token\":\"../../etc/passwd\",\"status\":\"pending\"}]}",
          &a, err, sizeof err) != 0,
      "an authorization whose token isn't base64url: refused");
  CSERVE_ACME_PROBLEM p;
  cserve_acme_problem("{\"type\":\"urn:ietf:params:acme:error:badNonce\","
                      "\"detail\":\"stale\"}",
                      &p);
  CSERVE_TEST_ASSERT(!strcmp(p.type, "urn:ietf:params:acme:error:badNonce") &&
                         !strcmp(p.detail, "stale"),
                     "a problem: its type and detail");
  cserve_acme_problem("<html>", &p);
  CSERVE_TEST_ASSERT(!p.type[0] && !p.detail[0], "no problem document: \"\"");
}

int main(void) {
  test_b64url();
  test_quote();
  CSERVE_ACME_KEY k;
  test_keys(&k);
  test_jws(&k);
  test_csr(&k);
  cserve_acme_key_free(&k);
  test_readers();
  return cserve_test_summary();
}
