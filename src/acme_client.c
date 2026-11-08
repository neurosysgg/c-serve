/* ACME's client pieces (acme.h): base64url, a JSON string's quoting, a
 * P-256 key in PSA with its JWK and thumbprint, the JWS, the CSR, and the
 * server's objects read through kit/json. cserve-acme is one thread and
 * shares no process with a server, so these call mbedtls without tls.c's
 * lock. */
#include "acme.h"

#include "json.h"
#include "tls.h"

#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <psa/crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long cserve_b64url(const unsigned char *in, size_t n, char *out, size_t cap) {
  static const char A[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t need = n / 3 * 4 + (n % 3 ? n % 3 + 1 : 0);
  if (need + 1 > cap) {
    return -1;
  }
  size_t o = 0;
  for (size_t i = 0; i < n; i += 3) {
    unsigned v = (unsigned)in[i] << 16;
    if (i + 1 < n) {
      v |= (unsigned)in[i + 1] << 8;
    }
    if (i + 2 < n) {
      v |= in[i + 2];
    }
    out[o++] = A[v >> 18 & 63];
    out[o++] = A[v >> 12 & 63];
    if (i + 1 < n) {
      out[o++] = A[v >> 6 & 63];
    }
    if (i + 2 < n) {
      out[o++] = A[v & 63];
    }
  }
  out[o] = '\0';
  return (long)o;
}

/* --- the key --- */

static int psa_up(char *err, size_t err_cap) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    snprintf(err, err_cap, "the crypto library didn't start");
    return -1;
  }
  return 0;
}

static void attributes(psa_key_attributes_t *a) {
  psa_set_key_type(a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(a, 256);
  psa_set_key_usage_flags(
      a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
             PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
  psa_set_key_algorithm(a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
}

/* k->key_id set: its JWK, thumbprint and PEM filled in. 0, or -1 (the
 * key destroyed) */
static int describe(CSERVE_ACME_KEY *k, char *err, size_t err_cap) {
  unsigned char pub[65];
  size_t n = 0;
  char x[48], y[48];
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ok =
      psa_export_public_key(k->key_id, pub, sizeof pub, &n) == PSA_SUCCESS &&
      n == 65 && pub[0] == 0x04 &&
      cserve_b64url(pub + 1, 32, x, sizeof x) > 0 &&
      cserve_b64url(pub + 33, 32, y, sizeof y) > 0;
  ok = ok && snprintf(k->jwk, sizeof k->jwk,
                      "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":"
                      "\"%s\"}",
                      x, y) < (int)sizeof k->jwk;
  unsigned char hash[32];
  size_t hl = 0;
  ok =
      ok &&
      psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)k->jwk,
                       strlen(k->jwk), hash, sizeof hash, &hl) == PSA_SUCCESS &&
      cserve_b64url(hash, hl, k->thumbprint, sizeof k->thumbprint) > 0;
  ok = ok && mbedtls_pk_copy_from_psa(k->key_id, &pk) == 0 &&
       mbedtls_pk_write_key_pem(&pk, (unsigned char *)k->pem, sizeof k->pem) ==
           0;
  mbedtls_pk_free(&pk);
  if (!ok) {
    snprintf(err, err_cap, "the key's public half didn't come out");
    cserve_acme_key_free(k);
    return -1;
  }
  return 0;
}

int cserve_acme_key_new(CSERVE_ACME_KEY *k, char *err, size_t err_cap) {
  memset(k, 0, sizeof *k);
  if (psa_up(err, err_cap) != 0) {
    return -1;
  }
  psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
  attributes(&a);
  mbedtls_svc_key_id_t id;
  if (psa_generate_key(&a, &id) != PSA_SUCCESS) {
    snprintf(err, err_cap, "no key was made");
    return -1;
  }
  k->key_id = id;
  return describe(k, err, err_cap);
}

int cserve_acme_key_load(CSERVE_ACME_KEY *k, const char *path, char *err,
                         size_t err_cap) {
  memset(k, 0, sizeof *k);
  if (psa_up(err, err_cap) != 0) {
    return -1;
  }
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_keyfile(&pk, path, NULL);
  if (ret != 0) {
    snprintf(err, err_cap, "%s: not a key mbedtls reads (-0x%04x)", path,
             (unsigned)-ret);
    mbedtls_pk_free(&pk);
    return -1;
  }
  if (mbedtls_pk_get_bitlen(&pk) != 256 ||
      mbedtls_pk_get_key_type(&pk) !=
          PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
    snprintf(err, err_cap, "%s: not a P-256 key", path);
    mbedtls_pk_free(&pk);
    return -1;
  }
  psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
  attributes(&a);
  mbedtls_svc_key_id_t id;
  ret = mbedtls_pk_import_into_psa(&pk, &a, &id);
  mbedtls_pk_free(&pk);
  if (ret != 0) {
    snprintf(err, err_cap, "%s: the key didn't go into PSA", path);
    return -1;
  }
  k->key_id = id;
  return describe(k, err, err_cap);
}

void cserve_acme_key_free(CSERVE_ACME_KEY *k) {
  if (k->key_id) {
    psa_destroy_key(k->key_id);
  }
  /* the PEM is the private key: gone from memory too */
  memset(k, 0, sizeof *k);
}

/* --- the JWS --- */

char *cserve_acme_jws(const CSERVE_ACME_KEY *k, const char *kid,
                      const char *nonce, const char *url, const char *payload,
                      char *err, size_t err_cap) {
  char qn[256], qu[CSERVE_ACME_URL + 16], qk[CSERVE_ACME_URL + 16];
  if (cserve_json_quote(nonce, qn, sizeof qn) < 0 ||
      cserve_json_quote(url, qu, sizeof qu) < 0 ||
      (kid && cserve_json_quote(kid, qk, sizeof qk) < 0)) {
    snprintf(err, err_cap, "JWS: a nonce, URL or kid too long");
    return NULL;
  }
  char prot[1200];
  int pn = snprintf(prot, sizeof prot,
                    "{\"alg\":\"ES256\",\"%s\":%s,\"nonce\":%s,\"url\":%s}",
                    kid ? "kid" : "jwk", kid ? qk : k->jwk, qn, qu);
  size_t plen = strlen(payload);
  size_t p64cap = sizeof prot / 3 * 4 + 8, l64cap = plen / 3 * 4 + 8;
  char *p64 = malloc(p64cap), *l64 = malloc(l64cap);
  size_t incap = p64cap + l64cap + 2;
  char *input = malloc(incap);
  char *out = NULL;
  long a = -1, b = -1;
  if (pn > 0 && (size_t)pn < sizeof prot && p64 && l64 && input) {
    a = cserve_b64url((const unsigned char *)prot, (size_t)pn, p64, p64cap);
    b = cserve_b64url((const unsigned char *)payload, plen, l64, l64cap);
  }
  unsigned char sig[64];
  size_t sl = 0;
  char s64[96];
  if (a >= 0 && b >= 0) {
    int in = snprintf(input, incap, "%s.%s", p64, l64);
    if (psa_sign_message(k->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         (const unsigned char *)input, (size_t)in, sig,
                         sizeof sig, &sl) == PSA_SUCCESS &&
        sl == sizeof sig && cserve_b64url(sig, sl, s64, sizeof s64) > 0) {
      size_t cap = (size_t)a + (size_t)b + 160;
      out = malloc(cap);
      if (out) {
        snprintf(out, cap,
                 "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":"
                 "\"%s\"}",
                 p64, l64, s64);
      }
    }
  }
  if (!out) {
    snprintf(err, err_cap, "JWS: not signed");
  }
  free(p64);
  free(l64);
  free(input);
  return out;
}

/* --- the CSR --- */

int cserve_acme_csr(const CSERVE_ACME_KEY *k, const char *name, char *out,
                    size_t cap, char *err, size_t err_cap) {
  if (!cserve_tls_name_ok(name, strlen(name))) {
    snprintf(err, err_cap, "CSR: %s is not a lowercase DNS name", name);
    return -1;
  }
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  mbedtls_x509write_csr csr;
  mbedtls_x509write_csr_init(&csr);
  char subject[300];
  snprintf(subject, sizeof subject, "CN=%s", name);
  mbedtls_x509_san_list san = {0};
  san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
  san.node.san.unstructured_name.p = (unsigned char *)(uintptr_t)name;
  san.node.san.unstructured_name.len = strlen(name);
  unsigned char der[1024];
  int n = -1;
  if (mbedtls_pk_copy_from_psa(k->key_id, &pk) == 0 &&
      mbedtls_x509write_csr_set_subject_name(&csr, subject) == 0 &&
      mbedtls_x509write_csr_set_subject_alternative_name(&csr, &san) == 0) {
    mbedtls_x509write_csr_set_key(&csr, &pk);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    n = mbedtls_x509write_csr_der(&csr, der, sizeof der);
  }
  mbedtls_x509write_csr_free(&csr);
  mbedtls_pk_free(&pk);
  /* the DER is written at the buffer's end */
  if (n <= 0 || cserve_b64url(der + sizeof der - n, (size_t)n, out, cap) < 0) {
    snprintf(err, err_cap, "CSR: not made for %s", name);
    return -1;
  }
  return 0;
}

/* --- the server's objects --- */

/* v's string into out: 0, or -1 (none, or too long) */
static int copy(const CSERVE_JSON *v, char *out, size_t cap) {
  const char *s = cserve_json_str(v);
  if (!s || strlen(s) >= cap) {
    return -1;
  }
  memcpy(out, s, strlen(s) + 1);
  return 0;
}

/* v's string as a URL into out: https://, printable, no space */
static int copy_url(const CSERVE_JSON *v, char *out) {
  if (copy(v, out, CSERVE_ACME_URL) != 0 || strncmp(out, "https://", 8) != 0 ||
      !out[8]) {
    return -1;
  }
  for (const char *p = out; *p; p++) {
    if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f) {
      return -1;
    }
  }
  return 0;
}

/* json as an object, or NULL with why in err */
static CSERVE_JSON *object(const char *json, const char *what, char *err,
                           size_t err_cap) {
  char why[128];
  CSERVE_JSON *v = cserve_json_parse(json, why, sizeof why);
  if (!v || v->type != CSERVE_JSON_OBJECT) {
    snprintf(err, err_cap, "the %s: %s", what, v ? "not an object" : why);
    cserve_json_free(v);
    return NULL;
  }
  return v;
}

int cserve_acme_directory(const char *json, CSERVE_ACME_DIRECTORY *d, char *err,
                          size_t err_cap) {
  memset(d, 0, sizeof *d);
  CSERVE_JSON *v = object(json, "directory", err, err_cap);
  if (!v) {
    return -1;
  }
  int ok = copy_url(cserve_json_get(v, "newNonce"), d->new_nonce) == 0 &&
           copy_url(cserve_json_get(v, "newAccount"), d->new_account) == 0 &&
           copy_url(cserve_json_get(v, "newOrder"), d->new_order) == 0;
  cserve_json_free(v);
  if (!ok) {
    snprintf(err, err_cap,
             "the directory: newNonce, newAccount or newOrder is no https URL");
    return -1;
  }
  return 0;
}

int cserve_acme_order(const char *json, CSERVE_ACME_ORDER *o, char *err,
                      size_t err_cap) {
  memset(o, 0, sizeof *o);
  CSERVE_JSON *v = object(json, "order", err, err_cap);
  if (!v) {
    return -1;
  }
  const CSERVE_JSON *az = cserve_json_get(v, "authorizations");
  const CSERVE_JSON *cert = cserve_json_get(v, "certificate");
  int ok =
      copy(cserve_json_get(v, "status"), o->status, sizeof o->status) == 0 &&
      copy_url(cserve_json_get(v, "finalize"), o->finalize) == 0 &&
      (!cert || copy_url(cert, o->certificate) == 0) && az &&
      az->type == CSERVE_JSON_ARRAY && az->count >= 1 &&
      az->count <= CSERVE_ACME_AUTHZ_MAX;
  for (int i = 0; ok && i < az->count; i++) {
    ok = copy_url(&az->items[i], o->authz[i]) == 0;
    o->nauthz = i + 1;
  }
  cserve_json_free(v);
  if (!ok) {
    snprintf(err, err_cap,
             "the order: its status, finalize, certificate or "
             "authorizations aren't what RFC 8555 says");
    return -1;
  }
  return 0;
}

int cserve_acme_authz(const char *json, CSERVE_ACME_AUTHZ *a, char *err,
                      size_t err_cap) {
  memset(a, 0, sizeof *a);
  CSERVE_JSON *v = object(json, "authorization", err, err_cap);
  if (!v) {
    return -1;
  }
  const CSERVE_JSON *id = cserve_json_get(v, "identifier");
  const CSERVE_JSON *chs = cserve_json_get(v, "challenges");
  int ok =
      copy(cserve_json_get(v, "status"), a->status, sizeof a->status) == 0 &&
      copy(cserve_json_get(id, "value"), a->name, sizeof a->name) == 0 && chs &&
      chs->type == CSERVE_JSON_ARRAY;
  int found = 0;
  for (int i = 0; ok && !found && i < chs->count; i++) {
    const CSERVE_JSON *c = &chs->items[i];
    const char *type = cserve_json_str(cserve_json_get(c, "type"));
    if (!type || strcmp(type, "http-01") != 0) {
      continue;
    }
    found = 1;
    ok = copy_url(cserve_json_get(c, "url"), a->url) == 0 &&
         copy(cserve_json_get(c, "token"), a->token, sizeof a->token) == 0 &&
         cserve_acme_token_ok(a->token, strlen(a->token)) &&
         copy(cserve_json_get(c, "status"), a->challenge,
              sizeof a->challenge) == 0;
  }
  cserve_json_free(v);
  if (!ok || !found) {
    snprintf(err, err_cap,
             !ok ? "the authorization: its status, identifier or http-01 "
                   "challenge aren't what RFC 8555 says"
                 : "the authorization offers no http-01 challenge");
    return -1;
  }
  return 0;
}

void cserve_acme_problem(const char *json, CSERVE_ACME_PROBLEM *p) {
  memset(p, 0, sizeof *p);
  char why[64];
  CSERVE_JSON *v = cserve_json_parse(json, why, sizeof why);
  if (copy(cserve_json_get(v, "type"), p->type, sizeof p->type) != 0) {
    p->type[0] = '\0';
  }
  if (copy(cserve_json_get(v, "detail"), p->detail, sizeof p->detail) != 0) {
    p->detail[0] = '\0';
  }
  cserve_json_free(v);
}
