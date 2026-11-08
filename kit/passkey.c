/* a passkey checked (passkey.h) */
#include "passkey.h"

#include "json.h"
#include "tls.h"

#include <mbedtls/pk.h>
#include <psa/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* a P-256 key's SPKI is these 27 bytes, then 04 || x || y */
static const unsigned char SPKI_PREFIX[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};
#define SPKI_LEN (sizeof SPKI_PREFIX + 64)

/* the COSE key CTAP2 gives for ES256: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
 * in canonical order -- these 10 bytes, x, then 3 more, then y */
static const unsigned char COSE_HEAD[] = {0xa5, 0x01, 0x02, 0x03, 0x26,
                                          0x20, 0x01, 0x21, 0x58, 0x20};
static const unsigned char COSE_MID[] = {0x22, 0x58, 0x20};
#define COSE_LEN (sizeof COSE_HEAD + 32 + sizeof COSE_MID + 32)

/* 0 when a and b (n bytes) are the same, in time n alone */
static int differ(const unsigned char *a, const unsigned char *b, size_t n) {
  unsigned char d = 0;
  for (size_t i = 0; i < n; i++) {
    d |= a[i] ^ b[i];
  }
  return d != 0;
}

static int psa_up(char *err, size_t err_cap) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    snprintf(err, err_cap, "the crypto library didn't start");
    return -1;
  }
  return 0;
}

int cserve_passkey_spki_ok(const unsigned char *spki, size_t n) {
  if (n != SPKI_LEN || memcmp(spki, SPKI_PREFIX, sizeof SPKI_PREFIX) != 0) {
    return 0;
  }
  /* and the point on the curve: mbedtls reads it or doesn't */
  mbedtls_pk_context pk;
  /* a parsed key may sit in a PSA key slot: the crypto's lock (tls.h) */
  cserve_crypto_lock();
  mbedtls_pk_init(&pk);
  int ok = psa_crypto_init() == PSA_SUCCESS &&
           mbedtls_pk_parse_public_key(&pk, spki, n) == 0 &&
           mbedtls_pk_get_key_type(&pk) ==
               PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
  mbedtls_pk_free(&pk);
  cserve_crypto_unlock();
  return ok;
}

int cserve_passkey_client_data(const unsigned char *json, size_t n,
                               const char *type, const char *challenge,
                               const char *origin, char *err, size_t err_cap) {
  if (n == 0 || n > 4096 || memchr(json, '\0', n)) {
    snprintf(err, err_cap, "client data: empty, too long, or with a NUL");
    return -1;
  }
  char *text = malloc(n + 1);
  if (!text) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  memcpy(text, json, n);
  text[n] = '\0';
  char why[128];
  CSERVE_JSON *v = cserve_json_parse(text, why, sizeof why);
  free(text);
  const char *t = cserve_json_str(cserve_json_get(v, "type"));
  const char *c = cserve_json_str(cserve_json_get(v, "challenge"));
  const char *o = cserve_json_str(cserve_json_get(v, "origin"));
  const CSERVE_JSON *x = cserve_json_get(v, "crossOrigin");
  int rc = -1;
  if (!v || v->type != CSERVE_JSON_OBJECT) {
    snprintf(err, err_cap, "client data: %s", v ? "not an object" : why);
  } else if (!t || strcmp(t, type) != 0) {
    snprintf(err, err_cap, "client data: type is not %s", type);
  } else if (!c || strlen(c) != strlen(challenge) ||
             differ((const unsigned char *)c, (const unsigned char *)challenge,
                    strlen(c))) {
    snprintf(err, err_cap, "client data: not the challenge minted");
  } else if (!o || strcmp(o, origin) != 0) {
    snprintf(err, err_cap, "client data: origin is not %s", origin);
  } else if (x && (x->type != CSERVE_JSON_BOOL || x->boolean)) {
    snprintf(err, err_cap, "client data: cross-origin");
  } else {
    rc = 0;
  }
  cserve_json_free(v);
  return rc;
}

int cserve_passkey_auth_data(const unsigned char *ad, size_t n,
                             const char *rp_id, unsigned want, uint32_t *count,
                             char *err, size_t err_cap) {
  if (n < 37) {
    snprintf(err, err_cap, "authenticator data: %zu bytes, fewer than 37", n);
    return -1;
  }
  if (psa_up(err, err_cap) != 0) {
    return -1;
  }
  unsigned char hash[32];
  size_t hl = 0;
  if (psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)rp_id,
                       strlen(rp_id), hash, sizeof hash, &hl) != PSA_SUCCESS ||
      differ(ad, hash, 32)) {
    snprintf(err, err_cap, "authenticator data: not %s's rpIdHash", rp_id);
    return -1;
  }
  if ((ad[32] & want) != want) {
    snprintf(err, err_cap, "authenticator data: flags 0x%02x lack 0x%02x",
             ad[32], want);
    return -1;
  }
  *count = (uint32_t)ad[33] << 24 | (uint32_t)ad[34] << 16 |
           (uint32_t)ad[35] << 8 | ad[36];
  return 0;
}

int cserve_passkey_register(const CSERVE_PASSKEY_RP *rp, const char *challenge,
                            const unsigned char *client_data, size_t cd_n,
                            const unsigned char *auth_data, size_t ad_n,
                            const unsigned char *spki, size_t spki_n,
                            const unsigned char *cred_id, size_t id_n,
                            uint32_t *count, char *err, size_t err_cap) {
  if (cserve_passkey_client_data(client_data, cd_n, "webauthn.create",
                                 challenge, rp->origin, err, err_cap) != 0 ||
      cserve_passkey_auth_data(auth_data, ad_n, rp->rp_id,
                               CSERVE_PASSKEY_UP | CSERVE_PASSKEY_UV |
                                   CSERVE_PASSKEY_AT,
                               count, err, err_cap) != 0) {
    return -1;
  }
  if (!cserve_passkey_spki_ok(spki, spki_n)) {
    snprintf(err, err_cap, "the key: not a P-256 public key");
    return -1;
  }
  if (id_n == 0 || id_n > 1023) {
    snprintf(err, err_cap, "the credential id: %zu bytes", id_n);
    return -1;
  }
  /* attested credential data: aaguid (16), the id's length (2), the id,
   * the COSE key; then extensions only when ED says so */
  size_t at = 37 + 16;
  if (ad_n < at + 2) {
    snprintf(err, err_cap, "authenticator data: no attested credential");
    return -1;
  }
  size_t len = (size_t)auth_data[at] << 8 | auth_data[at + 1];
  at += 2;
  if (len != id_n || ad_n < at + len ||
      memcmp(auth_data + at, cred_id, id_n) != 0) {
    snprintf(err, err_cap, "authenticator data: not the credential posted");
    return -1;
  }
  at += len;
  unsigned char cose[COSE_LEN];
  const unsigned char *x = spki + sizeof SPKI_PREFIX, *y = x + 32;
  memcpy(cose, COSE_HEAD, sizeof COSE_HEAD);
  memcpy(cose + sizeof COSE_HEAD, x, 32);
  memcpy(cose + sizeof COSE_HEAD + 32, COSE_MID, sizeof COSE_MID);
  memcpy(cose + sizeof COSE_HEAD + 32 + sizeof COSE_MID, y, 32);
  if (ad_n < at + COSE_LEN || memcmp(auth_data + at, cose, COSE_LEN) != 0) {
    snprintf(err, err_cap, "authenticator data: its key is not the one posted");
    return -1;
  }
  at += COSE_LEN;
  if (at != ad_n && !(auth_data[32] & CSERVE_PASSKEY_ED)) {
    snprintf(err, err_cap, "authenticator data: bytes after the key");
    return -1;
  }
  return 0;
}

int cserve_passkey_assert(const CSERVE_PASSKEY_RP *rp, const char *challenge,
                          const unsigned char *client_data, size_t cd_n,
                          const unsigned char *auth_data, size_t ad_n,
                          const unsigned char *sig, size_t sig_n,
                          const unsigned char *spki, size_t spki_n,
                          uint32_t stored, uint32_t *count, char *err,
                          size_t err_cap) {
  if (cserve_passkey_client_data(client_data, cd_n, "webauthn.get", challenge,
                                 rp->origin, err, err_cap) != 0 ||
      cserve_passkey_auth_data(auth_data, ad_n, rp->rp_id,
                               CSERVE_PASSKEY_UP | CSERVE_PASSKEY_UV, count,
                               err, err_cap) != 0) {
    return -1;
  }
  if (!(*count > stored || (*count == 0 && stored == 0))) {
    snprintf(err, err_cap, "the count went from %u to %u: a copied key?",
             (unsigned)stored, (unsigned)*count);
    return -1;
  }
  if (sig_n == 0 || sig_n > 80) {
    snprintf(err, err_cap, "the signature: %zu bytes", sig_n);
    return -1;
  }
  /* what's signed: authData || SHA-256(clientDataJSON), hashed again */
  unsigned char cd_hash[32], hash[32];
  size_t hl = 0;
  unsigned char *msg = malloc(ad_n + 32);
  if (!msg) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  int ok = psa_hash_compute(PSA_ALG_SHA_256, client_data, cd_n, cd_hash,
                            sizeof cd_hash, &hl) == PSA_SUCCESS;
  memcpy(msg, auth_data, ad_n);
  memcpy(msg + ad_n, cd_hash, 32);
  ok = ok && psa_hash_compute(PSA_ALG_SHA_256, msg, ad_n + 32, hash,
                              sizeof hash, &hl) == PSA_SUCCESS;
  free(msg);
  ok = ok && cserve_passkey_spki_ok(spki, spki_n);
  mbedtls_pk_context pk;
  cserve_crypto_lock();
  mbedtls_pk_init(&pk);
  ok = ok && mbedtls_pk_parse_public_key(&pk, spki, spki_n) == 0 &&
       mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof hash, sig,
                         sig_n) == 0;
  mbedtls_pk_free(&pk);
  cserve_crypto_unlock();
  if (!ok) {
    snprintf(err, err_cap, "the signature doesn't verify");
    return -1;
  }
  return 0;
}
