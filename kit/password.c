#include "password.h"

#include <mbedtls/base64.h>
#include <mbedtls/constant_time.h>
#include <psa/crypto.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define PREFIX "$pbkdf2-sha256$"

/* 600 000 iterations of a salt and a hash drawn at random once and never
 * kept for anything: no password is known to give it */
static const char UNMATCHABLE[] =
    PREFIX "600000$jWXwxWGgMNM2dKmTGRBisg==$"
           "bDb5fZLtrtLDo8Z4gNiC4h5z6lYAShkliLFKEZ/JmOU=";

typedef struct {
  unsigned long iter;
  unsigned char salt[64], hash[64];
  size_t salt_len, hash_len;
} DIGEST;

/* the base64 in [s, e) into out (cap bytes): its length, or 0 -- also
 * for base64 that isn't written as encoding its bytes writes it (padding
 * left off, bits set past the end), which PasswordHash refuses too */
static size_t unbase64(const char *s, const char *e, unsigned char *out,
                       size_t cap) {
  size_t n = 0, m = 0, len = (size_t)(e - s);
  unsigned char again[96];
  if (e <= s || len >= sizeof again ||
      mbedtls_base64_decode(out, cap, &n, (const unsigned char *)s, len) != 0 ||
      mbedtls_base64_encode(again, sizeof again, &m, out, n) != 0 || m != len ||
      memcmp(again, s, len) != 0) {
    return 0;
  }
  return n;
}

static int parse(const char *digest, DIGEST *d) {
  if (!digest || strncmp(digest, PREFIX, sizeof PREFIX - 1) != 0) {
    return -1;
  }
  const char *p = digest + sizeof PREFIX - 1;
  if (*p < '1' || *p > '9') {
    return -1;
  }
  d->iter = 0;
  for (; *p >= '0' && *p <= '9'; p++) {
    d->iter = d->iter * 10 + (unsigned long)(*p - '0');
    if (d->iter > CSERVE_PASSWORD_ITER_MAX) {
      return -1;
    }
  }
  if (*p != '$' || d->iter < CSERVE_PASSWORD_ITER_MIN) {
    return -1;
  }
  const char *salt = p + 1, *sep = strchr(salt, '$');
  if (!sep || strchr(sep + 1, '$')) {
    return -1;
  }
  d->salt_len = unbase64(salt, sep, d->salt, sizeof d->salt);
  d->hash_len =
      unbase64(sep + 1, sep + 1 + strlen(sep + 1), d->hash, sizeof d->hash);
  return d->salt_len >= 16 && d->hash_len >= 32 ? 0 : -1;
}

static pthread_once_t g_psa = PTHREAD_ONCE_INIT;
static int g_psa_ok;

static void psa_up(void) { g_psa_ok = psa_crypto_init() == PSA_SUCCESS; }

/* PBKDF2 of password under d's cost and salt, compared with d's hash in
 * constant time. (PSA's verify_bytes would compare for us, but takes the
 * password only as a key, and an empty one can't be imported.) */
static int verify(const DIGEST *d, const char *password, size_t len) {
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  unsigned char out[sizeof d->hash];
  psa_status_t st =
      psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                          d->iter);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        d->salt, d->salt_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        (const unsigned char *)password, len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_output_bytes(&op, out, d->hash_len);
  }
  psa_key_derivation_abort(&op);
  int same =
      st == PSA_SUCCESS && mbedtls_ct_memcmp(out, d->hash, d->hash_len) == 0;
  memset(out, 0, sizeof out);
  return same;
}

int cserve_password_matches(const char *digest, const char *password,
                            size_t len) {
  DIGEST d, none;
  pthread_once(&g_psa, psa_up);
  if (!g_psa_ok || parse(UNMATCHABLE, &none) != 0) {
    return 0;
  }
  if (parse(digest, &d) != 0) {
    (void)verify(&none, password, len);
    return 0;
  }
  return verify(&d, password, len);
}

int cserve_password_valid(const char *digest) {
  DIGEST d;
  return parse(digest, &d) == 0;
}

const char *cserve_password_unmatchable(void) { return UNMATCHABLE; }
