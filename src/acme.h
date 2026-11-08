#ifndef CSERVE_ACME_H
#define CSERVE_ACME_H

#include <stddef.h>

/* ACME (RFC 8555), the parts both sides need: the host serves an HTTP-01
 * challenge's answer (acme.c), cserve-acme (host/acme.c) gets the
 * certificates with the rest (acme_client.c): JWS signed ES256 with a
 * P-256 key, the CSR, and the server's objects read into structs. */

/* 1 when token (n bytes) can be an HTTP-01 token: base64url's alphabet
 * only (RFC 8555 8.3), 1 to 128 bytes -- so it's a file name with no
 * '/' and no dot, and nothing else of a request reaches the disk;
 * else 0 */
int cserve_acme_token_ok(const char *token, size_t n);

/* --- the client's pieces (acme_client.c) --- */

/* in (n bytes) as base64url without padding into out (NUL-terminated):
 * its length, or -1 when it doesn't fit in cap */
long cserve_b64url(const unsigned char *in, size_t n, char *out, size_t cap);

/* s as a JSON string, quotes and all, into out (NUL-terminated): its
 * length, or -1 when it doesn't fit; control bytes as \u00XX */
long cserve_json_quote(const char *s, char *out, size_t cap);

/* A P-256 key, held by PSA for signing, with its public half as a JWK
 * (RFC 7517: crv, kty, x, y -- in that order, which is RFC 7638's for the
 * thumbprint) and that thumbprint (base64url of its SHA-256). */
typedef struct {
  unsigned key_id; /* PSA's (0: none) */
  char jwk[160];
  char thumbprint[48];
  char pem[512]; /* the private key as PEM, for writing it out */
} CSERVE_ACME_KEY;

/* a new key into k: 0, or -1 with why in err */
int cserve_acme_key_new(CSERVE_ACME_KEY *k, char *err, size_t err_cap);
/* the key in path (PEM: one cserve_acme_key_new() wrote) into k: 0, or -1
 * with why in err (not P-256 is a refusal too) */
int cserve_acme_key_load(CSERVE_ACME_KEY *k, const char *path, char *err,
                         size_t err_cap);
void cserve_acme_key_free(CSERVE_ACME_KEY *k);

/* A JWS in flattened JSON (RFC 7515 7.2.2, as RFC 8555 6.2 wants it):
 * protected {"alg":"ES256", then "jwk" (kid NULL) or "kid", "nonce",
 * "url"}, payload as given ("" for a POST-as-GET), the signature r||s.
 * malloc'd, or NULL with why in err. */
char *cserve_acme_jws(const CSERVE_ACME_KEY *k, const char *kid,
                      const char *nonce, const char *url, const char *payload,
                      char *err, size_t err_cap);

/* a CSR for name signed by k, as base64url DER (finalize's "csr") into
 * out: 0, or -1 with why in err */
int cserve_acme_csr(const CSERVE_ACME_KEY *k, const char *name, char *out,
                    size_t cap, char *err, size_t err_cap);

/* The server's objects, read from its JSON: every field copied, every
 * URL https:// (printable, no space). Each reader: 0, or -1 with why in
 * err. */
#define CSERVE_ACME_URL 512
#define CSERVE_ACME_AUTHZ_MAX 8

typedef struct {
  char new_nonce[CSERVE_ACME_URL], new_account[CSERVE_ACME_URL],
      new_order[CSERVE_ACME_URL];
} CSERVE_ACME_DIRECTORY;

typedef struct {
  char status[16]; /* pending, ready, processing, valid, invalid */
  char finalize[CSERVE_ACME_URL];
  char certificate[CSERVE_ACME_URL]; /* "" until valid */
  char authz[CSERVE_ACME_AUTHZ_MAX][CSERVE_ACME_URL];
  int nauthz;
} CSERVE_ACME_ORDER;

typedef struct {
  char status[16];           /* pending, valid, invalid, ... */
  char name[254];            /* the identifier's (a DNS name) */
  char url[CSERVE_ACME_URL]; /* its http-01 challenge's */
  char token[129];
  char challenge[16]; /* that challenge's status */
} CSERVE_ACME_AUTHZ;

typedef struct {
  char type[128]; /* "urn:ietf:params:acme:error:badNonce" */
  char detail[256];
} CSERVE_ACME_PROBLEM;

int cserve_acme_directory(const char *json, CSERVE_ACME_DIRECTORY *d, char *err,
                          size_t err_cap);
int cserve_acme_order(const char *json, CSERVE_ACME_ORDER *o, char *err,
                      size_t err_cap);
/* an authorization with an http-01 challenge (one without: refused) */
int cserve_acme_authz(const char *json, CSERVE_ACME_AUTHZ *a, char *err,
                      size_t err_cap);
/* a problem document (RFC 7807); a body that isn't one leaves both "" */
void cserve_acme_problem(const char *json, CSERVE_ACME_PROBLEM *p);

#endif
