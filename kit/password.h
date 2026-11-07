#ifndef CSERVE_PASSWORD_H
#define CSERVE_PASSWORD_H

#include <stddef.h>

/* A password checked against its digest: PBKDF2-HMAC-SHA256, through
 * mbedtls's PSA, written
 *
 *   $pbkdf2-sha256$<iterations>$<salt, base64>$<hash, base64>
 *
 * (base64 standard and padded; phpanta's PasswordHash mints and reads the
 * same). The comparison is PSA's own, in constant time. A digest that
 * isn't one of these never matches, and costs what a real one does: the
 * check runs against cserve_password_unmatchable() instead, so a
 * malformed digest and a wrong password take the same time -- as does a
 * name nobody has, when a gate checks the unmatchable digest for it. */

/* the cost a digest may ask for: below is no protection, above is a
 * request that never ends */
#define CSERVE_PASSWORD_ITER_MIN 100000
#define CSERVE_PASSWORD_ITER_MAX 10000000

/* whether password (len bytes) is the one digest was made of */
int cserve_password_matches(const char *digest, const char *password,
                            size_t len);

/* whether digest is one this reads (an app's init() asks, so a bad digest
 * is a refusal to start, not a gate that never opens) */
int cserve_password_valid(const char *digest);

/* a digest at the default cost nobody knows a password for */
const char *cserve_password_unmatchable(void);

#endif
