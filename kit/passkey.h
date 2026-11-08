#ifndef CSERVE_PASSKEY_H
#define CSERVE_PASSKEY_H

#include <stddef.h>
#include <stdint.h>

/* A passkey (WebAuthn) checked, the way phpanta's PasskeyVerifier does it
 * and a little stricter: ES256 alone, no attestation (the trust is in how
 * a device was let in, an invite), and no CBOR -- the browser posts the
 * key as SPKI (getPublicKey()) beside the authenticator data
 * (getAuthenticatorData()). Both ceremonies check the client data's type,
 * its challenge (constant time), its origin (exactly) and that it isn't
 * cross-origin; the authenticator data's rpIdHash (constant time), user
 * presence and user verification. Registration also wants the attested
 * credential data: its credential id must be the one posted and its key
 * (a COSE EC2 key in the one canonical encoding CTAP2 gives for P-256,
 * matched as bytes) the SPKI's. An assertion's signature is checked over
 * authData || SHA-256(clientDataJSON), and its count must rise -- unless
 * both counts are 0, an authenticator that keeps none.
 *
 * Each function: 0, or -1 with why in err. The why is for the log; a
 * client is told only that it was refused. */

typedef struct {
  const char *origin; /* "https://chat.example", as the browser says it */
  const char *rp_id;  /* "chat.example": its SHA-256 is the rpIdHash */
} CSERVE_PASSKEY_RP;

/* the flags in authenticator data */
#define CSERVE_PASSKEY_UP 0x01 /* user present */
#define CSERVE_PASSKEY_UV 0x04 /* user verified */
#define CSERVE_PASSKEY_AT 0x40 /* attested credential data follows */
#define CSERVE_PASSKEY_ED 0x80 /* extensions follow */

/* clientDataJSON (n bytes, as sent) read: type is "webauthn.create" or
 * "webauthn.get", challenge the base64url text the server minted */
int cserve_passkey_client_data(const unsigned char *json, size_t n,
                               const char *type, const char *challenge,
                               const char *origin, char *err, size_t err_cap);

/* authenticator data (n bytes) read: rpIdHash, the flags (want: those
 * that must be set), the count into *count */
int cserve_passkey_auth_data(const unsigned char *ad, size_t n,
                             const char *rp_id, unsigned want, uint32_t *count,
                             char *err, size_t err_cap);

/* a registration: the client data, the authenticator data, the SPKI (a
 * P-256 public key) and the credential id as posted. *count: the
 * authenticator's count now, to keep */
int cserve_passkey_register(const CSERVE_PASSKEY_RP *rp, const char *challenge,
                            const unsigned char *client_data, size_t cd_n,
                            const unsigned char *auth_data, size_t ad_n,
                            const unsigned char *spki, size_t spki_n,
                            const unsigned char *cred_id, size_t id_n,
                            uint32_t *count, char *err, size_t err_cap);

/* an assertion: the client data, the authenticator data, the signature
 * (DER, as the browser gives it), the stored SPKI and count. *count: the
 * new one, to keep */
int cserve_passkey_assert(const CSERVE_PASSKEY_RP *rp, const char *challenge,
                          const unsigned char *client_data, size_t cd_n,
                          const unsigned char *auth_data, size_t ad_n,
                          const unsigned char *sig, size_t sig_n,
                          const unsigned char *spki, size_t spki_n,
                          uint32_t stored, uint32_t *count, char *err,
                          size_t err_cap);

/* 1 when spki (n bytes) is a P-256 public key in SPKI DER, else 0 */
int cserve_passkey_spki_ok(const unsigned char *spki, size_t n);

#endif
