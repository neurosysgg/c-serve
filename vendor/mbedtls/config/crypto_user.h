/* c-serve's additions to TF-PSA-Crypto's default config
 * (TF_PSA_CRYPTO_USER_CONFIG_FILE): PSA guards its own key slots and RNG, so
 * a worker may sign, verify or draw random bytes while the loop handshakes. */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
