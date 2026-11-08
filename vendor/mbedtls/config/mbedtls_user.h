/* c-serve's additions to mbedtls 4.2's default config (MBEDTLS_USER_CONFIG_FILE):
 * what the release builds, plus DTLS-SRTP -- the use_srtp extension a browser
 * needs before it sends WebRTC media (comms-media; RFC 5764). */
#define MBEDTLS_SSL_DTLS_SRTP
