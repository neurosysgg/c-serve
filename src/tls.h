#ifndef CSERVE_TLS_H
#define CSERVE_TLS_H

#include <stddef.h>
#include <sys/types.h>

/* The TLS seam: all of c-serve that knows its TLS library
 * (tls.c: mbedtls 4). A client on a connected, non-blocking socket,
 * checking the server's certificate against the system's CA bundle
 * ($SSL_CERT_FILE, or the usual places) and the host name; the same
 * deadline rules as conn.h. */

typedef struct CSERVE_TLS CSERVE_TLS;

/* the handshake done on fd for host, or NULL with why in err */
CSERVE_TLS *cserve_tls_open(int fd, const char *host, long deadline, char *err,
                            size_t err_cap);
/* all of buf: 0, or -1 with why in err */
int cserve_tls_write(CSERVE_TLS *t, const char *buf, size_t n, long deadline,
                     char *err, size_t err_cap);
/* up to n bytes: how many, 0 at the end, -1 with why in err */
ssize_t cserve_tls_read(CSERVE_TLS *t, char *buf, size_t n, long deadline,
                        char *err, size_t err_cap);
/* bytes decrypted and waiting: a read gets them without the socket being
 * readable */
size_t cserve_tls_pending(const CSERVE_TLS *t);
/* a close_notify when it can go at once, then freed (not the fd) */
void cserve_tls_close(CSERVE_TLS *t);

/* The server side (listen.h's servers): a certificate chain and its key
 * (PEM files), and optionally the CA a client must present a certificate
 * from (NULL: none asked for). One per listener, shared by its
 * connections. */
typedef struct CSERVE_TLS_SERVER CSERVE_TLS_SERVER;

/* the server's config, or NULL with why in err */
CSERVE_TLS_SERVER *cserve_tls_server_new(const char *cert, const char *key,
                                         const char *client_ca, char *err,
                                         size_t err_cap);
void cserve_tls_server_free(CSERVE_TLS_SERVER *s);

/* The crypto's one lock. mbedtls is built here without
 * MBEDTLS_THREADING_C, so PSA's key slots and its RNG are guarded by
 * nothing of their own: every TLS call holds this lock, and so must any
 * other use of a key slot or the RNG on any thread -- a key imported, a
 * signature made or checked, psa_generate_random(). Keyless work
 * (psa_hash_compute(), PBKDF2 over bytes: kit/password.c) touches
 * neither and runs without it, so a slow password check never holds up
 * a handshake. Never held across a wait. */
void cserve_crypto_lock(void);
void cserve_crypto_unlock(void);
/* PSA started, once, before any thread could race to start it (a host's
 * first act): 0, or -1 */
int cserve_crypto_start(void);

/* Every server speaks TLS 1.3 and nothing older (a client's config keeps
 * 1.2 too: it talks to servers this side doesn't choose).
 *
 * A server for many names, its certificate picked by the client's SNI:
 * dir holds a directory per name (a lowercase DNS name: one
 * cserve_tls_name_ok() takes), each with cert.pem (the chain, the
 * name's own certificate first) and key.pem (its P-256 key). A pair is
 * taken only when the key is the certificate's and the certificate's
 * subjectAltName carries the directory's name; one that isn't fails the
 * whole set. A client that names none of them, or none at all, is
 * refused in the handshake (unrecognized_name): nothing is served to a
 * stranger who asks the address what it is. A directory with no names
 * yet is a set that refuses every handshake -- a box before its first
 * certificate, which a reload then fills. NULL with why in err. */
CSERVE_TLS_SERVER *cserve_tls_names_new(const char *dir, char *err,
                                        size_t err_cap);
/* the names' directory read again (a certificate renewed): the new set
 * from the next handshake on, while every connection begun under the
 * old set keeps it to its end. A set that doesn't load leaves the old
 * one in place: 0, or -1 with why in err. Only for a server made by
 * cserve_tls_names_new(). */
int cserve_tls_names_reload(CSERVE_TLS_SERVER *s, char *err, size_t err_cap);
/* how many names the set has now (0 for a one-certificate server) */
int cserve_tls_names_count(CSERVE_TLS_SERVER *s);
/* 1 when host (n bytes, any case) is one of the set's names now, else
 * 0. Any thread. */
int cserve_tls_names_has(CSERVE_TLS_SERVER *s, const char *host, size_t n);
/* 1 when name (n bytes) is a lowercase DNS name: labels of [a-z0-9-],
 * 1-63 bytes each, no hyphen at either end, 253 bytes at most, no
 * trailing dot; else 0 */
int cserve_tls_name_ok(const char *name, size_t n);
/* the handshake done as the server on an accepted fd, or NULL with why in
 * err */
CSERVE_TLS *cserve_tls_accept(int fd, CSERVE_TLS_SERVER *s, long deadline,
                              char *err, size_t err_cap);

/* The server side without waiting, for a loop (loop.h) that owns the
 * socket: each call does what it can now and says what it needs next --
 * WANT_READ or WANT_WRITE: call it again when the socket is readable or
 * writable. Only the loop's thread calls these. */
#define CSERVE_TLS_WANT_READ (-2)
#define CSERVE_TLS_WANT_WRITE (-3)

/* the server's side on an accepted, non-blocking fd, its handshake not
 * begun, or NULL with why in err */
CSERVE_TLS *cserve_tls_server_start(int fd, CSERVE_TLS_SERVER *s, char *err,
                                    size_t err_cap);
/* the handshake moved on: 0 once it's done, a WANT, or -1 with why in
 * err */
int cserve_tls_step(CSERVE_TLS *t, char *err, size_t err_cap);
/* up to n bytes: how many, 0 at the end, a WANT, or -1 with why in err */
long cserve_tls_recv(CSERVE_TLS *t, char *buf, size_t n, char *err,
                     size_t err_cap);
/* some of buf sent: how many (> 0), a WANT, or -1 with why in err. After
 * a WANT the next call must offer the same bytes again (mbedtls has
 * taken some of them into a record already) */
long cserve_tls_send(CSERVE_TLS *t, const char *buf, size_t n, char *err,
                     size_t err_cap);

/* The next PEM certificate in buf[*pos..len), decoded into der (len
 * bytes always fit) and *pos moved past it: its DER's length, 0 when none
 * is left, -1 for a block that isn't clean base64 by mbedtls's rules
 * (skipped: the next one still reads). How the CA bundle is read
 * (tls.c). */
long cserve_tls_pem_next(const char *buf, size_t len, size_t *pos,
                         unsigned char *der);

/* The other side's certificate after the handshake (a server's, or the
 * client's one a server asked for): its subject's common name (printable
 * bytes, cut at cn_cap; "" without one) and the SHA-256 of its DER as 64
 * lowercase hex digits: 0, or -1 when there is none */
int cserve_tls_peer(CSERVE_TLS *t, char *cn, size_t cn_cap, char fpr[65]);

/* A client with a config of its own instead of the process's: the CA the
 * server's certificate must come from (NULL: the system's bundle), and a
 * certificate + key to present when the server asks (both NULL: none) --
 * a test's or a tool's client of a mutual-TLS server. */
typedef struct CSERVE_TLS_CLIENT CSERVE_TLS_CLIENT;

/* the client's config, or NULL with why in err */
CSERVE_TLS_CLIENT *cserve_tls_client_new(const char *ca, const char *cert,
                                         const char *key, char *err,
                                         size_t err_cap);
void cserve_tls_client_free(CSERVE_TLS_CLIENT *c);
/* open()'s handshake under c's config */
CSERVE_TLS *cserve_tls_connect(int fd, const char *host, CSERVE_TLS_CLIENT *c,
                               long deadline, char *err, size_t err_cap);

#endif
