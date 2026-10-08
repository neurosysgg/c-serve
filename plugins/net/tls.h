#ifndef CTUI_WM_NET_TLS_H
#define CTUI_WM_NET_TLS_H

#include <stddef.h>
#include <sys/types.h>

/* The TLS seam: all of the net plugin that knows its TLS library
 * (tls.c: mbedtls 4). A client on a connected, non-blocking socket,
 * checking the server's certificate against the system's CA bundle
 * ($SSL_CERT_FILE, or the usual places) and the host name; the same
 * deadline rules as conn.h. */

typedef struct CTUI_WM_TLS CTUI_WM_TLS;

/* the handshake done on fd for host, or NULL with why in err */
CTUI_WM_TLS *ctui_wm_tls_open(int fd, const char *host, long deadline,
                              char *err, size_t err_cap);
/* all of buf: 0, or -1 with why in err */
int ctui_wm_tls_write(CTUI_WM_TLS *t, const char *buf, size_t n, long deadline,
                      char *err, size_t err_cap);
/* up to n bytes: how many, 0 at the end, -1 with why in err */
ssize_t ctui_wm_tls_read(CTUI_WM_TLS *t, char *buf, size_t n, long deadline,
                         char *err, size_t err_cap);
/* bytes decrypted and waiting: a read gets them without the socket being
 * readable */
size_t ctui_wm_tls_pending(const CTUI_WM_TLS *t);
/* a close_notify when it can go at once, then freed (not the fd) */
void ctui_wm_tls_close(CTUI_WM_TLS *t);

/* The server side (listen.h's servers): a certificate chain and its key
 * (PEM files), and optionally the CA a client must present a certificate
 * from (NULL: none asked for). One per listener, shared by its
 * connections. */
typedef struct CTUI_WM_TLS_SERVER CTUI_WM_TLS_SERVER;

/* the server's config, or NULL with why in err */
CTUI_WM_TLS_SERVER *ctui_wm_tls_server_new(const char *cert, const char *key,
                                           const char *client_ca, char *err,
                                           size_t err_cap);
void ctui_wm_tls_server_free(CTUI_WM_TLS_SERVER *s);
/* the handshake done as the server on an accepted fd, or NULL with why in
 * err */
CTUI_WM_TLS *ctui_wm_tls_accept(int fd, CTUI_WM_TLS_SERVER *s, long deadline,
                                char *err, size_t err_cap);

/* The other side's certificate after the handshake (a server's, or the
 * client's one a server asked for): its subject's common name (printable
 * bytes, cut at cn_cap; "" without one) and the SHA-256 of its DER as 64
 * lowercase hex digits: 0, or -1 when there is none */
int ctui_wm_tls_peer(CTUI_WM_TLS *t, char *cn, size_t cn_cap, char fpr[65]);

/* A client with a config of its own instead of the process's: the CA the
 * server's certificate must come from (NULL: the system's bundle), and a
 * certificate + key to present when the server asks (both NULL: none) --
 * a test's or a tool's client of a mutual-TLS server. */
typedef struct CTUI_WM_TLS_CLIENT CTUI_WM_TLS_CLIENT;

/* the client's config, or NULL with why in err */
CTUI_WM_TLS_CLIENT *ctui_wm_tls_client_new(const char *ca, const char *cert,
                                           const char *key, char *err,
                                           size_t err_cap);
void ctui_wm_tls_client_free(CTUI_WM_TLS_CLIENT *c);
/* open()'s handshake under c's config */
CTUI_WM_TLS *ctui_wm_tls_connect(int fd, const char *host,
                                 CTUI_WM_TLS_CLIENT *c, long deadline,
                                 char *err, size_t err_cap);

#endif
