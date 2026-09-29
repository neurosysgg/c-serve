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

#endif
