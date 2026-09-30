#ifndef CTUI_WM_NET_LISTEN_H
#define CTUI_WM_NET_LISTEN_H

#include "conn.h"

#include <stddef.h>

/* The server side's listener: sockets bound to an address and port each,
 * served together by one poll() until a stop fd turns readable. Each
 * accepted connection runs on a detached thread of its own (at most max at
 * once: the ones past that are closed at once), as a conn.h connection
 * with the listener's deadline; its handler owns it and closes it. What
 * the handler shares with others is the handler's to lock. */

typedef struct CTUI_WM_LISTEN CTUI_WM_LISTEN;

/* the handler: c (close it with ctui_wm_conn_close()), the peer's address
 * as text ("127.0.0.1:50412", "[::1]:50412"), the listener's ud */
typedef void (*CTUI_WM_LISTEN_FN)(CTUI_WM_CONN *c, const char *peer, void *ud);

struct CTUI_WM_LISTEN {
  /* set by the caller (new() fills the defaults) */
  CTUI_WM_LISTEN_FN handler;
  void *ud;
  int max;        /* connections at once (64) */
  int timeout_ms; /* each connection's first deadline (30 s) */
  /* its own */
  int fd;
  int port; /* the bound one (asked for 0: the kernel's pick) */
};

/* a socket listening on host ("127.0.0.1", "::", "localhost") and port,
 * or NULL with why in err */
CTUI_WM_LISTEN *ctui_wm_listen_new(const char *host, int port,
                                   CTUI_WM_LISTEN_FN handler, void *ud,
                                   char *err, size_t err_cap);
void ctui_wm_listen_free(CTUI_WM_LISTEN *l);

/* serves ls[0..n) until stop_fd is readable (or poll fails): 0, or -1
 * with why in err. Connections still running are left to finish. */
int ctui_wm_listen_serve(CTUI_WM_LISTEN *const *ls, int n, int stop_fd,
                         char *err, size_t err_cap);

/* connections running now, over every listener */
int ctui_wm_listen_active(void);

#endif
