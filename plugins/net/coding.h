#ifndef CTUI_WM_NET_CODING_H
#define CTUI_WM_NET_CODING_H

#include <stddef.h>

/* A reply body's Content-Encoding undone as it arrives (zlib): gzip
 * (x-gzip), deflate (zlib-wrapped, or raw as some servers send it). Pure
 * like http.h: the tests and the fuzzer take it as it is. What follows
 * the compressed stream's end (padding, a second gzip member) is
 * dropped. */

typedef struct CTUI_WM_HTTP_CODING CTUI_WM_HTTP_CODING;

/* the decoded bytes, as they come; non-zero stops the body */
typedef int (*CTUI_WM_HTTP_CODING_OUT)(void *ctx, const char *buf, size_t n);

/* a Content-Encoding value (case-insensitive, trimmed): 0 if it needs
 * nothing undone ("", "identity"), 1 with *c ready, or -1 with why in err
 * (a coding we don't know, more than one, out of memory) */
int ctui_wm_http_coding_open(const char *value, CTUI_WM_HTTP_CODING **c,
                             char *err, size_t err_cap);
/* n more coded bytes, decoded to out: 0, 1 if out stopped it, or -1 with
 * why in err (not what the coding says) */
int ctui_wm_http_coding_feed(CTUI_WM_HTTP_CODING *c, const char *buf, size_t n,
                             CTUI_WM_HTTP_CODING_OUT out, void *ctx, char *err,
                             size_t err_cap);
/* the body ended: 0 if the compressed stream did too, -1 with why in err
 * (cut short) */
int ctui_wm_http_coding_end(CTUI_WM_HTTP_CODING *c, char *err, size_t err_cap);
void ctui_wm_http_coding_free(CTUI_WM_HTTP_CODING *c);

#endif
