#ifndef CSERVE_CODING_H
#define CSERVE_CODING_H

#include <stddef.h>

/* A reply body's Content-Encoding undone as it arrives (zlib): gzip
 * (x-gzip), deflate (zlib-wrapped, or raw as some servers send it). Pure
 * like http.h: the tests and the fuzzer take it as it is. What follows
 * the compressed stream's end (padding, a second gzip member) is
 * dropped. */

typedef struct CSERVE_HTTP_CODING CSERVE_HTTP_CODING;

/* the decoded bytes, as they come; non-zero stops the body */
typedef int (*CSERVE_HTTP_CODING_OUT)(void *ctx, const char *buf, size_t n);

/* a Content-Encoding value (case-insensitive, trimmed): 0 if it needs
 * nothing undone ("", "identity"), 1 with *c ready, or -1 with why in err
 * (a coding we don't know, more than one, out of memory) */
int cserve_http_coding_open(const char *value, CSERVE_HTTP_CODING **c,
                            char *err, size_t err_cap);
/* n more coded bytes, decoded to out: 0, 1 if out stopped it, or -1 with
 * why in err (not what the coding says) */
int cserve_http_coding_feed(CSERVE_HTTP_CODING *c, const char *buf, size_t n,
                            CSERVE_HTTP_CODING_OUT out, void *ctx, char *err,
                            size_t err_cap);
/* the body ended: 0 if the compressed stream did too, -1 with why in err
 * (cut short) */
int cserve_http_coding_end(CSERVE_HTTP_CODING *c, char *err, size_t err_cap);
void cserve_http_coding_free(CSERVE_HTTP_CODING *c);

#endif
