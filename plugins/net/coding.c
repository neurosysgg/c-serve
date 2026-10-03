/* strncasecmp() is POSIX, not C11 */
#define _POSIX_C_SOURCE 200809L
#include "coding.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

struct CTUI_WM_HTTP_CODING {
  z_stream z;
  int gzip;    /* else deflate */
  int started; /* inflateInit2() done */
  int ended;   /* the compressed stream's end seen */
  int any;     /* a byte fed */
  /* deflate: its first two bytes, which tell zlib's header from raw */
  unsigned char first[2];
  size_t nfirst;
};

int ctui_wm_http_coding_open(const char *value, CTUI_WM_HTTP_CODING **c,
                             char *err, size_t err_cap) {
  *c = NULL;
  const char *v = value, *ve = value + strlen(value);
  while (v < ve && (*v == ' ' || *v == '\t')) {
    v++;
  }
  while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) {
    ve--;
  }
  size_t n = (size_t)(ve - v);
  int gzip;
  if (n == 0 || (n == 8 && !strncasecmp(v, "identity", 8))) {
    return 0;
  }
  if ((n == 4 && !strncasecmp(v, "gzip", 4)) ||
      (n == 6 && !strncasecmp(v, "x-gzip", 6))) {
    gzip = 1;
  } else if (n == 7 && !strncasecmp(v, "deflate", 7)) {
    gzip = 0;
  } else {
    snprintf(err, err_cap, "a Content-Encoding we don't read: %.*s",
             n > 64 ? 64 : (int)n, v);
    return -1;
  }
  *c = calloc(1, sizeof **c);
  if (!*c) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  (*c)->gzip = gzip;
  return 1;
}

static int start(CTUI_WM_HTTP_CODING *c, int wbits, char *err, size_t err_cap) {
  if (inflateInit2(&c->z, wbits) != Z_OK) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  c->started = 1;
  return 0;
}

/* in[0..n) through inflate, its output to out */
static int run(CTUI_WM_HTTP_CODING *c, const unsigned char *in, size_t n,
               CTUI_WM_HTTP_CODING_OUT out, void *ctx, char *err,
               size_t err_cap) {
  unsigned char buf[16384];
  while (n > 0 && !c->ended) {
    uInt k = n > (1u << 30) ? 1u << 30 : (uInt)n;
    /* zlib's next_in isn't const (without ZLIB_CONST); it only reads */
    c->z.next_in = (Bytef *)(uintptr_t)in;
    c->z.avail_in = k;
    do {
      c->z.next_out = buf;
      c->z.avail_out = sizeof buf;
      int r = inflate(&c->z, Z_NO_FLUSH);
      if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR) {
        snprintf(err, err_cap, "the compressed body is broken");
        return -1;
      }
      size_t got = sizeof buf - c->z.avail_out;
      if (got && out(ctx, (const char *)buf, got)) {
        return 1;
      }
      if (r == Z_STREAM_END) {
        c->ended = 1;
      } else if (got == 0) {
        break; /* more input wanted */
      }
    } while (!c->ended && (c->z.avail_in > 0 || c->z.avail_out == 0));
    in += k;
    n -= k;
  }
  return 0;
}

int ctui_wm_http_coding_feed(CTUI_WM_HTTP_CODING *c, const char *buf, size_t n,
                             CTUI_WM_HTTP_CODING_OUT out, void *ctx, char *err,
                             size_t err_cap) {
  const unsigned char *p = (const unsigned char *)buf;
  if (n) {
    c->any = 1;
  }
  if (c->started) {
    return run(c, p, n, out, ctx, err, err_cap);
  }
  if (c->gzip) {
    /* 32: a zlib stream labelled gzip read too */
    if (start(c, 15 + 32, err, err_cap) != 0) {
      return -1;
    }
    return run(c, p, n, out, ctx, err, err_cap);
  }
  while (n > 0 && c->nfirst < 2) {
    c->first[c->nfirst++] = *p++;
    n--;
  }
  if (c->nfirst < 2) {
    return 0;
  }
  /* RFC 1950's header: method 8, the two bytes a multiple of 31 */
  int zlib = (c->first[0] & 0x0f) == 8 &&
             ((unsigned)c->first[0] << 8 | c->first[1]) % 31 == 0;
  if (start(c, zlib ? 15 : -15, err, err_cap) != 0) {
    return -1;
  }
  int r = run(c, c->first, 2, out, ctx, err, err_cap);
  return r ? r : run(c, p, n, out, ctx, err, err_cap);
}

int ctui_wm_http_coding_end(CTUI_WM_HTTP_CODING *c, char *err, size_t err_cap) {
  /* an empty body labelled compressed (some servers' empty replies) */
  if (c->ended || !c->any) {
    return 0;
  }
  snprintf(err, err_cap, "the compressed body ended early");
  return -1;
}

void ctui_wm_http_coding_free(CTUI_WM_HTTP_CODING *c) {
  if (!c) {
    return;
  }
  if (c->started) {
    inflateEnd(&c->z);
  }
  free(c);
}
