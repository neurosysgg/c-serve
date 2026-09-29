/* the net plugin's HTTP client (plugins/net/http.c): a server's reply
 * (status line, headers, Content-Length / chunked / to the end), and a
 * URL with a redirect's Location against it, then the request made for
 * it. First byte: 0 = a reply (the rest raw, NULs and all), 1 = URL and
 * Location, NUL-separated, 2 = a reply fed to the decoder in pieces (the
 * next byte seeds their sizes), which must decode as it does whole. */
#include "fuzz.h"

#include "http.h"

static void reply(const uint8_t *data, size_t size) {
  /* its own allocation, so reading past it is caught */
  char *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  CTUI_WM_HTTP_PARSED p;
  char err[128], v[256];
  if (ctui_wm_http_parse(buf, size, &p, err, sizeof err) == 0) {
    FUZZ_CHECK(p.body && p.body[p.len] == '\0' && p.len <= size,
               "a parsed body isn't NUL-terminated or is too long (%zu)",
               p.len);
    FUZZ_CHECK(p.status >= 100 && p.status <= 999, "status %d", p.status);
    ctui_wm_http_header(&p, "Location", v, sizeof v);
    ctui_wm_http_header(&p, "content-type", v, sizeof v);
    free(p.body);
  } else {
    FUZZ_CHECK(err[0], "a refused reply without why");
  }
  free(buf);
}

typedef struct {
  char *buf;
  size_t len;
} GOT;

static int got_body(CTUI_WM_HTTP_DEC *d, const char *buf, size_t n) {
  GOT *g = d->ctx;
  memcpy(g->buf + g->len, buf, n);
  g->len += n;
  return 0;
}

static void pieces(const uint8_t *data, size_t size) {
  if (size == 0) {
    return;
  }
  unsigned seed = data[0];
  data++;
  size--;
  char *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  CTUI_WM_HTTP_PARSED p;
  char err[128];
  int whole = ctui_wm_http_parse(buf, size, &p, err, sizeof err);
  /* a body is never longer than what was fed */
  GOT g = {malloc(size + 1), 0};
  CTUI_WM_HTTP_DEC d;
  ctui_wm_http_dec_init(&d);
  d.on_body = got_body;
  d.ctx = &g;
  int r = 0;
  for (size_t at = 0; at < size && r == 0;) {
    seed = seed * 1103515245u + 12345u;
    size_t k = 1 + (seed >> 16) % 17;
    k = k < size - at ? k : size - at;
    r = ctui_wm_http_dec_feed(&d, buf + at, k, err, sizeof err);
    at += k;
  }
  if (r == 0) {
    r = ctui_wm_http_dec_end(&d, err, sizeof err) == 0 ? 1 : -1;
  }
  FUZZ_CHECK((whole == 0) == (r == 1), "whole %d, in pieces %d", whole, r);
  if (whole == 0) {
    FUZZ_CHECK(p.status == d.status && p.len == g.len &&
                   !memcmp(p.body, g.buf, g.len) &&
                   p.headers_len == d.headers_len,
               "in pieces, a different reply");
    free(p.body);
  }
  ctui_wm_http_dec_free(&d);
  free(g.buf);
  free(buf);
}

static void url(const uint8_t *data, size_t size) {
  char *part[2];
  fuzz_split(data, size, part, 2);
  CTUI_WM_URL u, r;
  char err[128];
  if (ctui_wm_url_parse(part[0], &u, err, sizeof err) == 0) {
    FUZZ_CHECK(u.host[0] && u.port[0] && u.path[0] == '/',
               "a parsed URL without host, port or path");
    FUZZ_CHECK(!strpbrk(u.path, " \r\n"), "a space or line break in a path");
    char *out;
    size_t len;
    CTUI_WM_HTTP_REQ req = {.url = part[0]};
    if (ctui_wm_http_format(&req, &u, &out, &len) == 0) {
      FUZZ_CHECK(strstr(out, "\r\n\r\n") == out + len - 4,
                 "the request's headers end before its end");
      free(out);
    }
    if (ctui_wm_url_resolve(&u, part[1], &r, err, sizeof err) == 0) {
      FUZZ_CHECK(r.host[0] && r.path[0] == '/', "a resolved URL without "
                                                "host or path");
    }
  }
  fuzz_free(part, 2);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  if (data[0] == 0) {
    reply(data + 1, size - 1);
  } else if (data[0] == 1) {
    url(data + 1, size - 1);
  } else {
    pieces(data + 1, size - 1);
  }
  return 0;
}
