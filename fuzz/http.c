/* the HTTP client (src/http.c): a server's reply
 * (status line, headers, Content-Length / chunked / to the end), and a
 * URL with a redirect's Location against it, then the request made for
 * it. First byte: 0 = a reply (the rest raw, NULs and all), 1 = URL and
 * Location, NUL-separated, 2 = a reply fed to the decoder in pieces (the
 * next byte seeds their sizes), which must decode as it does whole; 3 =
 * a request's head as the server side takes it (httpd.c); 4 = a body
 * under a Content-Encoding (the next byte: its low bit gzip or deflate,
 * the rest seeds the pieces' sizes), which must decode in pieces as it
 * does whole (coding.c); 5 = a CGI's reply head (cgi.c), whole and fed
 * a byte more at a time; 6 = a CA bundle's PEM (src/tls.c): every block
 * it takes must be what mbedtls's own base64 decoder makes of it; 7 = a
 * request's path routed (static.c, in both climb modes, against a small
 * root of its own; route.c, against a fixed table): a file is always
 * inside the root, a capture never a dot-segment or more than one. Any
 * other first byte: as 3. */
#include "fuzz.h"

#include "cgi.h"
#include "coding.h"
#include "http.h"
#include "httpd.h"
#include "route.h"
#include "static.h"
#include "tls.h"

#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/base64.h>

static void reply(const uint8_t *data, size_t size) {
  /* its own allocation, so reading past it is caught */
  char *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  CSERVE_HTTP_PARSED p;
  char err[128], v[256];
  if (cserve_http_parse(buf, size, &p, err, sizeof err) == 0) {
    FUZZ_CHECK(p.body && p.body[p.len] == '\0' && p.len <= size,
               "a parsed body isn't NUL-terminated or is too long (%zu)",
               p.len);
    FUZZ_CHECK(p.status >= 100 && p.status <= 999, "status %d", p.status);
    cserve_http_header(&p, "Location", v, sizeof v);
    cserve_http_header(&p, "content-type", v, sizeof v);
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

static int got_body(CSERVE_HTTP_DEC *d, const char *buf, size_t n) {
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
  CSERVE_HTTP_PARSED p;
  char err[128];
  int whole = cserve_http_parse(buf, size, &p, err, sizeof err);
  /* a body is never longer than what was fed */
  GOT g = {malloc(size + 1), 0};
  CSERVE_HTTP_DEC d;
  cserve_http_dec_init(&d);
  d.on_body = got_body;
  d.ctx = &g;
  int r = 0;
  for (size_t at = 0; at < size && r == 0;) {
    seed = seed * 1103515245u + 12345u;
    size_t k = 1 + (seed >> 16) % 17;
    k = k < size - at ? k : size - at;
    r = cserve_http_dec_feed(&d, buf + at, k, err, sizeof err);
    at += k;
  }
  if (r == 0) {
    r = cserve_http_dec_end(&d, err, sizeof err) == 0 ? 1 : -1;
  }
  FUZZ_CHECK((whole == 0) == (r == 1), "whole %d, in pieces %d", whole, r);
  if (whole == 0) {
    FUZZ_CHECK(p.status == d.status && p.len == g.len &&
                   !memcmp(p.body, g.buf, g.len) &&
                   p.headers_len == d.headers_len,
               "in pieces, a different reply");
    free(p.body);
  }
  cserve_http_dec_free(&d);
  free(g.buf);
  free(buf);
}

static void url(const uint8_t *data, size_t size) {
  char *part[2];
  fuzz_split(data, size, part, 2);
  CSERVE_URL u, r;
  char err[128];
  if (cserve_url_parse(part[0], &u, err, sizeof err) == 0) {
    FUZZ_CHECK(u.host[0] && u.port[0] && u.path[0] == '/',
               "a parsed URL without host, port or path");
    FUZZ_CHECK(!strpbrk(u.path, " \r\n"), "a space or line break in a path");
    char *out;
    size_t len;
    CSERVE_HTTP_REQ req = {.url = part[0]};
    if (cserve_http_format(&req, &u, part[1][0] & 1, &out, &len) == 0) {
      FUZZ_CHECK(strstr(out, "\r\n\r\n") == out + len - 4,
                 "the request's headers end before its end");
      free(out);
    }
    if (cserve_url_resolve(&u, part[1], &r, err, sizeof err) == 0) {
      FUZZ_CHECK(r.host[0] && r.path[0] == '/', "a resolved URL without "
                                                "host or path");
    }
  }
  fuzz_free(part, 2);
}

static void request(const uint8_t *data, size_t size) {
  char *buf = malloc(size + 1);
  memcpy(buf, data, size);
  buf[size] = '\0';
  CSERVE_HTTPD_REQ r;
  char err[128];
  int st = cserve_httpd_parse(buf, &r, err, sizeof err);
  if (st == 0) {
    FUZZ_CHECK(r.path[0] == '/' && r.method[0], "a request without path or "
                                                "method");
    FUZZ_CHECK(r.query >= r.target && r.query <= r.target + strlen(r.target),
               "the query outside the target");
    for (int i = 0; i < r.n; i++) {
      FUZZ_CHECK(!strpbrk(r.h[i].name, " :\r\n") &&
                     !strpbrk(r.h[i].value, "\r\n"),
                 "a header with a line break or a colon in its name");
    }
    cserve_httpd_header(&r, "Host");
  } else {
    FUZZ_CHECK(st >= 400 && st <= 505 && err[0], "refused with %d", st);
  }
  free(buf);
}

typedef struct {
  char *buf;
  size_t len, cap;
} UNZ;

static int unz_out(void *ctx, const char *buf, size_t n) {
  UNZ *u = ctx;
  /* a bomb stops at 1 MB, the same place both ways */
  size_t room = u->cap - u->len, k = n < room ? n : room;
  memcpy(u->buf + u->len, buf, k);
  u->len += k;
  return u->len == u->cap;
}

/* data under coding, fed in pieces of step(seed) bytes: the result */
static int unz(const char *coding, const char *data, size_t n, unsigned seed,
               UNZ *u) {
  CSERVE_HTTP_CODING *c;
  char err[128];
  if (cserve_http_coding_open(coding, &c, err, sizeof err) != 1) {
    return -2;
  }
  int r = 0;
  for (size_t at = 0; at < n && r == 0;) {
    size_t k = n - at;
    if (seed) {
      seed = seed * 1103515245u + 12345u;
      k = 1 + (seed >> 16) % 61;
      k = k < n - at ? k : n - at;
    }
    r = cserve_http_coding_feed(c, data + at, k, unz_out, u, err, sizeof err);
    FUZZ_CHECK(r >= 0 || err[0], "a refused body without why");
    at += k;
  }
  if (r == 0) {
    r = cserve_http_coding_end(c, err, sizeof err);
  }
  cserve_http_coding_free(c);
  return r;
}

static void coded(const uint8_t *data, size_t size) {
  if (size == 0) {
    return;
  }
  const char *coding = data[0] & 1 ? "gzip" : "deflate";
  unsigned seed = data[0] | 1u;
  char *buf = malloc(size);
  memcpy(buf, data + 1, size - 1);
  UNZ whole = {malloc(1 << 20), 0, 1 << 20};
  UNZ parts = {malloc(1 << 20), 0, 1 << 20};
  int a = unz(coding, buf, size - 1, 0, &whole);
  int b = unz(coding, buf, size - 1, seed, &parts);
  FUZZ_CHECK(a == b, "whole %d, in pieces %d", a, b);
  /* a refused one may have handed on different amounts before it broke */
  if (a >= 0) {
    FUZZ_CHECK(
        whole.len == parts.len && !memcmp(whole.buf, parts.buf, whole.len),
        "in pieces, a different body (%zu vs %zu)", whole.len, parts.len);
  }
  free(whole.buf);
  free(parts.buf);
  free(buf);
}

static void pem(const uint8_t *data, size_t size) {
  char *buf = malloc(size ? size : 1);
  unsigned char *der = malloc(size ? size : 1);
  unsigned char *ref = malloc(size ? size : 1);
  memcpy(buf, data, size);
  size_t pos = 0, last = 0;
  long n;
  while ((n = cserve_tls_pem_next(buf, size, &pos, der)) != 0) {
    FUZZ_CHECK(pos > last && pos <= size, "no progress (%zu after %zu)", pos,
               last);
    if (n > 0) {
      FUZZ_CHECK((size_t)n <= size, "%ld bytes out of %zu", n, size);
      /* the block's body (after the first BEGIN past the last block), as
       * mbedtls decodes it */
      static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
      const char *b = memmem(buf + last, pos - last, BEGIN, sizeof BEGIN - 1);
      const char *e = buf + pos - (sizeof "-----END CERTIFICATE-----" - 1);
      FUZZ_CHECK(b != NULL, "a block without its BEGIN");
      b += sizeof BEGIN - 1;
      size_t olen = 0;
      int ret = mbedtls_base64_decode(
          ref, size, &olen, (const unsigned char *)b, (size_t)(e - b));
      FUZZ_CHECK(ret == 0 && olen == (size_t)n && !memcmp(ref, der, olen),
                 "a block mbedtls decodes otherwise (%d, %zu vs %ld bytes)",
                 ret, olen, n);
    }
    last = pos;
  }
  free(buf);
  free(der);
  free(ref);
}

static void cgi_head(const uint8_t *data, size_t size) {
  char *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  CSERVE_HTTPD_REPLY rep;
  char type[256], err[160];
  memset(&rep, 0, sizeof rep);
  long whole =
      cserve_cgi_head(buf, size, &rep, type, sizeof type, err, sizeof err);
  if (whole > 0) {
    FUZZ_CHECK((size_t)whole <= size, "the body starts past the end (%ld)",
               whole);
    FUZZ_CHECK(rep.status >= 200 && rep.status <= 599, "status %d", rep.status);
    FUZZ_CHECK(!strpbrk(type, "\r\n") &&
                   strlen(rep.headers) < sizeof rep.headers,
               "a line break in the type, or headers overrun");
    /* every header line well formed: no bare CR or LF inside */
    for (const char *p = rep.headers; *p;) {
      const char *e = strstr(p, "\r\n");
      FUZZ_CHECK(e && !memchr(p, '\n', (size_t)(e - p)) &&
                     !memchr(p, '\r', (size_t)(e - p)),
                 "a header line that isn't one");
      if (!e) {
        break;
      }
      p = e + 2;
    }
  } else if (whole < 0) {
    FUZZ_CHECK(err[0], "a refused head without why");
  }
  /* as it comes in: not whole until the length it's whole at */
  for (size_t n = 0; whole > 0 && n < (size_t)whole && n < 512; n++) {
    long r = cserve_cgi_head(buf, n, &rep, type, sizeof type, err, sizeof err);
    FUZZ_CHECK(r <= 0, "whole at %zu of %ld", n, whole);
  }
  free(buf);
}

static char g_paths_root[PATH_MAX];

static void paths_gone(void) {
  char rm[PATH_MAX + 16];
  snprintf(rm, sizeof rm, "rm -rf '%s'", g_paths_root);
  (void)!system(rm);
}

/* the root mode 7 routes into (gone at exit): a file, a stamped asset's,
 * a directory */
static const char *paths_root(void) {
  char *root = g_paths_root;
  if (!root[0]) {
    char dir[] = "/tmp/cserve-fuzz-XXXXXX";
    if (!mkdtemp(dir)) {
      abort();
    }
    char p[PATH_MAX];
    const char *dirs[] = {"assets", "assets/js", "sub"};
    for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) {
      snprintf(p, sizeof p, "%s/%s", dir, dirs[i]);
      mkdir(p, 0700);
    }
    const char *files[] = {"a.css", "assets/js/main.js", "sub/page.html",
                           "index.php", ".user.ini"};
    for (size_t i = 0; i < sizeof files / sizeof *files; i++) {
      snprintf(p, sizeof p, "%s/%s", dir, files[i]);
      FILE *f = fopen(p, "w");
      if (f) {
        fclose(f);
      }
    }
    if (!realpath(dir, root)) {
      abort();
    }
    atexit(paths_gone);
  }
  return root;
}

static void on_any(const CSERVE_HTTPD_REQ *r, const char *body,
                   const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)r;
  (void)body;
  for (int i = 0; i < m->n; i++) {
    const char *v = m->p[i].value;
    if (strcmp(m->p[i].name, "*") == 0) {
      /* the rest: no segment of it dotted */
      for (const char *q = v; *q; q++) {
        FUZZ_CHECK(!(*q == '.' && (q == v || q[-1] == '/')),
                   "a dot-segment in the rest: %s", v);
      }
    } else {
      FUZZ_CHECK(*v && *v != '.' && !strchr(v, '/'),
                 "a capture that isn't one segment: %s", v);
    }
  }
  rep->status = 200;
}

static const CSERVE_ROUTE FUZZ_ROUTES[] = {
    {CSERVE_GET, "/", on_any},
    {CSERVE_GET, "/releases/{slug}", on_any},
    {CSERVE_GET | CSERVE_POST, "/releases/{slug}/{format}", on_any},
    {CSERVE_DELETE, "/releases/{slug}/{format}", on_any},
    {CSERVE_GET, "/assets/*", on_any},
    {CSERVE_GET, "/{a}/{b}/{c}/*", on_any},
};

static void paths(const uint8_t *data, size_t size) {
  if (size == 0) {
    return;
  }
  /* the first byte: the method; the rest the path (as httpd decoded it) */
  static const char *const METHOD[] = {"GET", "HEAD", "POST", "DELETE", "BREW"};
  CSERVE_HTTPD_REQ r;
  memset(&r, 0, sizeof r);
  snprintf(r.method, sizeof r.method, "%s", METHOD[data[0] % 5]);
  size_t n = size - 1 < sizeof r.path - 1 ? size - 1 : sizeof r.path - 1;
  memcpy(r.path, data + 1, n);
  r.path[n] = '\0';
  const char *root = paths_root();
  size_t rl = strlen(root);
  for (int front = 0; front < 2; front++) {
    CSERVE_STATIC s = {.root = root, .climb_front = front};
    CSERVE_STATIC_ROUTE rt;
    cserve_static_route(&s, r.path, &rt);
    FUZZ_CHECK(rt.kind != CSERVE_STATIC_FILE ||
                   (!strncmp(rt.file, root, rl) && rt.file[rl] == '/'),
               "a file outside the root: %s", rt.file);
    FUZZ_CHECK(rt.kind == CSERVE_STATIC_FILE || !rt.immutable,
               "immutable but not a file");
  }
  CSERVE_HTTPD_REPLY rep = {0};
  int answered = cserve_route_dispatch(
      FUZZ_ROUTES, (int)(sizeof FUZZ_ROUTES / sizeof *FUZZ_ROUTES), &r, NULL,
      &rep);
  FUZZ_CHECK(!answered || rep.status == 200 || rep.status == 405,
             "dispatch answered %d", rep.status);
  if (rep.owned) {
    free(rep.body);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  if (data[0] == 0) {
    reply(data + 1, size - 1);
  } else if (data[0] == 1) {
    url(data + 1, size - 1);
  } else if (data[0] == 2) {
    pieces(data + 1, size - 1);
  } else if (data[0] == 4) {
    coded(data + 1, size - 1);
  } else if (data[0] == 5) {
    cgi_head(data + 1, size - 1);
  } else if (data[0] == 6) {
    pem(data + 1, size - 1);
  } else if (data[0] == 7) {
    paths(data + 1, size - 1);
  } else {
    request(data + 1, size - 1);
  }
  return 0;
}
