/* the net plugin's HTTP client (plugins/net/http.c): a server's reply
 * (status line, headers, Content-Length / chunked / to the end), and a
 * URL with a redirect's Location against it, then the request made for
 * it. First byte: 0 = a reply (the rest raw, NULs and all), 1 = URL and
 * Location, NUL-separated. */
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
  } else {
    url(data + 1, size - 1);
  }
  return 0;
}
