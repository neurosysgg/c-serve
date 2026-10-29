/* a web root's files: phpanta's public/.htaccess as code (the build
 * stamp stripped, real files served, everything else to the front), and
 * what a served file's headers say */
/* realpath, st_mtim: POSIX, not C11 */
#define _GNU_SOURCE
#include "static.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* a file this big or smaller is read whole (its Content-Length said);
 * past it, streamed */
#define FILE_WHOLE (8 << 20)

/* "v-" and 8 lowercase hex digits: phpanta's tools/build-assets.mjs's
 * stamp */
static int stamp(const char *seg, size_t len) {
  if (len != 10 || seg[0] != 'v' || seg[1] != '-') {
    return 0;
  }
  for (size_t i = 2; i < len; i++) {
    if (!isxdigit((unsigned char)seg[i]) || isupper((unsigned char)seg[i])) {
      return 0;
    }
  }
  return 1;
}

static const char *ext_of(const char *file) {
  const char *slash = strrchr(file, '/');
  const char *dot = strrchr(slash ? slash : file, '.');
  return dot ? dot + 1 : "";
}

static void route(const CSERVE_STATIC *s, const char *path,
                  CSERVE_STATIC_ROUTE *out) {
  out->kind = CSERVE_STATIC_FRONT;
  if (path[0] != '/') {
    out->kind = CSERVE_STATIC_BAD;
    return;
  }
  /* the path again, segment by segment: empty ones dropped, "." and ".."
   * refused or the front's, a dot-segment or file the front's */
  char rel[PATH_MAX];
  size_t n = 0;
  int seg_no = 0, dotted = 0;
  const char *first = NULL, *second = NULL;
  for (const char *p = path; *p;) {
    while (*p == '/') {
      p++;
    }
    size_t len = strcspn(p, "/");
    if (len == 0) {
      break;
    }
    if ((len == 2 && p[0] == '.' && p[1] == '.') || (len == 1 && p[0] == '.')) {
      out->kind = s->climb_front ? CSERVE_STATIC_FRONT : CSERVE_STATIC_BAD;
      return;
    }
    dotted |= p[0] == '.';
    /* /assets/js/v-XXXXXXXX/... or /assets/css/...: the stamp goes */
    if (seg_no == 2 && first && second && stamp(p, len) &&
        !strncmp(first, "assets/", 7) &&
        (!strncmp(second, "js/", 3) || !strncmp(second, "css/", 4))) {
      out->immutable = 1;
    } else {
      if (n + len + 2 > sizeof rel) {
        return; /* too long for a file: the front's */
      }
      rel[n++] = '/';
      memcpy(rel + n, p, len);
      n += len;
    }
    if (seg_no == 0) {
      first = p;
    } else if (seg_no == 1) {
      second = p;
    }
    seg_no++;
    p += len;
  }
  rel[n] = '\0';
  if (dotted || n == 0) {
    return;
  }
  const char *ext = ext_of(rel);
  if (!strncasecmp(ext, "php", 3) || !strcasecmp(ext, "phtml") ||
      !strcasecmp(ext, "phar")) {
    return; /* scripts are never served, nor run but for the front */
  }
  char full[PATH_MAX], real[PATH_MAX];
  struct stat st;
  if (snprintf(full, sizeof full, "%s%s", s->root, rel) >= (int)sizeof full ||
      !realpath(full, real) || stat(real, &st) != 0 || !S_ISREG(st.st_mode)) {
    return;
  }
  /* a symlink leading out of the root: not ours to serve */
  size_t rl = strlen(s->root);
  if (strncmp(real, s->root, rl) != 0 || real[rl] != '/') {
    return;
  }
  out->kind = CSERVE_STATIC_FILE;
  snprintf(out->file, sizeof out->file, "%s", real);
}

void cserve_static_route(const CSERVE_STATIC *s, const char *path,
                         CSERVE_STATIC_ROUTE *out) {
  memset(out, 0, sizeof *out);
  route(s, path, out);
  /* a stamp seen on the way to something else says nothing */
  if (out->kind != CSERVE_STATIC_FILE) {
    out->immutable = 0;
  }
}

static const struct {
  const char *ext, *type;
} MIME[] = {
    {"html", "text/html; charset=utf-8"},
    {"htm", "text/html; charset=utf-8"},
    {"css", "text/css; charset=utf-8"},
    {"js", "text/javascript; charset=utf-8"},
    {"mjs", "text/javascript; charset=utf-8"},
    {"map", "application/json"},
    {"json", "application/json"},
    {"webmanifest", "application/manifest+json"},
    {"txt", "text/plain; charset=utf-8"},
    {"svg", "image/svg+xml"},
    {"png", "image/png"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"gif", "image/gif"},
    {"ico", "image/vnd.microsoft.icon"},
    {"webp", "image/webp"},
    {"avif", "image/avif"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"wasm", "application/wasm"},
};

const char *cserve_static_mime(const char *file) {
  const char *ext = ext_of(file);
  for (size_t i = 0; i < sizeof MIME / sizeof *MIME; i++) {
    if (!strcasecmp(ext, MIME[i].ext)) {
      return MIME[i].type;
    }
  }
  return "application/octet-stream";
}

/* .htaccess's tiers: what carries behaviour an hour (a year when its URL
 * names its content), pictures and fonts 30 days */
const char *cserve_static_cache(const char *file, int immutable) {
  const char *ext = ext_of(file);
  static const char *const CODE[] = {"css", "js", "mjs", "map"};
  static const char *const MEDIA[] = {"svg", "png",  "jpg",  "jpeg", "gif",
                                      "ico", "webp", "avif", "woff", "woff2"};
  for (size_t i = 0; i < sizeof CODE / sizeof *CODE; i++) {
    if (!strcasecmp(ext, CODE[i])) {
      return immutable ? "public, max-age=31536000, immutable"
                       : "public, max-age=3600";
    }
  }
  for (size_t i = 0; i < sizeof MEDIA / sizeof *MEDIA; i++) {
    if (!strcasecmp(ext, MEDIA[i])) {
      return "public, max-age=2592000";
    }
  }
  return "";
}

static void text(CSERVE_HTTPD_REPLY *rep, int status, const char *t) {
  cserve_httpd_text(rep, status, "text/plain; charset=utf-8", t, strlen(t));
}

/* the big file's body, a piece at a time */
static int file_stream(CSERVE_HTTPD_OUT *o, void *ud) {
  int fd = (int)(intptr_t)ud;
  char buf[65536];
  ssize_t n;
  int ret = 0;
  while ((n = read(fd, buf, sizeof buf)) != 0) {
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0 || cserve_httpd_out(o, buf, (size_t)n) != 0) {
      ret = -1;
      break;
    }
  }
  close(fd);
  return ret;
}

/* whether an If-None-Match list has etag (or is "*") */
static int matches(const char *list, const char *etag) {
  if (!list) {
    return 0;
  }
  if (strcmp(list, "*") == 0) {
    return 1;
  }
  size_t el = strlen(etag);
  for (const char *p = list; (p = strstr(p, etag)); p += el) {
    char after = p[el];
    if ((p == list || p[-1] == ' ' || p[-1] == ',') &&
        (after == '\0' || after == ',' || after == ' ')) {
      return 1;
    }
  }
  return 0;
}

void cserve_static_serve(const CSERVE_HTTPD_REQ *r,
                         const CSERVE_STATIC_ROUTE *rt,
                         CSERVE_HTTPD_REPLY *rep) {
  if (strcmp(r->method, "GET") && strcmp(r->method, "HEAD")) {
    text(rep, 405, "GET or HEAD here\n");
    snprintf(rep->headers, sizeof rep->headers, "Allow: GET, HEAD\r\n");
    return;
  }
  int fd = open(rt->file, O_RDONLY | O_CLOEXEC);
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    if (fd >= 0) {
      close(fd);
    }
    text(rep, 404, "not found\n");
    return;
  }
  char etag[64];
  snprintf(etag, sizeof etag, "W/\"%llx-%llx\"", (unsigned long long)st.st_size,
           (unsigned long long)st.st_mtim.tv_sec * 1000000000ULL +
               (unsigned long long)st.st_mtim.tv_nsec);
  const char *cache = cserve_static_cache(rt->file, rt->immutable);
  int n = snprintf(rep->headers, sizeof rep->headers,
                   "ETag: %s\r\nX-Content-Type-Options: nosniff\r\n", etag);
  if (*cache && n > 0 && (size_t)n < sizeof rep->headers) {
    snprintf(rep->headers + n, sizeof rep->headers - (size_t)n,
             "Cache-Control: %s\r\n", cache);
  }
  if (matches(cserve_httpd_header(r, "If-None-Match"), etag)) {
    close(fd);
    rep->status = 304;
    return;
  }
  rep->status = 200;
  rep->type = cserve_static_mime(rt->file);
  if (st.st_size > FILE_WHOLE) {
    rep->stream = file_stream;
    rep->stream_ud = (void *)(intptr_t)fd;
    return;
  }
  char *body = malloc((size_t)st.st_size + 1);
  size_t got = 0;
  while (body && got < (size_t)st.st_size) {
    ssize_t k = read(fd, body + got, (size_t)st.st_size - got);
    if (k < 0 && errno == EINTR) {
      continue;
    }
    if (k <= 0) {
      break;
    }
    got += (size_t)k;
  }
  close(fd);
  if (!body || got != (size_t)st.st_size) {
    free(body);
    rep->headers[0] = '\0';
    text(rep, 500, "the file couldn't be read\n");
    return;
  }
  rep->body = body;
  rep->len = got;
  rep->owned = 1;
}
