/* cserve-precompress ROOT: every text-like file under ROOT (by static.c's
 * types: text, JavaScript, JSON, SVG, XML) given a gzip copy beside it,
 * FILE.gz, which cserve serves to a client that takes gzip (static.h).
 * Run once per deploy, after the files are in place: a copy older than
 * its file is never served, so a forgotten run costs bytes, never
 * correctness. Symlinks are not followed, a file under 256 bytes or one
 * that gzip doesn't make smaller gets no copy, a fresh copy is left as it
 * is, and a copy is written beside its file and renamed into place. */
#define _XOPEN_SOURCE 700 /* nftw() */
#include "static.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

static int g_made, g_fresh, g_failed;

static int compressible(const char *path) {
  const char *t = cserve_static_mime(path);
  return !strncmp(t, "text/", 5) || strstr(t, "javascript") ||
         strstr(t, "json") || strstr(t, "svg") || strstr(t, "xml");
}

/* path's bytes, all of them (malloc'd; *n its length), or NULL */
static unsigned char *slurp(const char *path, size_t *n) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0) {
    if (fd >= 0) {
      close(fd);
    }
    return NULL;
  }
  unsigned char *buf = malloc((size_t)st.st_size + 1);
  size_t got = 0;
  while (buf && got < (size_t)st.st_size) {
    ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
    if (r < 0 && errno == EINTR) {
      continue;
    }
    if (r <= 0) {
      break;
    }
    got += (size_t)r;
  }
  close(fd);
  if (buf && got != (size_t)st.st_size) {
    free(buf);
    return NULL;
  }
  *n = got;
  return buf;
}

/* in as gzip into a buffer (malloc'd; *out_n its length), or NULL */
static unsigned char *gzip(const unsigned char *in, size_t n, size_t *out_n) {
  z_stream z = {0};
  if (deflateInit2(&z, 9, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
    return NULL;
  }
  size_t cap = deflateBound(&z, (uLong)n);
  unsigned char *out = malloc(cap);
  z.next_in = (unsigned char *)in;
  z.avail_in = (uInt)n;
  z.next_out = out;
  z.avail_out = (uInt)cap;
  int ok = out && deflate(&z, Z_FINISH) == Z_STREAM_END;
  *out_n = z.total_out;
  deflateEnd(&z);
  if (!ok) {
    free(out);
    return NULL;
  }
  return out;
}

static int visit(const char *path, const struct stat *st, int type,
                 struct FTW *ftw) {
  (void)ftw;
  size_t len = strlen(path);
  if (type != FTW_F || !S_ISREG(st->st_mode) || st->st_size < 256 ||
      (len > 3 && !strcmp(path + len - 3, ".gz")) || !compressible(path)) {
    return 0;
  }
  char gz[4096], tmp[4200];
  struct stat gst;
  if (snprintf(gz, sizeof gz, "%s.gz", path) >= (int)sizeof gz) {
    g_failed++;
    return 0;
  }
  if (lstat(gz, &gst) == 0 && S_ISREG(gst.st_mode) &&
      (gst.st_mtim.tv_sec > st->st_mtim.tv_sec ||
       (gst.st_mtim.tv_sec == st->st_mtim.tv_sec &&
        gst.st_mtim.tv_nsec >= st->st_mtim.tv_nsec))) {
    g_fresh++;
    return 0;
  }
  size_t n = 0, zn = 0;
  unsigned char *in = slurp(path, &n), *z = in ? gzip(in, n, &zn) : NULL;
  free(in);
  if (!z) {
    fprintf(stderr, "cserve-precompress: %s: unreadable\n", path);
    g_failed++;
    return 0;
  }
  if (zn >= n) {
    free(z);
    return 0; /* no smaller: no copy */
  }
  snprintf(tmp, sizeof tmp, "%s.%d.tmp", gz, (int)getpid());
  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  int ok = fd >= 0 && write(fd, z, zn) == (ssize_t)zn;
  if (fd >= 0) {
    ok = close(fd) == 0 && ok;
  }
  free(z);
  if (!ok || rename(tmp, gz) != 0) {
    fprintf(stderr, "cserve-precompress: %s: %s\n", gz, strerror(errno));
    unlink(tmp);
    g_failed++;
    return 0;
  }
  g_made++;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: cserve-precompress ROOT\n");
    return 2;
  }
  if (nftw(argv[1], visit, 32, FTW_PHYS) != 0) {
    fprintf(stderr, "cserve-precompress: %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  printf("%d written, %d fresh already, %d failed\n", g_made, g_fresh,
         g_failed);
  return g_failed ? 1 : 0;
}
