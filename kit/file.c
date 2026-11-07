#define _POSIX_C_SOURCE 200809L
#include "file.h"

#include "headers.h"
#include "reading.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  int fd;
  long long at, left;
} PART;

/* the range out, a block at a time: -1 when the file gives fewer bytes
 * than were promised (it shrank) or the client went */
static int send_part(CSERVE_HTTPD_OUT *o, void *ud) {
  PART *p = ud;
  char buf[65536];
  int ret = 0;
  while (p->left > 0) {
    size_t want =
        p->left < (long long)sizeof buf ? (size_t)p->left : sizeof buf;
    ssize_t got = pread(p->fd, buf, want, (off_t)p->at);
    if (got <= 0 || cserve_httpd_out(o, buf, (size_t)got) != 0) {
      ret = -1;
      break;
    }
    p->at += got;
    p->left -= got;
  }
  close(p->fd);
  free(p);
  return ret;
}

int cserve_file_reply(const CSERVE_HTTPD_REQ *r, const char *path,
                      const char *type, CSERVE_HTTPD_REPLY *rep) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  struct stat st;
  if (fd < 0) {
    return -1;
  }
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return -1;
  }
  long long size = st.st_size, first = 0, last = size - 1;
  /* Range is a GET's alone (Request::range()) */
  CSERVE_RANGE range =
      strcmp(r->method, "GET") == 0
          ? cserve_range(cserve_httpd_header(r, "Range"), size, &first, &last)
          : CSERVE_RANGE_NONE;
  long long length = range == CSERVE_RANGE_PARTIAL       ? last - first + 1
                     : range == CSERVE_RANGE_UNSATISFIED ? 0
                                                         : size;
  char value[80];
  if (range == CSERVE_RANGE_PARTIAL) {
    snprintf(value, sizeof value, "bytes %lld-%lld/%lld", first, last, size);
  } else {
    snprintf(value, sizeof value, "bytes */%lld", size);
  }
  if (cserve_header(rep, CSERVE_H_ACCEPT_RANGES, "bytes") != 0 ||
      cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                    cserve_cache_value(CSERVE_CACHE_NO_STORE)) != 0 ||
      (range != CSERVE_RANGE_NONE &&
       cserve_header(rep, CSERVE_H_CONTENT_RANGE, value) != 0)) {
    close(fd);
    rep->headers[0] = '\0';
    cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
    return -1;
  }
  int status = range == CSERVE_RANGE_PARTIAL       ? 206
               : range == CSERVE_RANGE_UNSATISFIED ? 416
                                                   : 200;
  PART *p = length > 0 ? malloc(sizeof *p) : NULL;
  if (!p) {
    close(fd);
    if (length > 0) {
      rep->headers[0] = '\0';
      cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
      return -1;
    }
    cserve_httpd_text(rep, status, type, "", 0);
    return 0;
  }
  *p = (PART){fd, first, length};
  rep->status = status;
  rep->type = type;
  rep->stream = send_part;
  rep->stream_ud = p;
  rep->stream_length = length;
  return 0;
}
