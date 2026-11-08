/* server-sent events (sse.h) */
#include "sse.h"

#include "headers.h"

#include <stdio.h>
#include <string.h>

static int name_ok(const char *s) {
  size_t n = strlen(s);
  if (n == 0 || n > 32) {
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_')) {
      return 0;
    }
  }
  return 1;
}

long cserve_sse_event(char *out, size_t cap, long long id, const char *event,
                      const char *data, size_t n) {
  if ((event && !name_ok(event)) || memchr(data, '\0', n)) {
    return -1;
  }
  size_t o = 0;
#define PUT(p, k)                                                              \
  do {                                                                         \
    if (o + (k) >= cap) {                                                      \
      return -1;                                                               \
    }                                                                          \
    memcpy(out + o, (p), (k));                                                 \
    o += (k);                                                                  \
  } while (0)
  char head[96];
  int h = 0;
  if (id >= 0) {
    h = snprintf(head, sizeof head, "id: %lld\n", id);
    PUT(head, (size_t)h);
  }
  if (event) {
    h = snprintf(head, sizeof head, "event: %s\n", event);
    PUT(head, (size_t)h);
  }
  /* each line of data its own field: CR, LF and CRLF all end one */
  size_t at = 0;
  for (;;) {
    size_t e = at;
    while (e < n && data[e] != '\n' && data[e] != '\r') {
      e++;
    }
    PUT("data: ", 6);
    PUT(data + at, e - at);
    PUT("\n", 1);
    if (e >= n) {
      break;
    }
    at = e + (data[e] == '\r' && e + 1 < n && data[e + 1] == '\n' ? 2 : 1);
    if (at >= n) {
      break; /* a break at the very end ends the last line, no more */
    }
  }
  PUT("\n", 1);
#undef PUT
  out[o] = '\0';
  return (long)o;
}

int cserve_sse_last_id(const CSERVE_HTTPD_REQ *r, long long *id) {
  const char *v = cserve_httpd_header(r, "Last-Event-ID");
  if (!v || !*v || strspn(v, "0123456789") != strlen(v) || strlen(v) > 16) {
    return 0;
  }
  long long n = 0;
  for (const char *p = v; *p; p++) {
    n = n * 10 + (*p - '0');
  }
  if (n > (1LL << 53)) {
    return 0;
  }
  *id = n;
  return 1;
}

void cserve_sse_reply(CSERVE_HTTPD_REPLY *rep,
                      long (*pull)(void *ud, char *buf, size_t cap),
                      void (*done)(void *ud),
                      void (*opened)(void *ud, CSERVE_STREAM s), void *ud) {
  rep->status = 200;
  rep->type = "text/event-stream; charset=utf-8";
  rep->pull = pull;
  rep->done = done;
  rep->opened = opened;
  rep->pull_ud = ud;
  rep->stream = 1;
  (void)cserve_header(rep, CSERVE_H_CACHE_CONTROL, "no-store");
}
