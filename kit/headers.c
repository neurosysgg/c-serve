#include "headers.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *const NAMES[CSERVE_H_COUNT] = {
    [CSERVE_H_CONTENT_LANGUAGE] = "Content-Language",
    [CSERVE_H_CACHE_CONTROL] = "Cache-Control",
    [CSERVE_H_ETAG] = "ETag",
    [CSERVE_H_VARY] = "Vary",
    [CSERVE_H_ALLOW] = "Allow",
    [CSERVE_H_LOCATION] = "Location",
    [CSERVE_H_SET_COOKIE] = "Set-Cookie",
    [CSERVE_H_CONTENT_RANGE] = "Content-Range",
    [CSERVE_H_ACCEPT_RANGES] = "Accept-Ranges",
    [CSERVE_H_X_ROBOTS_TAG] = "X-Robots-Tag",
};

const char *cserve_header_name(CSERVE_HEADER h) {
  return h >= 0 && h < CSERVE_H_COUNT ? NAMES[h] : "";
}

int cserve_header(CSERVE_HTTPD_REPLY *rep, CSERVE_HEADER h, const char *value) {
  if (h < 0 || h >= CSERVE_H_COUNT || strpbrk(value, "\r\n")) {
    return -1;
  }
  size_t used = strlen(rep->headers);
  int n = snprintf(rep->headers + used, sizeof rep->headers - used,
                   "%s: %s\r\n", NAMES[h], value);
  if (n < 0 || (size_t)n >= sizeof rep->headers - used) {
    rep->headers[used] = '\0';
    return -1;
  }
  return 0;
}

int cserve_header_has(const CSERVE_HTTPD_REPLY *rep, CSERVE_HEADER h) {
  if (h < 0 || h >= CSERVE_H_COUNT) {
    return 0;
  }
  size_t nl = strlen(NAMES[h]);
  for (const char *p = rep->headers; *p;) {
    if (!strncasecmp(p, NAMES[h], nl) && p[nl] == ':') {
      return 1;
    }
    const char *e = strstr(p, "\r\n");
    if (!e) {
      break;
    }
    p = e + 2;
  }
  return 0;
}

const char *cserve_cache_value(CSERVE_CACHE c) {
  return c == CSERVE_CACHE_NO_STORE ? "no-store, private" : "no-cache";
}
