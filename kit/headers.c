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
    [CSERVE_H_WWW_AUTHENTICATE] = "WWW-Authenticate",
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

/* RFC 9110's qdtext: HTAB, SP, and printable ASCII but '"' and '\\' */
static int qdtext(unsigned char c) {
  return c == '\t' || c == ' ' || c == '!' || (c >= '#' && c <= '[') ||
         (c >= ']' && c <= '~');
}

int cserve_basic_challenge(CSERVE_HTTPD_REPLY *rep, const char *realm) {
  if (!*realm) {
    return -1;
  }
  for (const unsigned char *p = (const unsigned char *)realm; *p; p++) {
    if (!qdtext(*p)) {
      return -1;
    }
  }
  char value[1024];
  int n = snprintf(value, sizeof value, "Basic realm=\"%s\"", realm);
  if (n < 0 || (size_t)n >= sizeof value) {
    return -1;
  }
  return cserve_header(rep, CSERVE_H_WWW_AUTHENTICATE, value);
}

int cserve_rawurlencode(const char *s, char *out, size_t cap) {
  static const char HEX[] = "0123456789ABCDEF";
  size_t k = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    int keep = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
               *p == '.' || *p == '~';
    if (k + (keep ? 1 : 3) >= cap) {
      return -1;
    }
    if (keep) {
      out[k++] = (char)*p;
    } else {
      out[k++] = '%';
      out[k++] = HEX[*p >> 4];
      out[k++] = HEX[*p & 15];
    }
  }
  if (k >= cap) {
    return -1;
  }
  out[k] = '\0';
  return 0;
}
