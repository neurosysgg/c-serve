/* Set-Cookie, one way (cookie.h) */
#include "cookie.h"

#include "headers.h"

#include <stdio.h>
#include <string.h>

int cserve_cookie_name_ok(const char *s) {
  /* a token: visible ASCII but the separators */
  static const char SEPARATORS[] = "()<>@,;:\\\"/[]?={} \t";
  if (!*s) {
    return 0;
  }
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p <= 0x20 || *p >= 0x7f || strchr(SEPARATORS, *p)) {
      return 0;
    }
  }
  return 1;
}

int cserve_cookie_value_ok(const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    /* cookie-octet: %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E */
    if (c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\') {
      return 0;
    }
  }
  return 1;
}

static int set(CSERVE_HTTPD_REPLY *rep, const char *name, const char *value,
               const char *age, CSERVE_SAMESITE same, unsigned flags) {
  if (!cserve_cookie_name_ok(name) ||
      !cserve_cookie_value_ok(value, strlen(value))) {
    return -1;
  }
  char line[4096];
  int n = snprintf(line, sizeof line, "%s=%s; %sPath=/; Secure%s; SameSite=%s",
                   name, value, age,
                   flags & CSERVE_COOKIE_SCRIPT ? "" : "; HttpOnly",
                   same == CSERVE_SAMESITE_LAX ? "Lax" : "Strict");
  if (n < 0 || (size_t)n >= sizeof line) {
    return -1;
  }
  return cserve_header(rep, CSERVE_H_SET_COOKIE, line);
}

int cserve_cookie_set(CSERVE_HTTPD_REPLY *rep, const char *name,
                      const char *value, long max_age, CSERVE_SAMESITE same,
                      unsigned flags) {
  char age[32] = "";
  if (max_age >= 0) {
    snprintf(age, sizeof age, "Max-Age=%ld; ", max_age);
  }
  return set(rep, name, value, age, same, flags);
}

int cserve_cookie_clear(CSERVE_HTTPD_REPLY *rep, const char *name,
                        CSERVE_SAMESITE same) {
  return set(rep, name, "", "Max-Age=0; ", same, 0);
}
