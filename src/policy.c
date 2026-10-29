#include "policy.h"

#include <stdio.h>
#include <string.h>

typedef struct {
  char *s;
  size_t len, cap;
  int over;
  int directives; /* written into the CSP so far */
} OUT;

static void add(OUT *o, const char *s) {
  size_t n = strlen(s);
  if (o->over || o->len + n >= o->cap) {
    o->over = 1;
    return;
  }
  memcpy(o->s + o->len, s, n + 1);
  o->len += n;
}

/* "; name 'self' host ..." for one directive of the CSP, its sources
 * checked: 0, or -1 */
static int directive(OUT *o, const char *name, const char *own,
                     const char *const *hosts, char *err, size_t err_cap) {
  if (o->directives++) {
    add(o, "; ");
  }
  add(o, name);
  if (own) {
    add(o, " ");
    add(o, own);
  }
  for (int i = 0; hosts && hosts[i]; i++) {
    if (!*hosts[i] || strpbrk(hosts[i], " ;,'\"\r\n\t")) {
      snprintf(err, err_cap, "\"%s\" isn't a source a %s can name", hosts[i],
               name);
      return -1;
    }
    add(o, " ");
    add(o, hosts[i]);
  }
  return 0;
}

int cserve_security_headers(const CSERVE_SECURITY *p, char *out, size_t cap,
                            char *err, size_t err_cap) {
  static const CSERVE_SECURITY NONE = {0};
  p = p ? p : &NONE;
  OUT o = {.s = out, .cap = cap};
  if (cap) {
    out[0] = '\0';
  }
  add(&o, "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
          "Content-Security-Policy: ");
  int bad =
      directive(&o, "default-src", "'self'", NULL, err, err_cap) ||
      directive(&o, "script-src", "'self'", p->script, err, err_cap) ||
      directive(&o, "style-src", "'self'", p->style, err, err_cap) ||
      directive(&o, "img-src", "'self'", p->img, err, err_cap) ||
      directive(&o, "frame-src", p->frame && p->frame[0] ? NULL : "'none'",
                p->frame, err, err_cap) ||
      (p->connect && p->connect[0] &&
       directive(&o, "connect-src", "'self'", p->connect, err, err_cap)) ||
      (p->media && p->media[0] &&
       directive(&o, "media-src", "'self'", p->media, err, err_cap)) ||
      (p->font && p->font[0] &&
       directive(&o, "font-src", "'self'", p->font, err, err_cap)) ||
      directive(&o, "base-uri", "'self'", NULL, err, err_cap) ||
      directive(&o, "form-action", "'self'", NULL, err, err_cap) ||
      directive(&o, "frame-ancestors", "'none'", NULL, err, err_cap) ||
      directive(&o, "object-src", "'none'", NULL, err, err_cap);
  if (bad) {
    out[0] = '\0';
    return -1;
  }
  add(&o, "\r\n"
          "Referrer-Policy: strict-origin-when-cross-origin\r\n"
          "X-Content-Type-Options: nosniff\r\n"
          "Permissions-Policy: geolocation=(), camera=(), microphone=(), "
          "payment=(), usb=(), midi=()\r\n"
          "Cross-Origin-Opener-Policy: same-origin\r\n"
          "Cross-Origin-Resource-Policy: same-origin\r\n");
  if (o.over) {
    snprintf(err, err_cap, "the security headers outgrow %zu bytes", cap);
    if (cap) {
      out[0] = '\0';
    }
    return -1;
  }
  return 0;
}
