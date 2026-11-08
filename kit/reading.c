#include "reading.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* PHP's trim(): what it takes off both ends by default */
static int trimmed(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0' ||
         c == '\v';
}

/* [*s, *e) with trim()'s characters off both ends */
static void trim(const char **s, const char **e) {
  while (*s < *e && trimmed((unsigned char)**s)) {
    (*s)++;
  }
  while (*e > *s && trimmed((unsigned char)(*e)[-1])) {
    (*e)--;
  }
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int digit(int c) { return c >= '0' && c <= '9'; }

int cserve_utf8_valid(const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s, *e = p + n;
  while (p < e) {
    unsigned c = *p;
    if (c < 0x80) {
      p++;
      continue;
    }
    size_t k = c >= 0xC2 && c <= 0xDF   ? 2
               : c >= 0xE0 && c <= 0xEF ? 3
               : c >= 0xF0 && c <= 0xF4 ? 4
                                        : 0;
    if (!k || (size_t)(e - p) < k) {
      return 0;
    }
    for (size_t i = 1; i < k; i++) {
      if ((p[i] & 0xC0) != 0x80) {
        return 0;
      }
    }
    /* the second byte's range is what rules out overlong forms, the
     * surrogates and what's past U+10FFFF */
    if ((c == 0xE0 && p[1] < 0xA0) || (c == 0xED && p[1] > 0x9F) ||
        (c == 0xF0 && p[1] < 0x90) || (c == 0xF4 && p[1] > 0x8F)) {
      return 0;
    }
    p += k;
  }
  return 1;
}

static int hex(int c) {
  return digit(c)                             ? c - '0'
         : lower(c) >= 'a' && lower(c) <= 'f' ? lower(c) - 'a' + 10
                                              : -1;
}

/* [s, e) decoded into out (cap bytes, NUL-terminated): its length, or -1
 * if it doesn't fit. rawurldecode(str_replace('+', ' ', ...)) */
static long decode(const char *s, const char *e, char *out, size_t cap) {
  size_t n = 0;
  for (const char *p = s; p < e; p++) {
    int c = (unsigned char)*p;
    if (c == '+') {
      c = ' ';
    } else if (c == '%' && e - p >= 3 && hex(p[1]) >= 0 && hex(p[2]) >= 0) {
      c = hex(p[1]) * 16 + hex(p[2]);
      p += 2;
    }
    if (n + 1 >= cap) {
      return -1;
    }
    out[n++] = (char)c;
  }
  out[n] = '\0';
  return (long)n;
}

int cserve_query_get(const char *query, const char *name, char *out, size_t cap,
                     char *err, size_t err_cap) {
  char nbuf[4096], vbuf[4096];
  int found = 0;
  if (cap) {
    out[0] = '\0';
  }
  for (const char *p = query ? query : ""; *p;) {
    const char *end = p + strcspn(p, "&");
    if (end > p) {
      const char *eq = memchr(p, '=', (size_t)(end - p));
      const char *ne = eq ? eq : end, *vs = eq ? eq + 1 : end;
      long nl = decode(p, ne, nbuf, sizeof nbuf);
      long vl = decode(vs, end, vbuf, sizeof vbuf);
      if (nl < 0 || vl < 0) {
        snprintf(err, err_cap, "a query parameter too long to read");
        return -1;
      }
      if (!cserve_utf8_valid(nbuf, (size_t)nl) ||
          !cserve_utf8_valid(vbuf, (size_t)vl)) {
        snprintf(err, err_cap, "something sent does not decode to UTF-8");
        return -1;
      }
      if ((size_t)nl == strlen(name) && !memcmp(nbuf, name, (size_t)nl)) {
        if (found) {
          snprintf(err, err_cap, "'%s' was sent more than once", name);
          return -1;
        }
        if ((size_t)vl >= cap) {
          snprintf(err, err_cap, "'%s' is too long", name);
          return -1;
        }
        memcpy(out, vbuf, (size_t)vl + 1);
        found = 1;
      }
    }
    p = *end ? end + 1 : end;
  }
  return found ? 0 : 1;
}

int cserve_cookie_get(const char *cookie, const char *name, char *out,
                      size_t cap) {
  size_t name_len = strlen(name);
  for (const char *p = cookie ? cookie : "";;) {
    const char *end = p + strcspn(p, ";");
    const char *eq = memchr(p, '=', (size_t)(end - p));
    if (eq) {
      const char *ns = p, *ne = eq;
      trim(&ns, &ne);
      if ((size_t)(ne - ns) == name_len && !memcmp(ns, name, name_len)) {
        const char *vs = eq + 1, *ve = end;
        trim(&vs, &ve);
        if (ve - vs >= 2 && *vs == '"' && ve[-1] == '"') {
          vs++;
          ve--;
        }
        if ((size_t)(ve - vs) >= cap) {
          return -1;
        }
        memcpy(out, vs, (size_t)(ve - vs));
        out[ve - vs] = '\0';
        return 0;
      }
    }
    if (!*end) {
      return 1;
    }
    p = end + 1;
  }
}

/* a weight's text (spaces gone, lower-cased) in thousandths, or -1 past
 * QualityValue's grammar: 0, 0.d{0,3}, 1, 1.0{0,3} */
static int weight(const char *s, size_t n) {
  if (!n || (s[0] != '0' && s[0] != '1')) {
    return -1;
  }
  int w = (s[0] - '0') * 1000;
  if (n == 1) {
    return w;
  }
  if (s[1] != '.' || n > 5) {
    return -1;
  }
  int scale = 100;
  for (size_t i = 2; i < n; i++, scale /= 10) {
    if (!digit(s[i]) || (s[0] == '1' && s[i] != '0')) {
      return -1;
    }
    w += (s[i] - '0') * scale;
  }
  return w;
}

/* an entry's parameters [s, e) (each after a ';'): its weight in
 * thousandths, 1000 when none says, -1 when one past the grammar does --
 * the last q= said is the one that counts */
static int entry_weight(const char *s, const char *e) {
  int w = 1000;
  while (s < e) {
    const char *pe = memchr(s, ';', (size_t)(e - s));
    pe = pe ? pe : e;
    char buf[64];
    size_t n = 0;
    int whole = 1;
    for (const char *p = s; p < pe; p++) {
      if (*p == ' ') {
        continue;
      }
      if (n < sizeof buf) {
        buf[n++] = (char)lower((unsigned char)*p);
      } else {
        whole = 0;
      }
    }
    if (n >= 2 && buf[0] == 'q' && buf[1] == '=') {
      int q = whole ? weight(buf + 2, n - 2) : -1;
      if (q < 0) {
        return -1;
      }
      w = q;
    }
    s = pe < e ? pe + 1 : e;
  }
  return w;
}

#define OFFERED_MAX 16

int cserve_accept_language(const char *header, const char *const *offered,
                           int n) {
  /* what each offered language and "*" are worth: -1 not named */
  int worth[OFFERED_MAX + 1];
  n = n > OFFERED_MAX ? OFFERED_MAX : n;
  for (int i = 0; i <= n; i++) {
    worth[i] = -1;
  }
  for (const char *p = header ? header : "";;) {
    const char *end = p + strcspn(p, ",");
    const char *semi = memchr(p, ';', (size_t)(end - p));
    const char *rs = p, *re = semi ? semi : end;
    trim(&rs, &re);
    int q = entry_weight(semi ? semi + 1 : end, end);
    /* the primary subtag: "*", or 1-8 letters */
    const char *pe = memchr(rs, '-', (size_t)(re - rs));
    pe = pe ? pe : re;
    size_t len = (size_t)(pe - rs);
    int ok = q >= 0 && re > rs && len >= 1 && len <= 8;
    for (const char *c = rs; ok && c < pe; c++) {
      int l = lower((unsigned char)*c);
      ok = (l >= 'a' && l <= 'z') || (len == 1 && l == '*');
    }
    if (ok) {
      int slot = -1;
      if (len == 1 && *rs == '*') {
        slot = n;
      }
      for (int i = 0; i < n && slot < 0; i++) {
        if (strlen(offered[i]) == len && !strncasecmp(offered[i], rs, len)) {
          slot = i;
        }
      }
      if (slot >= 0 && q > worth[slot]) {
        worth[slot] = q;
      }
    }
    if (!*end) {
      break;
    }
    p = end + 1;
  }
  int best = 0, best_worth = 0;
  for (int i = 0; i < n; i++) {
    int w = worth[i] >= 0 ? worth[i] : worth[n] >= 0 ? worth[n] : 0;
    if (w > best_worth) {
      best = i;
      best_worth = w;
    }
  }
  return best;
}

int cserve_etag_matches(const char *if_none_match, const char *fingerprint) {
  if (!if_none_match) {
    return 0;
  }
  const char *s = if_none_match, *e = s + strlen(s);
  trim(&s, &e);
  if (e - s == 1 && *s == '*') {
    return 1;
  }
  static const char *const SUFFIX[] = {"-gzip", "-br", "-deflate"};
  size_t fl = strlen(fingerprint);
  for (const char *p = if_none_match; (p = strchr(p, '"'));) {
    const char *open = p + 1, *close = strchr(open, '"');
    if (!close) {
      break;
    }
    size_t n = (size_t)(close - open);
    for (size_t i = 0; i < sizeof SUFFIX / sizeof *SUFFIX; i++) {
      size_t sl = strlen(SUFFIX[i]);
      if (n >= sl && !memcmp(close - sl, SUFFIX[i], sl)) {
        n -= sl;
        break;
      }
    }
    if (n == fl && !memcmp(open, fingerprint, fl)) {
      return 1;
    }
    p = close + 1;
  }
  return 0;
}

int cserve_requested_xhr(const CSERVE_HTTPD_REQ *r) {
  const char *v = cserve_httpd_header(r, "X-Requested-With");
  return v && !strcasecmp(v, "XMLHttpRequest");
}

/* the digits at *p as a number, *p moved past them: 0, or -1 past what a
 * long long holds (PHP's 0 + "..." turning into a float) */
static int number(const char **p, const char *e, long long *out) {
  long long v = 0;
  for (; *p < e && digit(**p); (*p)++) {
    int d = **p - '0';
    if (v > (LLONG_MAX - d) / 10) {
      return -1;
    }
    v = v * 10 + d;
  }
  *out = v;
  return 0;
}

CSERVE_RANGE cserve_range(const char *header, long long size, long long *first,
                          long long *last) {
  if (!header) {
    return CSERVE_RANGE_NONE;
  }
  const char *s = header, *e = s + strlen(s);
  trim(&s, &e);
  if (e - s < 6 || strncasecmp(s, "bytes=", 6)) {
    return CSERVE_RANGE_NONE;
  }
  s += 6;
  long long a, b;
  if (s < e && *s == '-') {
    const char *d = ++s;
    if (number(&s, e, &a) != 0 || s == d || s != e) {
      return CSERVE_RANGE_NONE;
    }
    if (a == 0) {
      return CSERVE_RANGE_UNSATISFIED;
    }
    if (size == 0) {
      return CSERVE_RANGE_NONE;
    }
    *first = size - a > 0 ? size - a : 0;
    *last = size - 1;
    return CSERVE_RANGE_PARTIAL;
  }
  const char *d = s;
  if (number(&s, e, &a) != 0 || s == d || s == e || *s++ != '-') {
    return CSERVE_RANGE_NONE;
  }
  d = s;
  if (number(&s, e, &b) != 0 || s != e) {
    return CSERVE_RANGE_NONE;
  }
  int open = s == d;
  if (!open && b < a) {
    return CSERVE_RANGE_NONE;
  }
  b = open || b > size - 1 ? size - 1 : b;
  if (a > b || a >= size || size <= 0) {
    return CSERVE_RANGE_UNSATISFIED;
  }
  *first = a;
  *last = b;
  return CSERVE_RANGE_PARTIAL;
}

/* a base64 digit's value, -1 for the whitespace strict base64_decode()
 * steps over, -2 for anything else */
static int b64(unsigned char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+' || c == '/') {
    return c == '+' ? 62 : 63;
  }
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' ? -1 : -2;
}

/* s[0, n) through base64_decode($s, true) into out (n bytes hold it):
 * its length, or -1 where PHP answers false */
static long b64_strict(const char *s, size_t n, unsigned char *out) {
  size_t i = 0, pad = 0, j = 0;
  for (size_t k = 0; k < n; k++) {
    if (s[k] == '=') {
      pad++;
      continue;
    }
    int v = b64((unsigned char)s[k]);
    if (v == -1) {
      continue;
    }
    if (v == -2 || pad) {
      return -1;
    }
    switch (i % 4) {
    case 0:
      out[j] = (unsigned char)(v << 2);
      break;
    case 1:
      out[j++] |= (unsigned char)(v >> 4);
      out[j] = (unsigned char)((v & 0x0f) << 4);
      break;
    case 2:
      out[j++] |= (unsigned char)(v >> 2);
      out[j] = (unsigned char)((v & 0x03) << 6);
      break;
    default:
      out[j++] |= (unsigned char)v;
      break;
    }
    i++;
  }
  if (i % 4 == 1 || (pad && (pad > 2 || (i + pad) % 4 != 0))) {
    return -1;
  }
  return (long)j;
}

int cserve_basic_credentials(const char *authorization, char *user,
                             size_t user_cap, char *pass, size_t pass_cap) {
  user[0] = pass[0] = '\0';
  if (!authorization || strncasecmp(authorization, "basic ", 6) != 0) {
    return 1;
  }
  const char *s = authorization + 5;
  while (*s == ' ') {
    s++;
  }
  size_t n = strlen(s);
  unsigned char buf[1024];
  if (n > sizeof buf) {
    return 1;
  }
  long len = b64_strict(s, n, buf);
  if (len < 0 || memchr(buf, '\0', (size_t)len)) {
    return 1;
  }
  const unsigned char *colon = memchr(buf, ':', (size_t)len);
  size_t ul = colon ? (size_t)(colon - buf) : (size_t)len;
  size_t pl = colon ? (size_t)len - ul - 1 : 0;
  if (ul >= user_cap || pl >= pass_cap) {
    return 1;
  }
  memcpy(user, buf, ul);
  user[ul] = '\0';
  memcpy(pass, colon ? colon + 1 : buf, pl);
  pass[pl] = '\0';
  return 0;
}

long cserve_b64url_decode(const char *s, unsigned char *out, size_t cap) {
  size_t n = strlen(s), o = 0;
  if (n % 4 == 1) {
    return -1;
  }
  unsigned acc = 0;
  int bits = 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    int v = c >= 'A' && c <= 'Z'   ? c - 'A'
            : c >= 'a' && c <= 'z' ? c - 'a' + 26
            : c >= '0' && c <= '9' ? c - '0' + 52
            : c == '-'             ? 62
            : c == '_'             ? 63
                                   : -1;
    if (v < 0) {
      return -1;
    }
    acc = (acc << 6 | (unsigned)v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o == cap) {
        return -1;
      }
      out[o++] = (unsigned char)(acc >> bits);
    }
  }
  /* what's left over must be zero bits: one spelling per value */
  if (bits && (acc & ((1u << bits) - 1))) {
    return -1;
  }
  return (long)o;
}
