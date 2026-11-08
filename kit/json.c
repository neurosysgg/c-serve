/* strtod_l()/newlocale() are GNU/POSIX, not C11 */
#define _GNU_SOURCE

#include "json.h"

#include "arena.h"

#include "reading.h"

#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64

typedef struct {
  const char *p;
  const char *start;
  char *err;
  size_t err_cap;
  int failed;
} PARSER;

static void fail(PARSER *ps, const char *what) {
  if (ps->failed) {
    return;
  }
  ps->failed = 1;
  int line = 1, col = 1;
  for (const char *c = ps->start; c < ps->p; c++) {
    if (*c == '\n') {
      line++;
      col = 1;
    } else {
      col++;
    }
  }
  snprintf(ps->err, ps->err_cap, "line %d, col %d: %s", line, col, what);
}

static void skip_ws(PARSER *ps) {
  while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r') {
    ps->p++;
  }
}

static int hex4(const char *s, unsigned *out) {
  *out = 0;
  for (int i = 0; i < 4; i++) {
    char c = s[i];
    unsigned d;
    if (c >= '0' && c <= '9') {
      d = (unsigned)(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      d = (unsigned)(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      d = (unsigned)(c - 'A' + 10);
    } else {
      return 0;
    }
    *out = *out * 16 + d;
  }
  return 1;
}

/* cp as UTF-8 into out: how many bytes (a surrogate is U+FFFD's three) */
static int utf8(unsigned cp, char *out) {
  if (cp >= 0xD800 && cp <= 0xDFFF) {
    cp = 0xFFFD;
  }
  if (cp < 0x80) {
    out[0] = (char)cp;
    return 1;
  }
  if (cp < 0x800) {
    out[0] = (char)(0xC0 | cp >> 6);
    out[1] = (char)(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    out[0] = (char)(0xE0 | cp >> 12);
    out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
  }
  out[0] = (char)(0xF0 | cp >> 18);
  out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
  out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
  out[3] = (char)(0x80 | (cp & 0x3F));
  return 4;
}

/* the decoded string is never longer than its escaped source (a lone
 * surrogate's six bytes become three), so one allocation of the source
 * span is always enough */
static char *parse_string(PARSER *ps) {
  ps->p++; /* opening quote */
  const char *end = ps->p;
  while (*end && *end != '"') {
    end += (*end == '\\' && end[1]) ? 2 : 1;
  }
  if (*end != '"') {
    fail(ps, "unterminated string");
    return NULL;
  }
  char *out = malloc((size_t)(end - ps->p) + 1);
  if (!out) {
    fail(ps, "out of memory");
    return NULL;
  }
  size_t n = 0;
  while (ps->p < end) {
    char c = *ps->p++;
    if ((unsigned char)c < 0x20) {
      fail(ps, "raw control character in string");
      free(out);
      return NULL;
    }
    if (c != '\\') {
      out[n++] = c;
      continue;
    }
    char e = *ps->p++;
    switch (e) {
    case '"':
    case '\\':
    case '/':
      out[n++] = e;
      break;
    case 'b':
      out[n++] = '\b';
      break;
    case 'f':
      out[n++] = '\f';
      break;
    case 'n':
      out[n++] = '\n';
      break;
    case 'r':
      out[n++] = '\r';
      break;
    case 't':
      out[n++] = '\t';
      break;
    case 'u': {
      unsigned cp;
      if (!hex4(ps->p, &cp)) {
        fail(ps, "bad \\u escape");
        free(out);
        return NULL;
      }
      ps->p += 4;
      unsigned lo;
      if (cp >= 0xD800 && cp <= 0xDBFF && ps->p[0] == '\\' && ps->p[1] == 'u' &&
          hex4(ps->p + 2, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        ps->p += 6;
      }
      /* a C string would end at a NUL, silently dropping the rest */
      n += (size_t)utf8(cp ? cp : 0xFFFD, out + n);
      break;
    }
    default:
      fail(ps, "unknown escape in string");
      free(out);
      return NULL;
    }
  }
  out[n] = '\0';
  if (!cserve_utf8_valid(out, n)) {
    fail(ps, "a string that isn't UTF-8");
    free(out);
    return NULL;
  }
  ps->p = end + 1;
  return out;
}

static int digit(char c) { return c >= '0' && c <= '9'; }

static size_t digits(const char *s) {
  size_t n = 0;
  while (digit(s[n])) {
    n++;
  }
  return n;
}

static void parse_value(PARSER *ps, CSERVE_JSON *v, int depth);

static int push_item(PARSER *ps, CSERVE_JSON *v, int *cap) {
  if (v->count == *cap) {
    int ncap = *cap ? *cap * 2 : 4;
    CSERVE_JSON *items = realloc(v->items, (size_t)ncap * sizeof *items);
    if (items) {
      v->items = items;
    }
    char **keys = v->type == CSERVE_JSON_OBJECT && items
                      ? realloc(v->keys, (size_t)ncap * sizeof *keys)
                      : v->keys;
    if (!items || (v->type == CSERVE_JSON_OBJECT && !keys)) {
      fail(ps, "out of memory");
      return -1;
    }
    v->keys = keys;
    *cap = ncap;
  }
  memset(&v->items[v->count], 0, sizeof v->items[0]);
  if (v->keys) {
    v->keys[v->count] = NULL;
  }
  v->count++;
  return 0;
}

static void parse_container(PARSER *ps, CSERVE_JSON *v, int depth) {
  int is_obj = *ps->p == '{';
  char close = is_obj ? '}' : ']';
  v->type = is_obj ? CSERVE_JSON_OBJECT : CSERVE_JSON_ARRAY;
  ps->p++;
  skip_ws(ps);
  if (*ps->p == close) {
    ps->p++;
    return;
  }
  int cap = 0;
  for (;;) {
    skip_ws(ps);
    if (push_item(ps, v, &cap) != 0) {
      return;
    }
    if (is_obj) {
      if (*ps->p != '"') {
        fail(ps, "expected a \"key\"");
        return;
      }
      char *key = parse_string(ps);
      v->keys[v->count - 1] = key;
      if (ps->failed) {
        return;
      }
      for (int i = 0; i < v->count - 1; i++) {
        if (strcmp(v->keys[i], key) == 0) {
          fail(ps, "a key said twice");
          return;
        }
      }
      skip_ws(ps);
      if (*ps->p != ':') {
        fail(ps, "expected ':' after key");
        return;
      }
      ps->p++;
    }
    parse_value(ps, &v->items[v->count - 1], depth + 1);
    if (ps->failed) {
      return;
    }
    skip_ws(ps);
    if (*ps->p == close) {
      ps->p++;
      return;
    }
    if (*ps->p != ',') {
      fail(ps, is_obj ? "expected ',' or '}'" : "expected ',' or ']'");
      return;
    }
    ps->p++;
  }
}

static void parse_number(PARSER *ps, CSERVE_JSON *v) {
  /* JSON's grammar first: strtod alone takes hex, inf, nan, 01 and 1. */
  const char *q = ps->p + (*ps->p == '-');
  int ok = digit(*q);
  q += *q == '0' ? 1 : digits(q);
  ok = ok && !digit(*q);
  if (ok && *q == '.') {
    q++;
    ok = digit(*q);
    q += digits(q);
  }
  if (ok && (*q == 'e' || *q == 'E')) {
    q += q[1] == '+' || q[1] == '-' ? 2 : 1;
    ok = digit(*q);
    q += digits(q);
  }
  /* in the C locale: under a comma-decimal LC_NUMERIC plain strtod would
   * stop at the "." */
  locale_t c_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  char *end = NULL;
  v->type = CSERVE_JSON_NUMBER;
  v->number = !ok        ? 0
              : c_locale ? strtod_l(ps->p, &end, c_locale)
                         : strtod(ps->p, &end);
  if (c_locale) {
    freelocale(c_locale);
  }
  if (!ok || end != q) {
    fail(ps, "invalid number");
  } else if (!isfinite(v->number)) {
    fail(ps, "number out of range");
  } else {
    ps->p = q;
  }
}

static void parse_value(PARSER *ps, CSERVE_JSON *v, int depth) {
  if (depth > MAX_DEPTH) {
    fail(ps, "nesting too deep");
    return;
  }
  skip_ws(ps);
  char c = *ps->p;
  if (c == '{' || c == '[') {
    parse_container(ps, v, depth);
  } else if (c == '"') {
    v->type = CSERVE_JSON_STRING;
    v->string = parse_string(ps);
  } else if (strncmp(ps->p, "true", 4) == 0) {
    v->type = CSERVE_JSON_BOOL;
    v->boolean = 1;
    ps->p += 4;
  } else if (strncmp(ps->p, "false", 5) == 0) {
    v->type = CSERVE_JSON_BOOL;
    ps->p += 5;
  } else if (strncmp(ps->p, "null", 4) == 0) {
    v->type = CSERVE_JSON_NULL;
    ps->p += 4;
  } else if (c == '-' || digit(c)) {
    parse_number(ps, v);
  } else {
    fail(ps, c ? "unexpected character" : "unexpected end of input");
  }
}

CSERVE_JSON *cserve_json_parse(const char *text, char *err, size_t err_cap) {
  PARSER ps = {.p = text, .start = text, .err = err, .err_cap = err_cap};
  CSERVE_JSON *root = calloc(1, sizeof *root);
  if (!root) {
    snprintf(err, err_cap, "out of memory");
    return NULL;
  }
  parse_value(&ps, root, 0);
  skip_ws(&ps);
  if (!ps.failed && *ps.p) {
    fail(&ps, "trailing content after the top-level value");
  }
  if (ps.failed) {
    cserve_json_free(root);
    return NULL;
  }
  return root;
}

static void free_inner(CSERVE_JSON *v) {
  free(v->string);
  for (int i = 0; i < v->count; i++) {
    free_inner(&v->items[i]);
    if (v->keys) {
      free(v->keys[i]);
    }
  }
  free(v->items);
  free(v->keys);
}

void cserve_json_free(CSERVE_JSON *v) {
  if (v) {
    free_inner(v);
    free(v);
  }
}

const CSERVE_JSON *cserve_json_get(const CSERVE_JSON *v, const char *key) {
  if (!v || v->type != CSERVE_JSON_OBJECT) {
    return NULL;
  }
  for (int i = 0; i < v->count; i++) {
    if (v->keys[i] && strcmp(v->keys[i], key) == 0) {
      return &v->items[i];
    }
  }
  return NULL;
}

const char *cserve_json_str(const CSERVE_JSON *v) {
  return v && v->type == CSERVE_JSON_STRING ? v->string : NULL;
}

int cserve_json_whole(const CSERVE_JSON *v, long long lo, long long hi,
                      long long *out) {
  if (!v || v->type != CSERVE_JSON_NUMBER || v->number != floor(v->number) ||
      v->number < (double)lo || v->number > (double)hi) {
    return -1;
  }
  *out = (long long)v->number;
  return 0;
}

/* --- writing --- */

long cserve_json_quote(const char *s, char *out, size_t cap) {
  size_t o = 0;
  if (cap < 3) {
    return -1;
  }
  out[o++] = '"';
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    char esc[8];
    size_t k;
    if (*p == '"' || *p == '\\') {
      esc[0] = '\\';
      esc[1] = (char)*p;
      k = 2;
    } else if (*p < 0x20 || *p == 0x7f) {
      k = (size_t)snprintf(esc, sizeof esc, "\\u%04x", *p);
    } else {
      esc[0] = (char)*p;
      k = 1;
    }
    if (o + k + 2 > cap) {
      return -1;
    }
    memcpy(out + o, esc, k);
    o += k;
  }
  out[o++] = '"';
  out[o] = '\0';
  return (long)o;
}

const char *cserve_json_string(CSERVE_ARENA *a, const char *s) {
  size_t cap = strlen(s) * 6 + 3; /* every byte \u00XX at worst */
  char *out = cserve_arena_alloc(a, cap);
  if (!out || cserve_json_quote(s, out, cap) < 0) {
    return "\"\"";
  }
  return out;
}
