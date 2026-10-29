#include "markup.h"

#include "html.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef enum { N_ELEMENT, N_TEXT, N_TR, N_FRAGMENT, N_DOCUMENT } KIND;

typedef struct {
  const CSERVE_ATTR *attr;
  const char *value;   /* or */
  const CSERVE_TR *tr; /* or neither: written bare */
} ATTRV;

struct CSERVE_NODE {
  KIND kind;
  const CSERVE_TAG *tag; /* an element's */
  const ATTRV *attrs;    /* an element's, in the order set */
  int nattrs;
  const CSERVE_NODE *const *kids; /* an element's, a fragment's */
  int nkids;
  const char *s;           /* a text's */
  const CSERVE_TR *tr;     /* a translatable's */
  const CSERVE_NODE *html; /* a document's */
};

static CSERVE_NODE NOTHING = {.kind = N_FRAGMENT};

CSERVE_NODE *cserve_nothing(void) { return &NOTHING; }

static CSERVE_NODE *node(CSERVE_ARENA *a, KIND kind) {
  CSERVE_NODE *n = cserve_arena_alloc(a, sizeof *n);
  if (!n) {
    return &NOTHING;
  }
  n->kind = kind;
  return n;
}

CSERVE_NODE *cserve_el(CSERVE_ARENA *a, const CSERVE_TAG *tag) {
  CSERVE_NODE *n = node(a, N_ELEMENT);
  if (n != &NOTHING) {
    n->tag = tag;
  }
  return n;
}

/* el's copy (its arrays shared until a builder replaces one) */
static CSERVE_NODE *copy(CSERVE_ARENA *a, const CSERVE_NODE *el,
                         const char *what) {
  if (el->kind != N_ELEMENT) {
    if (el != &NOTHING) {
      cserve_arena_fail(a, "%s on a node that isn't an element", what);
    }
    return &NOTHING;
  }
  CSERVE_NODE *n = cserve_arena_alloc(a, sizeof *n);
  if (!n) {
    return &NOTHING;
  }
  *n = *el;
  return n;
}

/* el with v set: where an attribute of its name was, or last; v.attr NULL
 * after the name: taken away */
static CSERVE_NODE *set(CSERVE_ARENA *a, const CSERVE_NODE *el,
                        const CSERVE_ATTR *attr, ATTRV v, int remove) {
  CSERVE_NODE *n = copy(a, el, "an attribute");
  if (n == &NOTHING) {
    return n;
  }
  ATTRV *attrs =
      cserve_arena_alloc(a, (size_t)(el->nattrs + 1) * sizeof *attrs);
  if (!attrs) {
    return &NOTHING;
  }
  int k = 0, placed = 0;
  for (int i = 0; i < el->nattrs; i++) {
    if (strcmp(el->attrs[i].attr->name, attr->name)) {
      attrs[k++] = el->attrs[i];
    } else if (!remove && !placed) {
      attrs[k++] = v;
      placed = 1;
    }
  }
  if (!remove && !placed) {
    attrs[k++] = v;
  }
  n->attrs = attrs;
  n->nattrs = k;
  return n;
}

CSERVE_NODE *cserve_attr(CSERVE_ARENA *a, const CSERVE_NODE *el,
                         const CSERVE_ATTR *attr, const char *value) {
  return set(a, el, attr,
             (ATTRV){.attr = attr, .value = cserve_arena_strdup(a, value)}, 0);
}

CSERVE_NODE *cserve_attr_tr(CSERVE_ARENA *a, const CSERVE_NODE *el,
                            const CSERVE_ATTR *attr, const CSERVE_TR *value) {
  return set(a, el, attr, (ATTRV){.attr = attr, .tr = value}, 0);
}

CSERVE_NODE *cserve_attr_bool(CSERVE_ARENA *a, const CSERVE_NODE *el,
                              const CSERVE_ATTR *attr, int on) {
  return set(a, el, attr, (ATTRV){.attr = attr}, !on);
}

/* the NULL-terminated nodes in ap, after the n in before, as one array */
static const CSERVE_NODE *const *gather(CSERVE_ARENA *a,
                                        const CSERVE_NODE *const *before, int n,
                                        va_list ap, int *total) {
  va_list count;
  va_copy(count, ap);
  int more = 0;
  while (va_arg(count, const CSERVE_NODE *)) {
    more++;
  }
  va_end(count);
  const CSERVE_NODE **kids =
      cserve_arena_alloc(a, (size_t)(n + more + 1) * sizeof *kids);
  if (!kids) {
    *total = 0;
    return NULL;
  }
  if (n) {
    memcpy(kids, before, (size_t)n * sizeof *kids);
  }
  for (int i = 0; i < more; i++) {
    kids[n + i] = va_arg(ap, const CSERVE_NODE *);
  }
  *total = n + more;
  return kids;
}

/* whether tag may hold anything: 0, or -1 failed into a */
static int may_hold(CSERVE_ARENA *a, const CSERVE_TAG *tag) {
  if (tag->flags & CSERVE_TAG_VOID) {
    cserve_arena_fail(a, "<%s> is a void element and cannot contain anything",
                      tag->name);
    return -1;
  }
  if (tag->flags & CSERVE_TAG_RAW_TEXT) {
    cserve_arena_fail(a,
                      "<%s> holds raw text, which a browser reads without "
                      "decoding; give it a src instead",
                      tag->name);
    return -1;
  }
  return 0;
}

CSERVE_NODE *cserve_containing_(CSERVE_ARENA *a, const CSERVE_NODE *el, ...) {
  CSERVE_NODE *n = copy(a, el, "children");
  if (n == &NOTHING || may_hold(a, el->tag) != 0) {
    return &NOTHING;
  }
  va_list ap;
  va_start(ap, el);
  const CSERVE_NODE *const *kids =
      gather(a, el->kids, el->nkids, ap, &n->nkids);
  va_end(ap);
  if (!kids) {
    return &NOTHING;
  }
  n->kids = kids;
  return n;
}

CSERVE_NODE *cserve_text(CSERVE_ARENA *a, const char *s) {
  CSERVE_NODE *n = node(a, N_TEXT);
  if (n != &NOTHING) {
    n->s = cserve_arena_strdup(a, s);
  }
  return n;
}

CSERVE_NODE *cserve_tr(CSERVE_ARENA *a, const CSERVE_TR *t) {
  CSERVE_NODE *n = node(a, N_TR);
  if (n != &NOTHING) {
    n->tr = t;
  }
  return n;
}

CSERVE_NODE *cserve_fragment_(CSERVE_ARENA *a, ...) {
  CSERVE_NODE *n = node(a, N_FRAGMENT);
  if (n == &NOTHING) {
    return n;
  }
  va_list ap;
  va_start(ap, a);
  n->kids = gather(a, NULL, 0, ap, &n->nkids);
  va_end(ap);
  return n->kids ? n : &NOTHING;
}

CSERVE_NODE *cserve_document(CSERVE_ARENA *a, const CSERVE_NODE *html) {
  CSERVE_NODE *n = node(a, N_DOCUMENT);
  if (n != &NOTHING) {
    n->html = html;
  }
  return n;
}

struct CSERVE_LIST {
  CSERVE_ARENA *a;
  CSERVE_NODE *frag;
  const CSERVE_NODE **kids;
  int cap;
};

CSERVE_LIST *cserve_list(CSERVE_ARENA *a) {
  CSERVE_LIST *l = cserve_arena_alloc(a, sizeof *l);
  if (l) {
    l->a = a;
    l->frag = node(a, N_FRAGMENT);
  }
  return l;
}

void cserve_list_add(CSERVE_LIST *l, CSERVE_NODE *n) {
  if (!l || l->frag == &NOTHING) {
    return;
  }
  if (l->frag->nkids == l->cap) {
    int cap = l->cap ? l->cap * 2 : 8;
    const CSERVE_NODE **kids =
        cserve_arena_alloc(l->a, (size_t)cap * sizeof *kids);
    if (!kids) {
      return;
    }
    if (l->frag->nkids) {
      memcpy(kids, l->kids, (size_t)l->frag->nkids * sizeof *kids);
    }
    l->kids = kids;
    l->cap = cap;
    l->frag->kids = kids;
  }
  l->kids[l->frag->nkids++] = n;
}

CSERVE_NODE *cserve_list_node(const CSERVE_LIST *l) {
  return l ? l->frag : &NOTHING;
}

/* -- escaping ----------------------------------------------------------- */

static int utf8_lead(unsigned c) {
  return c < 0x80 || (c >= 0xC2 && c <= 0xF4);
}

static int utf8_trail(unsigned c) { return c >= 0x80 && c <= 0xBF; }

/* how many bytes at s (avail of them) are one character: > 0, or < 0 for
 * a sequence that isn't one and how many bytes of it to replace with one
 * U+FFFD -- PHP's get_next_char() (ext/standard/html.c) for UTF-8, so
 * the replacements fall where htmlspecialchars' do */
static int next_char(const unsigned char *s, size_t avail) {
  unsigned c = s[0];
  if (c < 0x80) {
    return 1;
  }
  if (c < 0xC2) {
    return -1;
  }
  if (c < 0xE0) {
    if (avail < 2) {
      return -1;
    }
    if (!utf8_trail(s[1])) {
      return utf8_lead(s[1]) ? -1 : -2;
    }
    return 2;
  }
  if (c < 0xF0) {
    if (avail < 3 || !utf8_trail(s[1]) || !utf8_trail(s[2])) {
      if (avail < 2 || utf8_lead(s[1])) {
        return -1;
      }
      if (avail < 3 || utf8_lead(s[2])) {
        return -2;
      }
      return -3;
    }
    unsigned cp = ((c & 0x0F) << 12) | ((s[1] & 0x3Fu) << 6) | (s[2] & 0x3Fu);
    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) {
      return -3;
    }
    return 3;
  }
  if (c < 0xF5) {
    if (avail < 4 || !utf8_trail(s[1]) || !utf8_trail(s[2]) ||
        !utf8_trail(s[3])) {
      if (avail < 2 || utf8_lead(s[1])) {
        return -1;
      }
      if (avail < 3 || utf8_lead(s[2])) {
        return -2;
      }
      if (avail < 4 || utf8_lead(s[3])) {
        return -3;
      }
      return -4;
    }
    unsigned cp = ((c & 0x07) << 18) | ((s[1] & 0x3Fu) << 12) |
                  ((s[2] & 0x3Fu) << 6) | (s[3] & 0x3Fu);
    if (cp < 0x10000 || cp > 0x10FFFF) {
      return -4;
    }
    return 4;
  }
  return -1;
}

void cserve_escape(void (*add)(void *ctx, const char *s, size_t n), void *ctx,
                   const char *s, size_t n) {
  const unsigned char *p = (const unsigned char *)s, *e = p + n;
  const unsigned char *run = p; /* bytes passed through, not yet added */
  while (p < e) {
    const char *ent = NULL;
    size_t skip = 1;
    switch (*p) {
    case '&':
      ent = "&amp;";
      break;
    case '<':
      ent = "&lt;";
      break;
    case '>':
      ent = "&gt;";
      break;
    case '"':
      ent = "&quot;";
      break;
    case '\'':
      ent = "&#039;";
      break;
    default:
      if (*p >= 0x80) {
        int k = next_char(p, (size_t)(e - p));
        if (k < 0) {
          ent = "\xEF\xBF\xBD";
          skip = (size_t)-k;
        } else {
          skip = (size_t)k;
        }
      }
    }
    if (ent) {
      add(ctx, (const char *)run, (size_t)(p - run));
      add(ctx, ent, strlen(ent));
      p += skip;
      run = p;
    } else {
      p += skip;
    }
  }
  add(ctx, (const char *)run, (size_t)(p - run));
}

/* -- addresses ---------------------------------------------------------- */

static int alpha(int c) { return (c | 32) >= 'a' && (c | 32) <= 'z'; }

int cserve_stays_on_origin(const char *value) {
  /* what a URL parser reads: no tab, CR or LF anywhere, and the leading
   * C0 controls and spaces gone */
  const char *p = value;
  while (*p && (unsigned char)*p <= 0x20) {
    p++;
  }
  char first[2];
  int n = 0;
  const char *scheme_end = NULL;
  int scheme_ok = 1; /* still inside a possible scheme */
  for (const char *q = p; *q && (n < 2 || scheme_ok); q++) {
    if (*q == '\t' || *q == '\n' || *q == '\r') {
      continue;
    }
    if (n < 2) {
      first[n] = *q;
    }
    if (scheme_ok) {
      if (*q == ':' && n > 0) {
        scheme_end = q;
        scheme_ok = 0;
      } else if (!(n == 0
                       ? alpha((unsigned char)*q)
                       : alpha((unsigned char)*q) || (*q >= '0' && *q <= '9') ||
                             *q == '+' || *q == '-' || *q == '.')) {
        scheme_ok = 0;
      }
    }
    n++;
  }
  if (scheme_end) {
    return 0; /* an address of its own: a host, or a scheme with none */
  }
  return !(n >= 2 && (first[0] == '/' || first[0] == '\\') &&
           (first[1] == '/' || first[1] == '\\'));
}

/* -- render ------------------------------------------------------------- */

typedef struct {
  CSERVE_ARENA *a;
  const CSERVE_LANGUAGES *langs;
  char *s;
  size_t len, cap;
  int failed;
} OUT;

static void put(void *ctx, const char *s, size_t n) {
  OUT *o = ctx;
  if (o->failed || !n) {
    return;
  }
  if (o->len + n + 1 > o->cap) {
    size_t cap = o->cap ? o->cap : 4096;
    while (cap < o->len + n + 1) {
      cap *= 2;
    }
    char *s2 = realloc(o->s, cap);
    if (!s2) {
      cserve_arena_fail(o->a, "out of memory rendering (%zu bytes)", cap);
      o->failed = 1;
      return;
    }
    o->s = s2;
    o->cap = cap;
  }
  memcpy(o->s + o->len, s, n);
  o->len += n;
}

static void puts_(OUT *o, const char *s) { put(o, s, strlen(s)); }

static void pad(OUT *o, int depth) {
  for (int i = 0; i < depth; i++) {
    put(o, "  ", 2);
  }
}

static void escaped(OUT *o, const char *s) {
  cserve_escape(put, o, s, strlen(s));
}

static int writes_text(const CSERVE_NODE *n);

static int is_inline(const CSERVE_NODE *frag) {
  for (int i = 0; i < frag->nkids; i++) {
    if (writes_text(frag->kids[i])) {
      return 1;
    }
  }
  return 0;
}

static int writes_text(const CSERVE_NODE *n) {
  return n->kind == N_TEXT || n->kind == N_TR ||
         (n->kind == N_FRAGMENT && is_inline(n));
}

static int phrasing(const CSERVE_NODE *n) {
  return n->kind == N_ELEMENT && (n->tag->flags & CSERVE_TAG_PHRASING);
}

#define DEPTH_MAX 256

static void render(OUT *o, const CSERVE_NODE *n, int depth, int lang);

static void render_inline(OUT *o, const CSERVE_NODE *frag, int depth,
                          int lang) {
  for (int i = 0; i < frag->nkids; i++) {
    const CSERVE_NODE *k = frag->kids[i];
    if (k->kind == N_FRAGMENT) {
      if (depth > DEPTH_MAX) {
        cserve_arena_fail(o->a, "fragments nested past %d", DEPTH_MAX);
        return;
      }
      render_inline(o, k, depth, lang);
    } else {
      render(o, k, depth, lang);
    }
  }
}

/* Fragment::lines(): the nodes, fragments opened, a line each at depth,
 * except two phrasing elements in a row; *prev carries the last across
 * the fragments it opens */
static void lines(OUT *o, const CSERVE_NODE *frag, int depth, int lang,
                  const CSERVE_NODE **prev, int nesting) {
  if (nesting > DEPTH_MAX) {
    cserve_arena_fail(o->a, "fragments nested past %d", DEPTH_MAX);
    return;
  }
  for (int i = 0; i < frag->nkids; i++) {
    const CSERVE_NODE *k = frag->kids[i];
    if (k->kind == N_FRAGMENT) {
      lines(o, k, depth, lang, prev, nesting + 1);
      continue;
    }
    if (*prev && !(phrasing(*prev) && phrasing(k))) {
      put(o, "\n", 1);
      pad(o, depth);
    }
    render(o, k, depth, lang);
    *prev = k;
  }
}

static void attributes(OUT *o, const CSERVE_NODE *el, int lang) {
  for (int i = 0; i < el->nattrs; i++) {
    const ATTRV *v = &el->attrs[i];
    put(o, " ", 1);
    puts_(o, v->attr->name);
    if (!v->value && !v->tr) {
      continue;
    }
    const char *value = v->tr ? cserve_tr_in(o->a, v->tr, lang) : v->value;
    if (v->attr->url) {
      int ok = value[0] == '/' || value[0] == '#'
                   ? cserve_stays_on_origin(value)
                   : !strncasecmp(value, "https:", 6) ||
                         !strncasecmp(value, "mailto:", 7);
      if (!ok) {
        cserve_arena_fail(o->a,
                          "<%s %s=\"%s\"> is not a URL this site may "
                          "emit. Allowed: a site-relative path, a "
                          "#fragment of the page, or https: / mailto:",
                          el->tag->name, v->attr->name, value);
      }
    }
    put(o, "=\"", 2);
    escaped(o, value);
    put(o, "\"", 1);
  }
}

static void render(OUT *o, const CSERVE_NODE *n, int depth, int lang) {
  if (depth > DEPTH_MAX) {
    cserve_arena_fail(o->a, "elements nested past %d", DEPTH_MAX);
    return;
  }
  switch (n->kind) {
  case N_TEXT:
    escaped(o, n->s);
    return;
  case N_TR:
    escaped(o, cserve_tr_in(o->a, n->tr, lang));
    return;
  case N_FRAGMENT:
    if (is_inline(n)) {
      render_inline(o, n, depth, lang);
    } else {
      const CSERVE_NODE *prev = NULL;
      lines(o, n, depth, lang, &prev, 0);
    }
    return;
  case N_DOCUMENT:
    puts_(o, "<!DOCTYPE html>\n");
    pad(o, depth);
    render(o, n->html, depth, lang);
    return;
  case N_ELEMENT:
    break;
  }
  const CSERVE_TAG *tag = n->tag;
  for (int i = 0; i < n->nattrs; i++) {
    if (!strcmp(n->attrs[i].attr->name, cserve_attr_lang.name) &&
        n->attrs[i].value) {
      int own = cserve_language_of(o->langs, n->attrs[i].value);
      lang = own >= 0 ? own : lang;
    }
  }
  put(o, "<", 1);
  puts_(o, tag->name);
  attributes(o, n, lang);
  put(o, ">", 1);
  if (tag->flags & CSERVE_TAG_VOID) {
    if (n->nkids) {
      may_hold(o->a, tag);
    }
    return;
  }
  if (n->nkids) {
    if (tag->flags & CSERVE_TAG_RAW_TEXT) {
      may_hold(o->a, tag);
      return;
    }
    int inline_ = (tag->flags & CSERVE_TAG_INLINE) != 0;
    for (int i = 0; i < n->nkids && !inline_; i++) {
      inline_ = writes_text(n->kids[i]);
    }
    if (inline_) {
      render_inline(o, n, depth, lang);
    } else {
      put(o, "\n", 1);
      pad(o, depth + 1);
      const CSERVE_NODE *prev = NULL;
      lines(o, n, depth + 1, lang, &prev, 0);
      put(o, "\n", 1);
      pad(o, depth);
    }
  }
  put(o, "</", 2);
  puts_(o, tag->name);
  put(o, ">", 1);
}

int cserve_render(CSERVE_ARENA *a, const CSERVE_NODE *n,
                  const CSERVE_LANGUAGES *langs, int lang, char **out,
                  size_t *len) {
  *out = NULL;
  *len = 0;
  OUT o = {.a = a, .langs = langs};
  if (!cserve_arena_error(a)) {
    render(&o, n, 0, lang);
  }
  if (cserve_arena_error(a)) {
    free(o.s);
    return -1;
  }
  put(&o, "", 0);
  if (!o.s) {
    o.s = malloc(1);
    if (!o.s) {
      cserve_arena_fail(a, "out of memory rendering");
      return -1;
    }
  }
  o.s[o.len] = '\0';
  *out = o.s;
  *len = o.len;
  return 0;
}
