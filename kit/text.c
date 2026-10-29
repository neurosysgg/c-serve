#include "text.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int cserve_language_of(const CSERVE_LANGUAGES *langs, const char *tag) {
  for (int i = 0; tag && i < langs->n; i++) {
    if (!strcmp(langs->tags[i], tag)) {
      return i;
    }
  }
  return -1;
}

static int blank(const char *s) {
  for (; *s; s++) {
    if (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\r') {
      return 0;
    }
  }
  return 1;
}

int cserve_texts_complete(const CSERVE_TEXT *const *texts, int n, int nlangs,
                          char *err, size_t err_cap) {
  for (int i = 0; i < n; i++) {
    for (int l = 0; l < nlangs && l < CSERVE_LANG_MAX; l++) {
      const char *w = texts[i]->in[l];
      if (texts[i]->kind != CSERVE_TR_CATALOG || !w || blank(w)) {
        snprintf(err, err_cap,
                 "entry %d of the catalog has no words in "
                 "language %d (\"%s\" in the first)",
                 i, l, texts[i]->in[0] ? texts[i]->in[0] : "");
        return -1;
      }
    }
  }
  return 0;
}

const CSERVE_TR *cserve_verbatim(CSERVE_ARENA *a, const char *s) {
  CSERVE_TR *t = cserve_arena_alloc(a, sizeof *t);
  if (!t) {
    static const CSERVE_TR NONE = {.kind = CSERVE_TR_VERBATIM, .s = ""};
    return &NONE;
  }
  t->kind = CSERVE_TR_VERBATIM;
  t->s = cserve_arena_strdup(a, s);
  return t;
}

const CSERVE_TR *cserve_joined_(CSERVE_ARENA *a, const char *glue, ...) {
  va_list ap;
  int n = 0;
  va_start(ap, glue);
  while (va_arg(ap, const CSERVE_TR *)) {
    n++;
  }
  va_end(ap);
  CSERVE_TR *t = cserve_arena_alloc(a, sizeof *t);
  const CSERVE_TR **parts =
      cserve_arena_alloc(a, (size_t)(n ? n : 1) * sizeof *parts);
  if (!t || !parts) {
    static const CSERVE_TR NONE = {.kind = CSERVE_TR_VERBATIM, .s = ""};
    return &NONE;
  }
  va_start(ap, glue);
  for (int i = 0; i < n; i++) {
    parts[i] = va_arg(ap, const CSERVE_TR *);
  }
  va_end(ap);
  t->kind = CSERVE_TR_JOINED;
  t->s = cserve_arena_strdup(a, glue);
  t->parts = parts;
  t->n = n;
  return t;
}

const CSERVE_TR *cserve_phrase_(CSERVE_ARENA *a, const CSERVE_TEXT *entry,
                                ...) {
  static const CSERVE_TR NONE = {.kind = CSERVE_TR_VERBATIM, .s = ""};
  va_list ap;
  int n = 0;
  va_start(ap, entry);
  while (va_arg(ap, const char *)) {
    n++;
  }
  va_end(ap);
  if (n % 2 || entry->kind != CSERVE_TR_CATALOG) {
    cserve_arena_fail(a,
                      "a phrase is a catalog entry and name, value pairs "
                      "(\"%s\")",
                      entry->in[0] ? entry->in[0] : "");
    return &NONE;
  }
  CSERVE_TR *t = cserve_arena_alloc(a, sizeof *t);
  const char **args = cserve_arena_alloc(a, (size_t)(n ? n : 1) * sizeof *args);
  if (!t || !args) {
    return &NONE;
  }
  va_start(ap, entry);
  for (int i = 0; i < n; i++) {
    args[i] = cserve_arena_strdup(a, va_arg(ap, const char *));
  }
  va_end(ap);
  t->kind = CSERVE_TR_PHRASE;
  t->base = entry;
  t->args = args;
  t->n = n / 2;
  return t;
}

/* a growing string in the arena */
typedef struct {
  CSERVE_ARENA *a;
  char *s;
  size_t len, cap;
} STR;

static void add(STR *b, const char *s, size_t n) {
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap * 2 : 64;
    while (cap < b->len + n + 1) {
      cap *= 2;
    }
    char *s2 = cserve_arena_alloc(b->a, cap);
    if (!s2) {
      return;
    }
    if (b->len) {
      memcpy(s2, b->s, b->len);
    }
    b->s = s2;
    b->cap = cap;
  }
  memcpy(b->s + b->len, s, n);
  b->len += n;
  b->s[b->len] = '\0';
}

static int name_start(int c) { return c >= 'a' && c <= 'z'; }

static int name_char(int c) {
  return name_start(c) || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

/* pattern with t's values in it, into b: 0, or -1 failed into a */
static int format(CSERVE_ARENA *a, const CSERVE_TR *t, const char *pattern,
                  STR *b) {
  unsigned used = 0; /* a bit per value */
  if (t->n > 32) {
    cserve_arena_fail(a, "a phrase with more than 32 values");
    return -1;
  }
  for (const char *p = pattern; *p;) {
    size_t k = strcspn(p, "{}'");
    add(b, p, k);
    p += k;
    if (!*p) {
      break;
    }
    if (*p == '\'') {
      cserve_arena_fail(a,
                        "'%s' has an apostrophe, which ICU reads as "
                        "quoting: write \xe2\x80\x99",
                        pattern);
      return -1;
    }
    const char *name = p + 1, *e = name;
    while (name_char((unsigned char)*e)) {
      e++;
    }
    if (*p == '}' || !name_start((unsigned char)*name) || *e != '}') {
      cserve_arena_fail(a, "'%s' has a brace that isn't a {name}", pattern);
      return -1;
    }
    int found = -1;
    for (int i = 0; i < t->n && found < 0; i++) {
      if (strlen(t->args[2 * i]) == (size_t)(e - name) &&
          !memcmp(t->args[2 * i], name, (size_t)(e - name))) {
        found = i;
      }
    }
    if (found < 0) {
      cserve_arena_fail(a, "'%s' uses {%.*s}, and nothing was bound to it",
                        pattern, (int)(e - name), name);
      return -1;
    }
    used |= 1u << found;
    add(b, t->args[2 * found + 1], strlen(t->args[2 * found + 1]));
    p = e + 1;
  }
  for (int i = 0; i < t->n; i++) {
    if (!(used & (1u << i))) {
      cserve_arena_fail(a, "'%s' doesn't use the %s it was given", pattern,
                        t->args[2 * i]);
      return -1;
    }
  }
  return 0;
}

static int resolve(CSERVE_ARENA *a, const CSERVE_TR *t, int lang, STR *b,
                   int depth) {
  if (depth > 32) {
    cserve_arena_fail(a, "a translatable nested past 32");
    return -1;
  }
  switch (t->kind) {
  case CSERVE_TR_VERBATIM:
    add(b, t->s, strlen(t->s));
    return 0;
  case CSERVE_TR_JOINED:
    for (int i = 0; i < t->n; i++) {
      if (i) {
        add(b, t->s, strlen(t->s));
      }
      if (resolve(a, t->parts[i], lang, b, depth + 1) != 0) {
        return -1;
      }
    }
    return 0;
  case CSERVE_TR_CATALOG:
  case CSERVE_TR_PHRASE: {
    const CSERVE_TR *entry = t->kind == CSERVE_TR_PHRASE ? t->base : t;
    const char *w =
        lang >= 0 && lang < CSERVE_LANG_MAX ? entry->in[lang] : NULL;
    if (lang < 0) {
      cserve_arena_fail(a, "\"%s\" was rendered with no language in scope",
                        entry->in[0] ? entry->in[0] : "");
      return -1;
    }
    if (!w) {
      cserve_arena_fail(a, "\"%s\" has no words in language %d",
                        entry->in[0] ? entry->in[0] : "", lang);
      return -1;
    }
    if (t->kind == CSERVE_TR_CATALOG) {
      add(b, w, strlen(w));
      return 0;
    }
    return format(a, t, w, b);
  }
  }
  cserve_arena_fail(a, "a translatable of no kind");
  return -1;
}

const char *cserve_tr_in(CSERVE_ARENA *a, const CSERVE_TR *t, int lang) {
  if (t->kind == CSERVE_TR_CATALOG && lang >= 0 && lang < CSERVE_LANG_MAX &&
      t->in[lang]) {
    return t->in[lang];
  }
  if (t->kind == CSERVE_TR_VERBATIM) {
    return t->s;
  }
  STR b = {.a = a};
  if (resolve(a, t, lang, &b, 0) != 0 || !b.s) {
    return "";
  }
  return b.s;
}
