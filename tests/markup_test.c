/* kit/markup.c and kit/text.c: escaping and the origin check against
 * Phpanta's own answers (data/goldens.h), the trees goldens.php builds
 * built again here and rendered to the same bytes, what a builder
 * refuses, and the catalog's and a phrase's rules */
#include "html.h"
#include "markup.h"
#include "text.h"

#include "data/goldens.h"
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N(a) (sizeof(a) / sizeof *(a))

static const CSERVE_LANGUAGES LANGS = {{"en", "de"}, 2};
static const CSERVE_TEXT HELLO = CSERVE_TEXT_IN("hello", "hallo");

typedef struct {
  char *s;
  size_t len;
} BUF;

static void grow(void *ctx, const char *s, size_t n) {
  BUF *b = ctx;
  b->s = realloc(b->s, b->len + n + 1);
  memcpy(b->s + b->len, s, n);
  b->len += n;
  b->s[b->len] = '\0';
}

static void test_escape(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_ESCAPE); i++) {
    BUF b = {0};
    grow(&b, "", 0);
    cserve_escape(grow, &b, GOLD_ESCAPE[i].in, strlen(GOLD_ESCAPE[i].in));
    if (strcmp(b.s, GOLD_ESCAPE[i].out)) {
      printf("    escape case %zu differs\n", i);
      bad++;
    }
    free(b.s);
  }
  CSERVE_TEST_ASSERT(!bad,
                     "escaping is htmlspecialchars(ENT_QUOTES | "
                     "ENT_SUBSTITUTE)'s (%zu cases, %d wrong)",
                     N(GOLD_ESCAPE), bad);
}

static void test_origin(void) {
  int bad = 0;
  for (size_t i = 0; i < N(GOLD_ORIGIN); i++) {
    int s = cserve_stays_on_origin(GOLD_ORIGIN[i].value);
    if (s != GOLD_ORIGIN[i].stays) {
      printf("    origin case %zu (\"%s\"): %d, phpanta %d\n", i,
             GOLD_ORIGIN[i].value, s, GOLD_ORIGIN[i].stays);
      bad++;
    }
  }
  CSERVE_TEST_ASSERT(!bad,
                     "staying on the origin, as staysOnThisOrigin "
                     "decides (%zu cases, %d wrong)",
                     N(GOLD_ORIGIN), bad);
  CSERVE_TEST_ASSERT(!cserve_stays_on_origin("https:/x") &&
                         !cserve_stays_on_origin("javascript:x") &&
                         cserve_stays_on_origin("releases"),
                     "a scheme of any kind doesn't stay; a relative path does");
}

#define EL(t) cserve_el(a, &cserve_tag_##t)
#define ATTR(n, attr, v) cserve_attr(a, n, &cserve_attr_##attr, v)
#define HAS(n, ...) cserve_containing(a, n, __VA_ARGS__)
#define TEXT(s) cserve_text(a, s)

/* the tree goldens.php names name */
static const CSERVE_NODE *tree(CSERVE_ARENA *a, const char *name) {
  const CSERVE_NODE *hello = cserve_tr(a, &HELLO);
  if (!strcmp(name, "text")) {
    return HAS(EL(p), TEXT("a < b & 'c' \"d\""));
  }
  if (!strcmp(name, "block")) {
    return HAS(EL(div), HAS(EL(p), TEXT("one")), HAS(EL(p), TEXT("two")));
  }
  if (!strcmp(name, "phrasing")) {
    return HAS(EL(div), HAS(ATTR(EL(a), href, "/x"), TEXT("x")),
               HAS(EL(span), TEXT("y")), HAS(EL(p), TEXT("z")),
               ATTR(ATTR(EL(img), src, "/i.png"), alt, ""), EL(br));
  }
  if (!strcmp(name, "nested")) {
    return HAS(EL(section), HAS(EL(div), HAS(EL(ul), HAS(EL(li), TEXT("1")),
                                             HAS(EL(li), TEXT("2")))));
  }
  if (!strcmp(name, "void")) {
    return HAS(
        EL(div),
        ATTR(ATTR(EL(img), src, "https://my.hidrive.com/x"), alt, "cover"),
        ATTR(cserve_attr_bool(a, EL(input), &cserve_attr_required, 1), name,
             "n"));
  }
  if (!strcmp(name, "lang")) {
    return HAS(ATTR(EL(div), lang, "de"), HAS(EL(p), hello),
               HAS(ATTR(EL(p), lang, "fr"), hello),
               HAS(cserve_attr_tr(a, ATTR(EL(p), lang, "en"),
                                  &cserve_attr_title, &HELLO),
                   hello));
  }
  if (!strcmp(name, "container")) {
    return HAS(
        EL(div), HAS(ATTR(EL(a), href, "#top"), HAS(EL(span), TEXT("x"))),
        HAS(EL(div), cserve_fragment(a, TEXT("a"), HAS(EL(span), TEXT("b")))));
  }
  if (!strcmp(name, "flatten")) {
    return HAS(EL(div),
               cserve_fragment(a, HAS(EL(p), TEXT("1")),
                               cserve_fragment(a, HAS(EL(p), TEXT("2")),
                                               HAS(EL(p), TEXT("3")))),
               HAS(EL(p), TEXT("4")));
  }
  if (!strcmp(name, "document")) {
    return cserve_document(
        a, HAS(ATTR(EL(html), lang, "en"),
               HAS(EL(head), ATTR(EL(meta), charset, "UTF-8"),
                   HAS(EL(title), TEXT("T"))),
               HAS(EL(body),
                   HAS(ATTR(EL(main), id, "content"), HAS(EL(p), TEXT("x"))))));
  }
  if (!strcmp(name, "order")) {
    return ATTR(ATTR(ATTR(EL(div), class, "a"), id, "b"), class, "c");
  }
  if (!strcmp(name, "empty")) {
    return HAS(EL(div), EL(div), ATTR(EL(script), src, "/a.js"));
  }
  if (!strcmp(name, "schemes")) {
    return HAS(EL(p), HAS(ATTR(EL(a), href, "mailto:x@y"), TEXT("m")),
               TEXT(" \xC2\xB7 "),
               HAS(cserve_attr_bool(a, ATTR(EL(a), href, "HTTPS://x"),
                                    &cserve_attr_data_no_spa, 1),
                   TEXT("h")));
  }
  if (!strcmp(name, "joined")) {
    return HAS(ATTR(EL(title), lang, "de"),
               cserve_tr(a, cserve_joined(a, " \xE2\x80\x94 ", &HELLO,
                                          cserve_verbatim(a, "neuro.SYS"))));
  }
  if (!strcmp(name, "utf8")) {
    return HAS(EL(p), TEXT("\xC3\xBC \xE2\x82\xAC \xF0\x9D\x84\x9E \xC3("));
  }
  if (!strcmp(name, "attrs")) {
    return ATTR(ATTR(cserve_attr_bool(a, EL(audio), &cserve_attr_controls, 1),
                     preload, ""),
                src, "/a?x=1&y=2");
  }
  if (!strcmp(name, "fragment")) {
    return cserve_fragment(a, HAS(EL(title), TEXT("T")),
                           HAS(EL(section), HAS(EL(p), TEXT("x")),
                               HAS(EL(button), TEXT("b")),
                               HAS(EL(button), TEXT("c"))));
  }
  return NULL;
}

static void test_trees(void) {
  for (size_t i = 0; i < N(GOLD_MARKUP); i++) {
    CSERVE_ARENA *a = cserve_arena_new();
    const CSERVE_NODE *t = tree(a, GOLD_MARKUP[i].name);
    char *out = NULL;
    size_t len = 0;
    int rc = t ? cserve_render(a, t, &LANGS, 0, &out, &len) : -1;
    int same = rc == 0 && len == strlen(GOLD_MARKUP[i].html) &&
               !strcmp(out, GOLD_MARKUP[i].html);
    CSERVE_TEST_ASSERT(same, "the \"%s\" tree renders as phpanta renders it",
                       GOLD_MARKUP[i].name);
    if (!same) {
      printf("    got:  %s\n    want: %s\n    (%s)\n", out ? out : "(none)",
             GOLD_MARKUP[i].html,
             cserve_arena_error(a) ? cserve_arena_error(a) : "");
    }
    free(out);
    cserve_arena_free(a);
  }
}

/* whether n fails to render, and why says what's in err */
static int refused(CSERVE_ARENA *a, const CSERVE_NODE *n, int lang,
                   const char *why) {
  char *out;
  size_t len;
  int rc = cserve_render(a, n, &LANGS, lang, &out, &len);
  const char *err = cserve_arena_error(a);
  int ok = rc == -1 && !out && err && strstr(err, why);
  if (!ok) {
    printf("    rendered: %s; error: %s\n", rc == 0 ? out : "(none)",
           err ? err : "(none)");
  }
  if (rc == 0) {
    free(out);
  }
  cserve_arena_free(a);
  return ok;
}

static void test_refusals(void) {
  CSERVE_ARENA *a = cserve_arena_new();
  CSERVE_TEST_ASSERT(refused(a, HAS(EL(br), TEXT("x")), 0, "void"),
                     "a void element holding anything");
  a = cserve_arena_new();
  CSERVE_TEST_ASSERT(
      refused(a, HAS(EL(script), TEXT("alert(1)")), 0, "raw text"),
      "a script holding anything");
  static const char *const BAD[] = {
      "javascript:alert(1)", "http://x", "//evil", "/\\evil",
      "/\r\n/evil",          "relative", "",       " /x"};
  for (size_t i = 0; i < N(BAD); i++) {
    a = cserve_arena_new();
    CSERVE_TEST_ASSERT(refused(a, ATTR(EL(a), href, BAD[i]), 0, "not a URL"),
                       "href=\"%s\" is refused", BAD[i]);
  }
  a = cserve_arena_new();
  CSERVE_TEST_ASSERT(
      refused(a, HAS(EL(p), cserve_tr(a, &HELLO)), -1, "no language"),
      "a text with no language in scope");
  a = cserve_arena_new();
  CSERVE_TEST_ASSERT(refused(a,
                             cserve_attr_tr(a, EL(img), &cserve_attr_src,
                                            cserve_verbatim(a, "data:x")),
                             0, "not a URL"),
                     "a translatable address is checked as it resolves");
  a = cserve_arena_new();
  (void)HAS(EL(br), TEXT("x"));
  CSERVE_TEST_ASSERT(refused(a, HAS(EL(p), TEXT("fine")), 0, "void"),
                     "an arena that failed while building renders nothing");
  a = cserve_arena_new();
  const CSERVE_NODE *base = ATTR(EL(a), href, "/a");
  const CSERVE_NODE *other = ATTR(base, href, "/b");
  char *x, *y;
  size_t xl, yl;
  int rc = cserve_render(a, HAS(EL(p), base), &LANGS, 0, &x, &xl) |
           cserve_render(a, HAS(EL(p), other), &LANGS, 0, &y, &yl);
  CSERVE_TEST_ASSERT(!rc && strstr(x, "/a") && strstr(y, "/b"),
                     "a builder copies: the element it's given is unchanged");
  free(x);
  free(y);
  cserve_arena_free(a);
}

static void test_list(void) {
  CSERVE_ARENA *a = cserve_arena_new();
  CSERVE_LIST *l = cserve_list(a);
  char item[8];
  for (int i = 0; i < 20; i++) {
    snprintf(item, sizeof item, "%d", i);
    cserve_list_add(l, HAS(EL(li), TEXT(item)));
  }
  char *out;
  size_t len;
  int rc =
      cserve_render(a, HAS(EL(ul), cserve_list_node(l)), &LANGS, 0, &out, &len);
  CSERVE_TEST_ASSERT(rc == 0 && strstr(out, "<ul>\n  <li>0</li>\n") &&
                         strstr(out, "<li>19</li>\n</ul>"),
                     "a list grown an item at a time is a fragment of them");
  if (rc == 0) {
    free(out);
  }
  cserve_arena_free(a);
}

static void test_phrase(void) {
  static const CSERVE_TEXT BEATS = CSERVE_TEXT_IN("{bpm} bpm", "{bpm} bpm");
  static const CSERVE_TEXT COVER =
      CSERVE_TEXT_IN("{title} cover art", "cover von {title}");
  CSERVE_ARENA *a = cserve_arena_new();
  CSERVE_TEST_ASSERT(
      !strcmp(cserve_tr_in(a, cserve_phrase(a, &BEATS, "bpm", "140"), 0),
              "140 bpm") &&
          !strcmp(cserve_tr_in(a, cserve_phrase(a, &COVER, "title", "ill"), 1),
                  "cover von ill") &&
          !cserve_arena_error(a),
      "a phrase's values go where its words say, in either language");
  cserve_arena_free(a);
  struct {
    const char *pattern, *why;
  } BAD[] = {
      {"{bpm} at {key}", "nothing was bound"},
      {"just words", "doesn't use"},
      {"{bpm, number}", "brace"},
      {"{0}", "brace"},
      {"a } b {bpm}", "brace"},
      {"{bpm}'s", "apostrophe"},
      {"{Bpm}", "brace"},
  };
  for (size_t i = 0; i < N(BAD); i++) {
    CSERVE_TEXT t = CSERVE_TEXT_IN(BAD[i].pattern, BAD[i].pattern);
    a = cserve_arena_new();
    const char *s = cserve_tr_in(a, cserve_phrase(a, &t, "bpm", "140"), 0);
    const char *err = cserve_arena_error(a);
    CSERVE_TEST_ASSERT(!*s && err && strstr(err, BAD[i].why),
                       "'%s' with bpm is refused (%s)", BAD[i].pattern,
                       err ? err : "no error");
    cserve_arena_free(a);
  }
  a = cserve_arena_new();
  (void)cserve_phrase(a, &BEATS, "bpm");
  CSERVE_TEST_ASSERT(cserve_arena_error(a) != NULL,
                     "a name without its value is refused");
  cserve_arena_free(a);
}

static void test_catalog(void) {
  static const CSERVE_TEXT GOOD = CSERVE_TEXT_IN("yes", "ja");
  static const CSERVE_TEXT HALF = CSERVE_TEXT_IN("only english");
  static const CSERVE_TEXT BLANK = CSERVE_TEXT_IN("words", "  ");
  const CSERVE_TEXT *ok[] = {&GOOD, &HELLO};
  const CSERVE_TEXT *half[] = {&GOOD, &HALF};
  const CSERVE_TEXT *blank[] = {&BLANK};
  char err[256];
  CSERVE_TEST_ASSERT(cserve_texts_complete(ok, 2, 2, err, sizeof err) == 0,
                     "a catalog with both languages throughout is complete");
  CSERVE_TEST_ASSERT(cserve_texts_complete(half, 2, 2, err, sizeof err) == -1 &&
                         strstr(err, "only english"),
                     "an entry missing a language is named");
  CSERVE_TEST_ASSERT(cserve_texts_complete(blank, 1, 2, err, sizeof err) == -1,
                     "blank words are no words");
  CSERVE_TEST_ASSERT(cserve_language_of(&LANGS, "de") == 1 &&
                         cserve_language_of(&LANGS, "DE") == -1 &&
                         cserve_language_of(&LANGS, "fr") == -1,
                     "a language is offered exactly or not at all");
}

int main(void) {
  printf("markup_test\n");
  test_escape();
  test_origin();
  test_trees();
  test_refusals();
  test_list();
  test_phrase();
  test_catalog();
  return cserve_test_summary();
}
