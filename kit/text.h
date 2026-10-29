#ifndef CSERVE_TEXT_H
#define CSERVE_TEXT_H

#include "arena.h"

#include <stddef.h>

/* Every word a page says, in each language it's offered in, resolved as
 * late as possible: a view names a text, and render puts it into the
 * language of the nearest lang above it (phpanta's Translatable).
 *
 * A language is an index into the app's offered list, the default first;
 * a catalog entry holds its words in that order. An app declares its
 * entries through a macro of its own that takes every language as an
 * argument, so a missing one is a compiler error, not a page that falls
 * back:
 *
 *   #define T(id, en, de) const CSERVE_TEXT id = CSERVE_TEXT_IN(en, de)
 *   T(downloads, "downloads", "downloads");
 *
 * A phrase is an entry with {name} placeholders and the values bound to
 * them (ReleaseText::Beats->with(bpm: 140)). Its grammar is strict: a
 * placeholder is {a-z, then letters and digits}, every one is bound,
 * every value is used, and any other brace -- or an apostrophe, which
 * ICU's MessageFormat (phpanta's) would read as quoting -- is an error,
 * so a phrase renders here exactly as it did there. */

#define CSERVE_LANG_MAX 6

typedef enum {
  CSERVE_TR_CATALOG,  /* in[] */
  CSERVE_TR_VERBATIM, /* s, in every language */
  CSERVE_TR_JOINED,   /* parts[], with s between each */
  CSERVE_TR_PHRASE,   /* base (a catalog entry), args[] as name, value */
} CSERVE_TR_KIND;

typedef struct CSERVE_TR {
  CSERVE_TR_KIND kind;
  const char *in[CSERVE_LANG_MAX];
  const char *s;
  const struct CSERVE_TR *const *parts;
  int n;
  const struct CSERVE_TR *base;
  const char *const *args;
} CSERVE_TR;

/* a catalog entry: a translatable whose words are written out */
typedef CSERVE_TR CSERVE_TEXT;
#define CSERVE_TEXT_IN(...)                                                    \
  {                                                                            \
    .kind = CSERVE_TR_CATALOG, .in = {__VA_ARGS__}                             \
  }

/* the languages an app offers: primary subtags ("en"), the default first */
typedef struct {
  const char *tags[CSERVE_LANG_MAX];
  int n;
} CSERVE_LANGUAGES;

/* tag's index in langs (exactly: "DE" isn't "de"), or -1 */
int cserve_language_of(const CSERVE_LANGUAGES *langs, const char *tag);

/* whether each of texts (n of them) has words, none blank, for each of
 * nlangs languages: 0, or -1 with the first that hasn't in err (an app's
 * init() asks it of its catalog) */
int cserve_texts_complete(const CSERVE_TEXT *const *texts, int n, int nlangs,
                          char *err, size_t err_cap);

/* s in every language (copied) */
const CSERVE_TR *cserve_verbatim(CSERVE_ARENA *a, const char *s);
/* the parts, glue between each (NULL-terminated; the macro adds it) */
const CSERVE_TR *cserve_joined_(CSERVE_ARENA *a, const char *glue, ...);
#define cserve_joined(a, glue, ...) cserve_joined_(a, glue, __VA_ARGS__, NULL)
/* entry with its placeholders bound: name, value, ... (values copied;
 * NULL-terminated, the macro adds it) */
const CSERVE_TR *cserve_phrase_(CSERVE_ARENA *a, const CSERVE_TEXT *entry, ...);
#define cserve_phrase(a, entry, ...) cserve_phrase_(a, entry, __VA_ARGS__, NULL)

/* t in language lang: its words (in a, or the entry's own), or "" with
 * why failed into a -- no language in scope (lang < 0), none written for
 * it, a phrase that doesn't fit its values */
const char *cserve_tr_in(CSERVE_ARENA *a, const CSERVE_TR *t, int lang);

#endif
