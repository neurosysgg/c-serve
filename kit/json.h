#ifndef CSERVE_JSON_H
#define CSERVE_JSON_H

#include <stddef.h>

/* A JSON file an app reads at start-up, as a tree (lifted from ctui's
 * json.c, whose grammar and number reading it keeps). Strict, because a
 * machine writes these files: no comments, no trailing commas, no key
 * said twice in one object, strings that are UTF-8 once decoded (a
 * \u0000 or a lone surrogate is U+FFFD, as there), nothing after the
 * value. Object members keep the order they're written in. */

typedef enum {
  CSERVE_JSON_NULL,
  CSERVE_JSON_BOOL,
  CSERVE_JSON_NUMBER,
  CSERVE_JSON_STRING,
  CSERVE_JSON_ARRAY,
  CSERVE_JSON_OBJECT,
} CSERVE_JSON_TYPE;

typedef struct CSERVE_JSON CSERVE_JSON;
struct CSERVE_JSON {
  CSERVE_JSON_TYPE type;
  int boolean;
  double number;
  char *string;
  /* ARRAY: items[0..count). OBJECT: keys[i] -> items[i], in file order. */
  CSERVE_JSON *items;
  char **keys;
  int count;
};

/* text as a tree (malloc'd), or NULL with "line L, col C: why" in err */
CSERVE_JSON *cserve_json_parse(const char *text, char *err, size_t err_cap);
void cserve_json_free(CSERVE_JSON *v);

/* an object's member key, or NULL (v no object, or without it) */
const CSERVE_JSON *cserve_json_get(const CSERVE_JSON *v, const char *key);
/* v's string, or NULL when v is no string */
const char *cserve_json_str(const CSERVE_JSON *v);
/* v as a whole number in [lo, hi] into out: 0, or -1 when it's no
 * number, has a fraction or falls outside */
int cserve_json_whole(const CSERVE_JSON *v, long long lo, long long hi,
                      long long *out);

#endif
