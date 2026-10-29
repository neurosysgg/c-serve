#ifndef CSERVE_MARKUP_H
#define CSERVE_MARKUP_H

#include "arena.h"
#include "text.h"

#include <stddef.h>

/* A page as a tree of nodes, never as a string: an element (a tag, its
 * attributes, its children), text, a translatable, a fragment (nodes with
 * no element around them), a document (the doctype and <html>). Escaping
 * and the check on every URL live in render, so they hold however a tree
 * was built -- this file is the only one that writes a '<'.
 *
 * Render is phpanta's (View/Html/), byte for byte, so a page served from
 * here and from there can be diffed:
 * - text and attribute values escaped as htmlspecialchars(ENT_QUOTES |
 *   ENT_SUBSTITUTE): &<>"' as entities (' as &#039;), bytes that aren't
 *   UTF-8 as U+FFFD;
 * - an element with a child that writes text, or an inline container's
 *   (a, span, ...), on one line; any other's children each on a line of
 *   their own, two spaces deeper, except that two phrasing elements in a
 *   row share one; fragments opened into their parent;
 * - lang="x" on an element puts what's under it into x -- when x is one
 *   of the languages offered; any other lang changes nothing.
 *
 * Builders copy (the element given is left as it was), and everything
 * they make lives in the arena. One that's refused fails the arena and
 * hands back a harmless node; render then fails. */

/* a tag: its name and how it renders */
enum {
  CSERVE_TAG_VOID = 1 << 0,     /* no children, no closing tag: <br> */
  CSERVE_TAG_PHRASING = 1 << 1, /* shares a line with the next phrasing */
  CSERVE_TAG_INLINE = 1 << 2,   /* children on one line, whatever they are */
  CSERVE_TAG_RAW_TEXT = 1 << 3, /* read undecoded (script): no children */
};
typedef struct {
  const char *name;
  unsigned flags;
} CSERVE_TAG;

/* an attribute: its name, and whether its value is an address (checked
 * at render: an https: or mailto: URL, or one that stays on this origin) */
typedef struct {
  const char *name;
  int url;
} CSERVE_ATTR;

typedef struct CSERVE_NODE CSERVE_NODE;

CSERVE_NODE *cserve_el(CSERVE_ARENA *a, const CSERVE_TAG *tag);
/* el with attr set to value (copied), where it was if el had it already,
 * else last */
CSERVE_NODE *cserve_attr(CSERVE_ARENA *a, const CSERVE_NODE *el,
                         const CSERVE_ATTR *attr, const char *value);
/* ... to a translatable, resolved in the element's language at render */
CSERVE_NODE *cserve_attr_tr(CSERVE_ARENA *a, const CSERVE_NODE *el,
                            const CSERVE_ATTR *attr, const CSERVE_TR *value);
/* ... written bare (<audio controls>); on = 0 takes attr away */
CSERVE_NODE *cserve_attr_bool(CSERVE_ARENA *a, const CSERVE_NODE *el,
                              const CSERVE_ATTR *attr, int on);
/* el with the children after its own (NULL-terminated; the macro adds it) */
CSERVE_NODE *cserve_containing_(CSERVE_ARENA *a, const CSERVE_NODE *el, ...);
#define cserve_containing(a, el, ...)                                          \
  cserve_containing_(a, el, __VA_ARGS__, NULL)

/* s as text (copied) */
CSERVE_NODE *cserve_text(CSERVE_ARENA *a, const char *s);
/* t, in the language in scope where it's rendered */
CSERVE_NODE *cserve_tr(CSERVE_ARENA *a, const CSERVE_TR *t);
/* the nodes, no element around them (NULL-terminated; the macro adds it) */
CSERVE_NODE *cserve_fragment_(CSERVE_ARENA *a, ...);
#define cserve_fragment(...) cserve_fragment_(__VA_ARGS__, NULL)
/* nothing: an empty fragment, for a child that's there only sometimes */
CSERVE_NODE *cserve_nothing(void);
/* the doctype, then html */
CSERVE_NODE *cserve_document(CSERVE_ARENA *a, const CSERVE_NODE *html);

/* a fragment grown a node at a time (a list's items, a loop's) */
typedef struct CSERVE_LIST CSERVE_LIST;
CSERVE_LIST *cserve_list(CSERVE_ARENA *a);
void cserve_list_add(CSERVE_LIST *l, CSERVE_NODE *n);
CSERVE_NODE *cserve_list_node(const CSERVE_LIST *l);

/* n rendered (depth 0, language lang of langs; -1: none yet) into a
 * malloc'd string (*out, *len bytes, NUL-terminated): 0, or -1 with the
 * arena failed (why: cserve_arena_error) and *out NULL. An arena that
 * failed before render renders nothing. */
int cserve_render(CSERVE_ARENA *a, const CSERVE_NODE *n,
                  const CSERVE_LANGUAGES *langs, int lang, char **out,
                  size_t *len);

/* whether value, as an address, stays on the origin of the page it's on
 * (Element::staysOnThisOrigin): with tab, CR and LF taken out and leading
 * controls and spaces off, as a browser's URL parser does first, it has
 * no scheme and doesn't start with two slashes of either kind -- so
 * "/\r\n/host", which a browser reads as //host, doesn't */
int cserve_stays_on_origin(const char *value);

/* s (n bytes) escaped as text and attribute values are, to add */
void cserve_escape(void (*add)(void *ctx, const char *s, size_t n), void *ctx,
                   const char *s, size_t n);

#endif
