#ifndef CSERVE_HTML_H
#define CSERVE_HTML_H

#include "markup.h"

/* HTML's own tags and attributes, as phpanta's HtmlTag and HtmlAttribute
 * (and LinkAttribute, RegionAttribute) name them: cserve_tag_div,
 * cserve_attr_aria_label. What each tag is to render (void, phrasing, an
 * inline container, raw text) is said once, here. An app's own elements
 * and attributes are CSERVE_TAG / CSERVE_ATTR of its own, written the
 * same way; a name in this list is never spelled as a string. */

/* X(tag, flags) */
#define CSERVE_HTML_TAGS(X)                                                    \
  X(html, 0)                                                                   \
  X(head, 0)                                                                   \
  X(meta, CSERVE_TAG_VOID)                                                     \
  X(link, CSERVE_TAG_VOID)                                                     \
  X(title, 0)                                                                  \
  X(script, CSERVE_TAG_RAW_TEXT)                                               \
  X(body, 0)                                                                   \
  X(header, 0)                                                                 \
  X(nav, 0)                                                                    \
  X(main, 0)                                                                   \
  X(footer, 0)                                                                 \
  X(section, 0)                                                                \
  X(h1, 0)                                                                     \
  X(h2, 0)                                                                     \
  X(h3, 0)                                                                     \
  X(h4, 0)                                                                     \
  X(p, 0)                                                                      \
  X(ul, 0)                                                                     \
  X(li, 0)                                                                     \
  X(br, CSERVE_TAG_VOID | CSERVE_TAG_PHRASING)                                 \
  X(a, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                                \
  X(img, CSERVE_TAG_VOID | CSERVE_TAG_PHRASING)                                \
  X(button, CSERVE_TAG_PHRASING)                                               \
  X(span, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                             \
  X(small, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                            \
  X(strong, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                           \
  X(em, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                               \
  X(div, 0)                                                                    \
  X(audio, CSERVE_TAG_PHRASING)                                                \
  X(video, CSERVE_TAG_PHRASING)                                                \
  X(iframe, CSERVE_TAG_PHRASING | CSERVE_TAG_RAW_TEXT)                         \
  X(canvas, CSERVE_TAG_PHRASING)                                               \
  X(textarea, CSERVE_TAG_PHRASING)                                             \
  X(pre, 0)                                                                    \
  X(meter, CSERVE_TAG_PHRASING)                                                \
  X(table, 0)                                                                  \
  X(tr, 0)                                                                     \
  X(th, 0)                                                                     \
  X(td, 0)                                                                     \
  X(tbody, 0)                                                                  \
  X(form, 0)                                                                   \
  X(input, CSERVE_TAG_VOID | CSERVE_TAG_PHRASING)                              \
  X(label, CSERVE_TAG_PHRASING | CSERVE_TAG_INLINE)                            \
  X(select, CSERVE_TAG_PHRASING)                                               \
  X(option, 0)                                                                 \
  X(fieldset, 0)                                                               \
  X(legend, 0)

/* X(identifier, name, whether its value is an address) */
#define CSERVE_HTML_ATTRS(X)                                                   \
  X(class, "class", 0)                                                         \
  X(id, "id", 0)                                                               \
  X(lang, "lang", 0)                                                           \
  X(title, "title", 0)                                                         \
  X(href, "href", 1)                                                           \
  X(hreflang, "hreflang", 0)                                                   \
  X(src, "src", 1)                                                             \
  X(rel, "rel", 0)                                                             \
  X(target, "target", 0)                                                       \
  X(type, "type", 0)                                                           \
  X(download, "download", 0)                                                   \
  X(alt, "alt", 0)                                                             \
  X(height, "height", 0)                                                       \
  X(width, "width", 0)                                                         \
  X(charset, "charset", 0)                                                     \
  X(name, "name", 0)                                                           \
  X(content, "content", 0)                                                     \
  X(controls, "controls", 0)                                                   \
  X(preload, "preload", 0)                                                     \
  X(aria_label, "aria-label", 0)                                               \
  X(aria_live, "aria-live", 0)                                                 \
  X(aria_describedby, "aria-describedby", 0)                                   \
  X(action, "action", 1)                                                       \
  X(method, "method", 0)                                                       \
  X(enctype, "enctype", 0)                                                     \
  X(value, "value", 0)                                                         \
  X(for, "for", 0)                                                             \
  X(required, "required", 0)                                                   \
  X(maxlength, "maxlength", 0)                                                 \
  X(autocomplete, "autocomplete", 0)                                           \
  X(checked, "checked", 0)                                                     \
  X(selected, "selected", 0)                                                   \
  X(readonly, "readonly", 0)                                                   \
  X(disabled, "disabled", 0)                                                   \
  X(hidden, "hidden", 0)                                                       \
  X(multiple, "multiple", 0)                                                   \
  X(min, "min", 0)                                                             \
  X(max, "max", 0)                                                             \
  X(placeholder, "placeholder", 0)                                             \
  X(data_no_spa, "data-no-spa", 0)                                             \
  X(data_language_bound, "data-language-bound", 0)

#define CSERVE_HTML_TAG_DECL(t, f) extern const CSERVE_TAG cserve_tag_##t;
CSERVE_HTML_TAGS(CSERVE_HTML_TAG_DECL)
#undef CSERVE_HTML_TAG_DECL
#define CSERVE_HTML_ATTR_DECL(id, n, u)                                        \
  extern const CSERVE_ATTR cserve_attr_##id;
CSERVE_HTML_ATTRS(CSERVE_HTML_ATTR_DECL)
#undef CSERVE_HTML_ATTR_DECL

#endif
