#include "html.h"

#define TAG(t, f) const CSERVE_TAG cserve_tag_##t = {#t, f};
CSERVE_HTML_TAGS(TAG)
#define ATTR(id, n, u) const CSERVE_ATTR cserve_attr_##id = {n, u};
CSERVE_HTML_ATTRS(ATTR)
