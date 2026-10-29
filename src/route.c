#include "route.h"

#include <stdio.h>
#include <string.h>

static const struct {
  const char *name;
  unsigned bit;
} METHODS[] = {
    {"GET", CSERVE_GET},         {"HEAD", CSERVE_HEAD},
    {"POST", CSERVE_POST},       {"PUT", CSERVE_PUT},
    {"PATCH", CSERVE_PATCH},     {"DELETE", CSERVE_DELETE},
    {"OPTIONS", CSERVE_OPTIONS},
};

unsigned cserve_route_method(const char *method) {
  for (size_t i = 0; i < sizeof METHODS / sizeof *METHODS; i++) {
    if (!strcmp(method, METHODS[i].name)) {
      return METHODS[i].bit;
    }
  }
  return 0;
}

/* the next non-empty segment at *s: its start and length (0 at the end) */
static const char *segment(const char **s, size_t *len) {
  while (**s == '/') {
    (*s)++;
  }
  const char *start = *s;
  *len = strcspn(start, "/");
  *s += *len;
  return start;
}

/* text[0, len) into m's store: its copy, or NULL when it doesn't fit */
static const char *keep(CSERVE_ROUTE_MATCH *m, size_t *used, const char *text,
                        size_t len) {
  if (*used + len + 1 > sizeof m->store) {
    return NULL;
  }
  char *at = m->store + *used;
  memcpy(at, text, len);
  at[len] = '\0';
  *used += len + 1;
  return at;
}

int cserve_route_match(const char *pattern, const char *path,
                       CSERVE_ROUTE_MATCH *m) {
  m->n = 0;
  size_t used = 0;
  const char *pp = pattern, *sp = path;
  for (;;) {
    size_t pl, sl;
    const char *pseg = segment(&pp, &pl);
    if (pl == 1 && pseg[0] == '*') {
      /* the rest, from its next segment on, empty ones folded away */
      while (*sp == '/') {
        sp++;
      }
      for (const char *q = sp; *q;) {
        size_t ql;
        const char *qs = segment(&q, &ql);
        if (ql && qs[0] == '.') {
          return 0;
        }
      }
      if (m->n == CSERVE_ROUTE_PARAMS) {
        return 0;
      }
      const char *name = keep(m, &used, "*", 1);
      const char *value = name ? keep(m, &used, sp, strlen(sp)) : NULL;
      if (!value) {
        return 0;
      }
      m->p[m->n].name = name;
      m->p[m->n++].value = value;
      return 1;
    }
    const char *sseg = segment(&sp, &sl);
    if (pl == 0 || sl == 0) {
      return pl == 0 && sl == 0;
    }
    if (pl >= 2 && pseg[0] == '{' && pseg[pl - 1] == '}') {
      if (sseg[0] == '.' || m->n == CSERVE_ROUTE_PARAMS) {
        return 0;
      }
      const char *name = keep(m, &used, pseg + 1, pl - 2);
      const char *value = name ? keep(m, &used, sseg, sl) : NULL;
      if (!value) {
        return 0;
      }
      m->p[m->n].name = name;
      m->p[m->n++].value = value;
    } else if (pl != sl || memcmp(pseg, sseg, pl) != 0) {
      return 0;
    }
  }
}

const char *cserve_route_param(const CSERVE_ROUTE_MATCH *m, const char *name) {
  for (int i = 0; i < m->n; i++) {
    if (!strcmp(m->p[i].name, name)) {
      return m->p[i].value;
    }
  }
  return NULL;
}

/* GET answers HEAD too */
static unsigned allowed(unsigned methods) {
  return methods & CSERVE_GET ? methods | CSERVE_HEAD : methods;
}

int cserve_route_dispatch(const CSERVE_ROUTE *routes, int n,
                          const CSERVE_HTTPD_REQ *r, const char *body,
                          CSERVE_HTTPD_REPLY *rep) {
  unsigned want = cserve_route_method(r->method), allow = 0;
  CSERVE_ROUTE_MATCH m;
  for (int i = 0; i < n; i++) {
    if (!cserve_route_match(routes[i].pattern, r->path, &m)) {
      continue;
    }
    if (want & allowed(routes[i].methods)) {
      routes[i].fn(r, body, &m, rep);
      return 1;
    }
    allow |= allowed(routes[i].methods);
  }
  if (!allow) {
    return 0;
  }
  /* "Allow: GET, HEAD, POST\r\n", in METHODS' order */
  size_t k = (size_t)snprintf(rep->headers, sizeof rep->headers, "Allow:");
  const char *sep = " ";
  for (size_t i = 0; i < sizeof METHODS / sizeof *METHODS; i++) {
    if (allow & METHODS[i].bit) {
      k += (size_t)snprintf(rep->headers + k, sizeof rep->headers - k, "%s%s",
                            sep, METHODS[i].name);
      sep = ", ";
    }
  }
  snprintf(rep->headers + k, sizeof rep->headers - k, "\r\n");
  static const char TEXT[] = "method not allowed\n";
  cserve_httpd_text(rep, 405, "text/plain; charset=utf-8", TEXT,
                    sizeof TEXT - 1);
  return 1;
}
