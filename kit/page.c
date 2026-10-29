#include "page.h"

#include "html.h"
#include "log.h"
#include "reading.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

int cserve_page_language(const CSERVE_SITE *site, const CSERVE_HTTPD_REQ *r) {
  char tag[16];
  if (site->cookie && cserve_cookie_get(cserve_httpd_header(r, "Cookie"),
                                        site->cookie, tag, sizeof tag) == 0) {
    int l = cserve_language_of(site->languages, tag);
    if (l >= 0) {
      return l;
    }
  }
  return cserve_accept_language(cserve_httpd_header(r, "Accept-Language"),
                                site->languages->tags, site->languages->n);
}

static pthread_once_t g_psa = PTHREAD_ONCE_INIT;
static int g_psa_ok;

static void psa_up(void) { g_psa_ok = psa_crypto_init() == PSA_SUCCESS; }

void cserve_page_fingerprint(const char *body, size_t len, char out[33]) {
  unsigned char hash[32];
  size_t n = 0;
  pthread_once(&g_psa, psa_up);
  if (!g_psa_ok ||
      psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)body, len, hash,
                       sizeof hash, &n) != PSA_SUCCESS ||
      n != sizeof hash) {
    memset(hash, 0, sizeof hash); /* a validator nothing matches but itself */
  }
  for (int i = 0; i < 16; i++) {
    snprintf(out + 2 * i, 3, "%02x", hash[i]);
  }
}

static void failed(CSERVE_HTTPD_REPLY *rep, const CSERVE_HTTPD_REQ *r,
                   const char *why) {
  cserve_logf(CSERVE_LOG_WARN, "%s %s: the page failed: %s", r->method,
              r->target, why);
  *rep = (CSERVE_HTTPD_REPLY){0};
  static const char TEXT[] = "500 Internal Server Error\n";
  cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", TEXT,
                    sizeof TEXT - 1);
}

void cserve_page(const CSERVE_SITE *site, const CSERVE_HTTPD_REQ *r,
                 CSERVE_ARENA *a, const CSERVE_VIEW *v, int status,
                 CSERVE_HTTPD_REPLY *rep) {
  int lang = cserve_page_language(site, r);
  const CSERVE_NODE *page;
  if (cserve_requested_xhr(r)) {
    /* led by a <title>, so Navigation reads the new page's title out of
     * it, escaped by the same rule as the rest */
    page = cserve_fragment(a,
                           cserve_containing(a, cserve_el(a, &cserve_tag_title),
                                             cserve_tr(a, v->title)),
                           v->content);
  } else {
    page = site->shell(a, v, lang, site->ud);
  }
  char *body;
  size_t len;
  if (cserve_render(a, page, site->languages, lang, &body, &len) != 0) {
    failed(rep, r, cserve_arena_error(a));
    return;
  }
  char etag[36], fp[33];
  cserve_page_fingerprint(body, len, fp);
  snprintf(etag, sizeof etag, "\"%s\"", fp);
  int keeps = cserve_header_has(rep, CSERVE_H_CACHE_CONTROL);
  int validates = status >= 200 && status < 300 && !keeps;
  /* the caller's headers go after the page's, as ViewResponse puts them */
  char theirs[sizeof rep->headers];
  memcpy(theirs, rep->headers, sizeof theirs);
  rep->headers[0] = '\0';
  int bad = 0;
  if (validates &&
      cserve_etag_matches(cserve_httpd_header(r, "If-None-Match"), fp)) {
    free(body);
    rep->status = 304;
    bad = cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                        cserve_cache_value(CSERVE_CACHE_NO_CACHE)) ||
          cserve_header(rep, CSERVE_H_ETAG, etag) ||
          cserve_header(rep, CSERVE_H_VARY,
                        "X-Requested-With, Accept-Language, Cookie");
    if (bad) {
      failed(rep, r, "the 304's headers don't fit");
    }
    return;
  }
  bad = cserve_header(rep, CSERVE_H_CONTENT_LANGUAGE,
                      site->languages->tags[lang]) ||
        (!keeps && cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                                 cserve_cache_value(CSERVE_CACHE_NO_CACHE))) ||
        (validates && cserve_header(rep, CSERVE_H_ETAG, etag)) ||
        cserve_header(rep, CSERVE_H_VARY,
                      "X-Requested-With, Accept-Language, Cookie");
  size_t used = strlen(rep->headers), more = strlen(theirs);
  if (bad || used + more >= sizeof rep->headers) {
    free(body);
    failed(rep, r, "the page's headers don't fit");
    return;
  }
  memcpy(rep->headers + used, theirs, more + 1);
  cserve_httpd_take(rep, status, "text/html; charset=utf-8", body, len);
}
