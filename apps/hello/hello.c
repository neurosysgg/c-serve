/* the test app: what the host's ABI, its router, both ways of linking an
 * app (dlopen()ed, built in) and the toolkit (kit/) have to answer --
 * pages in a shell, in two languages, as a document or as the SPA's
 * fragment, validated; a phrase; the language switch's cookie; its own
 * 404, 405 and OPTIONS, and its security headers; a file from its data
 * behind a password, in ranges */
#include "app.h"
#include "file.h"
#include "headers.h"
#include "html.h"
#include "login.h"
#include "markup.h"
#include "page.h"
#include "password.h"
#include "reading.h"
#include "text.h"

#include <stdio.h>
#include <string.h>

/* every word it says, in English and German: one missing is a compiler
 * error */
#define T(id, en, de) static const CSERVE_TEXT id = CSERVE_TEXT_IN(en, de)
T(SITE_NAME, "hello", "hallo");
T(GREETING, "hello, {name} (from {root})", "hallo, {name} (aus {root})");
T(NOT_FOUND, "nothing at {path}", "nichts unter {path}");
T(NOT_FOUND_TITLE, "not found", "nicht gefunden");
T(SWITCH, "deutsch", "english");
T(READ_ONLY, "hello is read-only.", "hallo ist schreibgesch\xC3\xBCtzt.");
#undef T
static const CSERVE_TEXT *const TEXTS[] = {
    &SITE_NAME, &GREETING, &NOT_FOUND, &NOT_FOUND_TITLE, &SWITCH, &READ_ONLY};

static const CSERVE_LANGUAGES LANGS = {{"en", "de"}, 2};

static char g_root[256], g_data[256];

/* "open sesame", user "hello": a test's password, nobody's secret */
static const char DIGEST[] = "$pbkdf2-sha256$100000$aGhoaGhoaGhoaGhoaGhoaA==$"
                             "Q6BUTVDg4JmC3fbGn2UQW2VqnUApAFQdUVTYYah0k1s=";

#define EL(t) cserve_el(a, &cserve_tag_##t)
#define ATTR(n, attr, v) cserve_attr(a, n, &cserve_attr_##attr, v)
#define FLAG(n, attr) cserve_attr_bool(a, n, &cserve_attr_##attr, 1)
#define HAS(n, ...) cserve_containing(a, n, __VA_ARGS__)

/* the document around a page: <html lang>, its title, <main id=content>
 * and a footer linking to the other language */
static const CSERVE_NODE *shell(CSERVE_ARENA *a, const CSERVE_VIEW *v, int lang,
                                void *ud) {
  (void)ud;
  const char *other = LANGS.tags[!lang];
  CSERVE_NODE *to_other = ATTR(
      FLAG(ATTR(EL(a), href, cserve_arena_printf(a, "/language/%s", other)),
           data_no_spa),
      lang, other);
  return cserve_document(
      a, HAS(ATTR(EL(html), lang, LANGS.tags[lang]),
             HAS(EL(head), ATTR(EL(meta), charset, "UTF-8"),
                 HAS(EL(title), cserve_tr(a, v->title))),
             HAS(EL(body), HAS(ATTR(EL(main), id, "content"), v->content),
                 HAS(FLAG(EL(footer), data_language_bound),
                     HAS(to_other, cserve_tr(a, &SWITCH))))));
}

static const CSERVE_SITE SITE = {&LANGS, "lang", shell, NULL};

/* a page titled "title -- hello" (View::title()'s way: the fragment's
 * title is the document's), of one paragraph saying t, built in a */
static void page(const CSERVE_HTTPD_REQ *r, CSERVE_ARENA *a,
                 const CSERVE_TR *title, const CSERVE_TR *t, int status,
                 CSERVE_HTTPD_REPLY *rep) {
  CSERVE_VIEW v = {cserve_joined(a, " \xE2\x80\x94 ", title, &SITE_NAME),
                   HAS(EL(p), cserve_tr(a, t))};
  cserve_page(&SITE, r, a, &v, status, rep);
}

static void hello(const CSERVE_HTTPD_REQ *r, const char *body,
                  const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)body;
  const char *name = cserve_route_param(m, "name");
  name = name ? name : "world";
  CSERVE_ARENA *a = cserve_arena_new();
  if (!a) {
    cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
    return;
  }
  page(r, a, cserve_verbatim(a, name),
       cserve_phrase(a, &GREETING, "name", name, "root", g_root), 200, rep);
  cserve_arena_free(a);
}

/* /language/{language}: the cookie set, and back where the visitor came
 * from -- the Referer's path, when it stays on this origin and isn't the
 * switch itself -- or home (LanguageController) */
static void language(const CSERVE_HTTPD_REQ *r, const char *body,
                     const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)body;
  const char *tag = cserve_route_param(m, "language");
  if (cserve_language_of(&LANGS, tag) < 0) {
    CSERVE_ARENA *a = cserve_arena_new();
    if (a) {
      page(r, a, &NOT_FOUND_TITLE, &NOT_FOUND_TITLE, 404, rep);
    }
    cserve_arena_free(a);
    return;
  }
  const char *back = "/", *referer = cserve_httpd_header(r, "Referer");
  const char *path = referer ? strstr(referer, "://") : NULL;
  path = path ? strchr(path + 3, '/') : NULL;
  if (path && cserve_stays_on_origin(path) &&
      strncmp(path, "/language/", 10) != 0) {
    back = path;
  }
  char cookie[96];
  snprintf(cookie, sizeof cookie,
           "lang=%s; Path=/; Max-Age=31536000; SameSite=Lax; Secure; HttpOnly",
           tag);
  if (cserve_header(rep, CSERVE_H_LOCATION, back) != 0 ||
      cserve_header(rep, CSERVE_H_SET_COOKIE, cookie) != 0 ||
      cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                    cserve_cache_value(CSERVE_CACHE_NO_STORE)) != 0) {
    rep->headers[0] = '\0';
    cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
    return;
  }
  cserve_httpd_text(rep, 303, NULL, "", 0);
}

/* /hello-file/{name}: data/name, behind Basic and in ranges -- the 401
 * the same for a file there is and one there isn't, and a wrong password
 * slowed down (login.h), the file being the account tried */
static void hello_file(const CSERVE_HTTPD_REQ *r, const char *body,
                       const CSERVE_ROUTE_MATCH *m, CSERVE_HTTPD_REPLY *rep) {
  (void)body;
  char user[64], pass[128], path[512];
  const char *auth = cserve_httpd_header(r, "Authorization");
  const char *account = cserve_route_param(m, "name");
  if (auth && cserve_login_check(r, account, rep)) {
    return;
  }
  cserve_basic_credentials(auth, user, sizeof user, pass, sizeof pass);
  int user_ok = strcmp(user, "hello") == 0;
  int pass_ok = cserve_password_matches(DIGEST, pass, strlen(pass));
  if (!user_ok || !pass_ok) {
    char realm[160], name[128];
    if (cserve_rawurlencode(cserve_route_param(m, "name"), name, sizeof name) !=
            0 ||
        snprintf(realm, sizeof realm, "hello: %s", name) >= (int)sizeof realm ||
        cserve_basic_challenge(rep, realm) != 0) {
      rep->headers[0] = '\0';
      cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
      return;
    }
    cserve_httpd_text(rep, 401, "text/plain; charset=utf-8", "", 0);
    if (auth) {
      cserve_login_fail(r, account, rep);
    }
    return;
  }
  cserve_login_pass(r, account);
  if (!*g_data ||
      snprintf(path, sizeof path, "%s/%s", g_data,
               cserve_route_param(m, "name")) >= (int)sizeof path ||
      cserve_file_reply(r, path, "text/plain", rep) != 0) {
    if (!rep->status) {
      cserve_httpd_text(rep, 404, "text/plain; charset=utf-8", "", 0);
    }
    return;
  }
  if (cserve_header(rep, CSERVE_H_X_ROBOTS_TAG, "noindex") != 0) {
    rep->status = 500;
  }
}

/* a method none of its routes take: an OPTIONS is told which they do
 * (204), anything else that this is read-only, in the visitor's
 * language (405) */
static void refuse(const CSERVE_HTTPD_REQ *r, const char *body, unsigned allow,
                   CSERVE_HTTPD_REPLY *rep) {
  (void)body;
  char methods[64];
  if (!strcmp(r->method, "OPTIONS")) {
    cserve_route_allow_text(allow | CSERVE_OPTIONS, methods, sizeof methods);
    if (cserve_header(rep, CSERVE_H_ALLOW, methods) == 0) {
      cserve_httpd_text(rep, 204, NULL, "", 0);
    }
    return;
  }
  cserve_route_allow_text(allow, methods, sizeof methods);
  CSERVE_ARENA *a = cserve_arena_new();
  const char *words =
      a ? cserve_tr_in(a, &READ_ONLY, cserve_page_language(&SITE, r)) : NULL;
  char text[128];
  if (words &&
      cserve_header(rep, CSERVE_H_CACHE_CONTROL,
                    cserve_cache_value(CSERVE_CACHE_NO_STORE)) == 0 &&
      cserve_header(rep, CSERVE_H_ALLOW, methods) == 0) {
    int n = snprintf(text, sizeof text, "%s\n", words);
    cserve_httpd_text(rep, 405, "text/plain; charset=utf-8", text, (size_t)n);
  }
  cserve_arena_free(a);
}

static void not_found(const CSERVE_HTTPD_REQ *r, const char *body,
                      CSERVE_HTTPD_REPLY *rep) {
  (void)body;
  CSERVE_ARENA *a = cserve_arena_new();
  if (!a) {
    cserve_httpd_text(rep, 500, "text/plain; charset=utf-8", "", 0);
    return;
  }
  page(r, a, &NOT_FOUND_TITLE, cserve_phrase(a, &NOT_FOUND, "path", r->path),
       404, rep);
  cserve_arena_free(a);
}

static const CSERVE_ROUTE ROUTES[] = {
    {CSERVE_GET, "/hello", hello},
    {CSERVE_GET, "/hello/{name}", hello},
    {CSERVE_GET, "/language/{language}", language},
    {CSERVE_GET, "/hello-file/{name}", hello_file},
};

static const char *const IMAGES[] = {"https://images.example", NULL};
static const CSERVE_SECURITY SECURITY = {.img = IMAGES};

static int init(const CSERVE_APP_ENV *env, char *err, size_t err_cap) {
  cserve_login_use(env->tarpit);
  if (cserve_texts_complete(TEXTS, sizeof TEXTS / sizeof *TEXTS, LANGS.n, err,
                            err_cap) != 0) {
    return -1;
  }
  if (snprintf(g_root, sizeof g_root, "%s", env->root) >= (int)sizeof g_root) {
    snprintf(err, err_cap, "a root too long for hello");
    return -1;
  }
  if (snprintf(g_data, sizeof g_data, "%s", env->data ? env->data : "") >=
      (int)sizeof g_data) {
    snprintf(err, err_cap, "a data directory too long for hello");
    return -1;
  }
  return 0;
}

const CSERVE_APP cserve_app_hello = {
    CSERVE_APP_HEADER("hello"), .init = init,
    .routes = ROUTES,           .nroutes = sizeof ROUTES / sizeof *ROUTES,
    .security = &SECURITY,      .not_found = not_found,
    .refuse = refuse,
};
