#ifndef CSERVE_HTTPD_H
#define CSERVE_HTTPD_H

#include "conn.h"

#include <stddef.h>

/* The server side's HTTP/1.1: a request's head parsed (pure: the tests
 * and the fuzzer take it on buffers), its body read by Content-Length (a
 * chunked request body is refused: 411), a reply written, and a
 * connection served request after request (keep-alive) with a handler
 * answering each. Origin-form targets only ("/path?query"). */

#define CSERVE_HTTPD_HEAD_MAX 16384 /* a request's head, all of it */
#define CSERVE_HTTPD_HEADERS 64

typedef struct {
  char method[16];
  char target[4096]; /* as sent */
  char path[4096];   /* the target's path, percent-decoded ("/a b") */
  const char *query; /* in target, after '?' ("" if none) */
  int minor;         /* HTTP/1.minor */
  int n;
  struct {
    const char *name, *value; /* in the parsed head, trimmed */
  } h[CSERVE_HTTPD_HEADERS];
  long long length; /* Content-Length, -1 none */
  int keep_alive;   /* the client wants the connection kept */
  /* set by serve() (parse() leaves them NULL): the peer's address as
   * text, the connection (its TLS peer: cserve_conn_peer_cert()) */
  const char *peer;
  CSERVE_CONN *conn;
  /* set by the loop (loop.h; the threaded server leaves them 0, and conn
   * is NULL on the loop): the peer's address family (4 or 6, an IPv4
   * address mapped into IPv6 counted as 4) and its network, the part a
   * limit or a penalty keys on -- an IPv4 address whole, an IPv6 one's
   * /64 -- in its first 4 or 8 bytes, the rest zero */
  int peer_family;
  unsigned char peer_net[16];
  /* set by the loop: 1 when the request came over TLS (the threaded
   * server leaves it 0) */
  int tls;
} CSERVE_HTTPD_REQ;

/* the head (buf: its lines up to and without the blank line, NUL-
 * terminated; the request keeps pointers into it, and it's cut up in
 * place) into r: 0, or an HTTP status to refuse it with (400, 411, 414,
 * 431, 501, 505) and why in err */
int cserve_httpd_parse(char *buf, CSERVE_HTTPD_REQ *r, char *err,
                       size_t err_cap);
/* The head found in bytes as they come (pure), for a server that reads
 * what's there rather than a line at a time (loop.h): the rules the
 * threaded server's line reader keeps -- lines end in LF or CRLF, up to
 * 4 empty lines before the request line are skipped, the head ends at
 * the first empty line after it, and no line nor the head as a whole is
 * longer than cap. Each call is handed every byte so far (buf, n: the
 * same bytes as the last call's and maybe more) and f, zeroed before the
 * first, carries where the last one stopped, so each byte is looked at
 * once. The head's lines go into out (cap bytes), each ending in LF and
 * the whole NUL-terminated: what cserve_httpd_parse() takes. 1 when the
 * head is complete (f->pos: the bytes it took, f->len: its length in
 * out), 0 while more bytes are needed, -1 to refuse it: *status says
 * with what (400, 431), or 0 to close without a word (a first line
 * too long to be a request). */
typedef struct {
  size_t pos; /* buf's bytes looked at */
  size_t len; /* out's */
  int lines;  /* the head's lines so far */
  int blanks; /* empty lines before the request line */
} CSERVE_HTTPD_FRAME;

int cserve_httpd_frame(CSERVE_HTTPD_FRAME *f, const char *buf, size_t n,
                       char *out, size_t cap, int *status, char *err,
                       size_t err_cap);

/* header name's value (case-insensitive name, the first one), or NULL */
const char *cserve_httpd_header(const CSERVE_HTTPD_REQ *r, const char *name);
/* status's reason phrase ("Not Found"; "" for one it doesn't know) */
const char *cserve_httpd_reason(int status);

/* a pull's "nothing now" (a stream's: below) */
#define CSERVE_PULL_WAIT (-2)

/* a stream's handle: which connection, and which use of its slot -- a
 * wake for one that has gone lands on nothing */
typedef struct {
  void *loop;
  int slot;
  unsigned gen;
} CSERVE_STREAM;

/* what a handler answers: status, the body (len bytes; free it if
 * owned), its Content-Type, extra header lines (each ending in CRLF; may
 * be NULL). Or, with pull set, a body of unknown length, pulled a piece
 * at a time once the head is out: pull() puts up to cap bytes in buf and
 * says how many, 0 at the end, -1 when it failed part-way. It is called
 * only while the client takes the body (never for HEAD, 204 or 304), and
 * done() is called once after, always -- also when pull() never was, or
 * the client went -- and frees pull_ud. A server that serves connections
 * from one loop (loop.h) pulls from that loop, so a pull returns as soon
 * as a file read does; only the threaded server (serve() below) lets one
 * wait (cgi.h's). The body goes out chunked (HTTP/1.1, the connection
 * kept) or until the connection closes (HTTP/1.0). */
typedef struct {
  int status;
  const char *type;
  char *body;
  size_t len;
  int owned; /* body is malloc'd: freed after it's sent */
  char headers[4096];
  long (*pull)(void *ud, char *buf, size_t cap);
  void (*done)(void *ud);
  void *pull_ud;
  /* > 0: the pulled body's exact length, said as Content-Length (no
   * chunks, the connection kept, a HEAD told it too); a body that comes
   * out shorter or longer fails, and the connection closes */
  long long stream_length;
  /* > 0: the loop (loop.h) holds the reply back this long before it
   * sends it -- a failed login's, from the tarpit (tarpit.h): the
   * connection waits on a timer, no worker does. The threaded server
   * sends it at once. */
  long delay_ms;
  /* A stream (the loop's alone, loop.h): a pulled body that stays open.
   * Its pull may return CSERVE_PULL_WAIT -- nothing now -- and the loop
   * parks the connection until cserve_stream_wake() says there's news
   * or the heartbeat comes round, then pulls again. opened(pull_ud, s)
   * runs on the loop's thread before the head goes, with the handle a
   * waker uses; done() is still called once at the end. A stream is
   * chunked and never keeps its connection. The threaded server refuses
   * one (a 500). */
  int stream;
  void (*opened)(void *ud, CSERVE_STREAM s);
} CSERVE_HTTPD_REPLY;

/* the reply's body let go: an owned one freed, a pull's done() called
 * (once: pull is cleared) */
void cserve_httpd_release(CSERVE_HTTPD_REPLY *rep);

/* The reply's head, as both servers write it (pure): status line, the
 * Server header (server "" or NULL: none), the length or chunking, the
 * type, Connection (keep), rep's own lines, the blank line -- into buf
 * (cap bytes): its length, or -1 when it doesn't fit. *chunked says
 * whether the body goes out in chunks, *body whether any body follows
 * the head at all (not for HEAD, 1xx, 204, 304). r NULL: a refusal sent
 * before a request was understood. */
int cserve_httpd_head(const char *server, const CSERVE_HTTPD_REQ *r,
                      const CSERVE_HTTPD_REPLY *rep, int keep, char *buf,
                      size_t cap, int *chunked, int *body);

/* whether the connection can carry another request after this reply
 * (more: the per-connection limit allows one): the client asked, and a
 * pulled body of unknown length doesn't end with the connection (HTTP/1.0,
 * or a HEAD, which is said without framing) */
int cserve_httpd_keep(const CSERVE_HTTPD_REQ *r, const CSERVE_HTTPD_REPLY *rep,
                      int more);

/* the reply's text as body: a copy (owned), or a 500 */
void cserve_httpd_text(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       const char *body, size_t len);

/* one request's handler: r and its body (length bytes of it, NUL-
 * terminated; NULL without one) in, rep filled (status 0: a 500) */
typedef void (*CSERVE_HTTPD_FN)(const CSERVE_HTTPD_REQ *r, const char *body,
                                CSERVE_HTTPD_REPLY *rep, void *ud);

typedef struct {
  CSERVE_HTTPD_FN handler;
  void *ud;
  const char *server; /* the Server header ("" or NULL: none) */
  long long body_max; /* a request body's limit (413 past it; 1 MiB) */
  int idle_ms;        /* waiting for the next request (10 s) */
  int timeout_ms;     /* reading one, writing its reply (30 s) */
  int max_requests;   /* on one connection (100) */
} CSERVE_HTTPD;

/* c served until the client closes, a request asks to, a limit is hit or
 * something fails; c closed then. peer is logged only. */
void cserve_httpd_serve(const CSERVE_HTTPD *h, CSERVE_CONN *c,
                        const char *peer);

/* s handed to add with &<>"' as entities (HTML text or an attribute
 * value), a run at a time: whatever buffer the caller keeps */
void cserve_httpd_escape(void (*add)(void *ctx, const char *s, size_t n),
                         void *ctx, const char *s);
/* body (malloc'd, len bytes; NULL: none) as the reply's, handed over */
void cserve_httpd_take(CSERVE_HTTPD_REPLY *rep, int status, const char *type,
                       char *body, size_t len);

#endif
