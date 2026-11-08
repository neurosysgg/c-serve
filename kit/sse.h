#ifndef CSERVE_SSE_H
#define CSERVE_SSE_H

#include "httpd.h"

#include <stddef.h>

/* Server-sent events (the HTML standard's text/event-stream) on a loop
 * stream (loop.h): an event written so nothing in it can start a field
 * of its own -- every CR, LF or CRLF in its data begins a new "data:"
 * line -- the heartbeat, the client's Last-Event-ID, and the reply set
 * up as a stream. */

/* the heartbeat: a comment, which a client ignores */
#define CSERVE_SSE_HEARTBEAT ":\n\n"

/* an event into out: "id: N" (id >= 0; < 0 none), "event: NAME" (NULL
 * none; [A-Za-z0-9_-], 1-32 bytes), data's n bytes as "data:" lines,
 * then the blank line. Its length, or -1 (a bad name, a NUL in data, or
 * no room in cap) */
long cserve_sse_event(char *out, size_t cap, long long id, const char *event,
                      const char *data, size_t n);

/* the Last-Event-ID a reconnecting client sent, as a whole number into
 * *id: 1, or 0 when there's none or it isn't one (0 to 2^53) */
int cserve_sse_last_id(const CSERVE_HTTPD_REQ *r, long long *id);

/* rep as an event stream: 200, text/event-stream, not cached, pull and
 * done and opened on ud (httpd.h's stream) */
void cserve_sse_reply(CSERVE_HTTPD_REPLY *rep,
                      long (*pull)(void *ud, char *buf, size_t cap),
                      void (*done)(void *ud),
                      void (*opened)(void *ud, CSERVE_STREAM s), void *ud);

#endif
