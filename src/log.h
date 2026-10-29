#ifndef CSERVE_LOG_H
#define CSERVE_LOG_H

/* What c-serve has to say (a request served, a CGI that failed), handed
 * to one process-wide hook: a host points it at its own log, or leaves
 * the default, which writes warnings to stderr and drops the rest. Set it
 * before any listener runs; it's read from every connection's thread. */

typedef enum {
  CSERVE_LOG_INFO, /* one line per request (the host's access log) */
  CSERVE_LOG_WARN, /* something went wrong that the client can't see */
} CSERVE_LOG_LEVEL;

/* line: one line, without its newline */
typedef void (*CSERVE_LOG_FN)(CSERVE_LOG_LEVEL level, const char *line,
                              void *ud);

/* fn (NULL: the default) gets every line from now on */
void cserve_log_set(CSERVE_LOG_FN fn, void *ud);

void cserve_logf(CSERVE_LOG_LEVEL level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif
