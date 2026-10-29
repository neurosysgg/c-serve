#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void to_stderr(CSERVE_LOG_LEVEL level, const char *line, void *ud) {
  (void)ud;
  if (level == CSERVE_LOG_WARN) {
    fprintf(stderr, "c-serve: %s\n", line);
  }
}

static CSERVE_LOG_FN g_fn = to_stderr;
static void *g_ud;

void cserve_log_set(CSERVE_LOG_FN fn, void *ud) {
  g_fn = fn ? fn : to_stderr;
  g_ud = fn ? ud : NULL;
}

void cserve_logf(CSERVE_LOG_LEVEL level, const char *fmt, ...) {
  char line[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof line, fmt, ap);
  va_end(ap);
  /* one line: a trailing newline of the caller's goes */
  size_t n = strlen(line);
  if (n && line[n - 1] == '\n') {
    line[n - 1] = '\0';
  }
  g_fn(level, line, g_ud);
}
