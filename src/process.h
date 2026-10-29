#ifndef CSERVE_PROCESS_H
#define CSERVE_PROCESS_H

#include <sys/types.h>

/* A program started for a request (cgi.c's php-cgi): in its own process
 * group (so a kill reaches what it started too), in cwd, with a whole
 * environment of its own -- set from a threaded server without touching
 * ours between fork and exec. Its stdout is a pipe to us (non-blocking),
 * its stdin a pipe or /dev/null, its stderr ours. In the child: an empty
 * signal mask, every signal back to its default, nothing of ours open
 * past fd 2. (ctui-wm's base/spawn.c, the part a server uses.) */

typedef struct {
  const char *const *argv; /* execvp()'d */
  const char *cwd;         /* NULL: ours */
  const char *const *envp; /* NULL-terminated "K=V": its whole environment */
  int in_pipe;             /* stdin a pipe to us (else /dev/null) */
} CSERVE_SPAWN;

typedef struct {
  pid_t pid;
  int in, out; /* our ends (in: -1 without in_pipe); close-on-exec */
} CSERVE_PROC;

/* starts s: 0, or -1 with errno (the child's when it couldn't exec or
 * enter cwd: nothing to reap then) and *p all -1 */
int cserve_spawn(const CSERVE_SPAWN *s, CSERVE_PROC *p);

/* closes p's pipes, then waits for it at most timeout_ms (< 0: however
 * long) before a SIGKILL to its group, then for that. Its exit status,
 * 128 + the signal that ended it, or -1 if there's nothing to wait for */
int cserve_spawn_wait(CSERVE_PROC *p, int timeout_ms);

#endif
