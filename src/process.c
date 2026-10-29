/* fork, pipe2, waitid, the close_range syscall: POSIX + Linux, not C11 */
#define _GNU_SOURCE
#include "process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* the child's fds while it sets itself up: above what it's given (0-2) */
#define HIGH_FD 3

/* tells the parent why we're giving up (errno), then gives up */
static _Noreturn void fail(int report) {
  int e = errno;
  (void)!write(report, &e, sizeof e);
  _exit(127);
}

/* fd moved to HIGH_FD or above (close-on-exec), so the dup2()s onto 0-2
 * can't overwrite it */
static int lift(int fd) {
  return fd < 0 || fd >= HIGH_FD ? fd : fcntl(fd, F_DUPFD_CLOEXEC, HIGH_FD);
}

/* every fd from 3 up close-on-exec: the report pipe stays until the exec
 * closes it (success) or fail() writes to it */
static void cloexec_rest(void) {
#ifdef SYS_close_range
  if (syscall(SYS_close_range, 3U, ~0U, 4U /* CLOSE_RANGE_CLOEXEC */) == 0) {
    return;
  }
#endif
  long max = sysconf(_SC_OPEN_MAX);
  for (int fd = 3; fd < (max > 0 && max < 65536 ? max : 65536); fd++) {
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  }
}

static _Noreturn void child(const CSERVE_SPAWN *s, int src[2], int report) {
  sigset_t none;
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, NULL);
  setpgid(0, 0);
  if ((report = lift(report)) < 0) {
    fail(report);
  }
  /* all lifted before any dup2(): one onto 0 could be the other's fd */
  for (int i = 0; i < 2; i++) {
    if ((src[i] = lift(src[i])) < 0) {
      fail(report);
    }
  }
  for (int i = 0; i < 2; i++) {
    if (dup2(src[i], i) < 0) {
      fail(report);
    }
  }
  if (s->cwd && chdir(s->cwd) != 0) {
    fail(report);
  }
  if (s->envp) {
    environ = (char **)s->envp; /* a plain store: fine after a fork */
  }
  cloexec_rest();
  /* a SIG_IGN of ours (SIGPIPE) would outlive the exec */
  for (int sig = 1; sig < NSIG; sig++) {
    if (sig != SIGKILL && sig != SIGSTOP) {
      signal(sig, SIG_DFL);
    }
  }
  execvp(s->argv[0], (char *const *)s->argv);
  fail(report);
}

static void close_fd(int *fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

int cserve_spawn(const CSERVE_SPAWN *s, CSERVE_PROC *p) {
  *p = (CSERVE_PROC){.pid = -1, .in = -1, .out = -1};
  if (!s->argv || !s->argv[0]) {
    errno = EINVAL;
    return -1;
  }
  /* [0] read, [1] write; stdin's is read by the child */
  int in[2] = {-1, -1}, out[2] = {-1, -1}, report[2] = {-1, -1}, null = -1;
  int e = 0;
  if ((s->in_pipe ? pipe2(in, O_CLOEXEC)
                  : (null = open("/dev/null", O_RDONLY | O_CLOEXEC))) < 0 ||
      pipe2(out, O_CLOEXEC) != 0 || pipe2(report, O_CLOEXEC) != 0) {
    e = errno;
  }
  pid_t pid = e ? -1 : fork();
  if (pid == 0) {
    int src[2] = {s->in_pipe ? in[0] : null, out[1]};
    child(s, src, report[1]);
  }
  if (pid < 0 && !e) {
    e = errno;
  }
  close_fd(&in[0]);
  close_fd(&out[1]);
  close_fd(&null);
  close_fd(&report[1]);
  if (!e) {
    /* EOF once it exec'd; an errno if it couldn't */
    int why = 0;
    ssize_t got;
    while ((got = read(report[0], &why, sizeof why)) < 0 && errno == EINTR) {
    }
    if (got == (ssize_t)sizeof why) {
      int status;
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      e = why ? why : EIO;
    }
  }
  close_fd(&report[0]);
  if (e) {
    close_fd(&in[1]);
    close_fd(&out[0]);
    errno = e;
    return -1;
  }
  p->pid = pid;
  p->in = in[1];
  p->out = out[0];
  fcntl(p->out, F_SETFL, fcntl(p->out, F_GETFL) | O_NONBLOCK);
  return 0;
}

static long now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* 1 once p has exited (still to be reaped), 0 at the deadline: peeked
 * every 10 ms (a CGI is usually gone by the time its stdout ends) */
static int exited_by(const CSERVE_PROC *p, long deadline) {
  for (;;) {
    siginfo_t si = {0};
    if (waitid(P_PID, (id_t)p->pid, &si, WEXITED | WNOHANG | WNOWAIT) != 0 ||
        si.si_pid != 0) {
      return 1;
    }
    if (now_ms() >= deadline) {
      return 0;
    }
    nanosleep(&(struct timespec){.tv_nsec = 10 * 1000 * 1000}, NULL);
  }
}

int cserve_spawn_wait(CSERVE_PROC *p, int timeout_ms) {
  close_fd(&p->in);
  close_fd(&p->out);
  if (p->pid <= 0) {
    return -1;
  }
  if (timeout_ms >= 0 && !exited_by(p, now_ms() + timeout_ms)) {
    kill(-p->pid, SIGKILL);
  }
  int status = 0;
  pid_t r;
  while ((r = waitpid(p->pid, &status, 0)) < 0 && errno == EINTR) {
  }
  p->pid = 0;
  if (r < 0) {
    return -1;
  }
  return WIFEXITED(status)     ? WEXITSTATUS(status)
         : WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                               : -1;
}
