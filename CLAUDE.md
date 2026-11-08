# Working on c-serve

An HTTP/1.1 server and client over TLS in C11 (README.md has the map). It was extracted from
ctui-wm's `plugins/net` on 2026-10-29, and ctui-wm consumes it as the `c-serve/` submodule. Where
it is headed — a web host with sites compiled in as apps, replacing neurosys.gg's PHP — is
`/srv/http/neurosys/docs/research/c-serve.md`; the earlier history of every file is in this
repo's log and in ctui-wm's HISTORY.md.

## Rules

- **`make check` passes before a commit**: ASan+UBSan, TSan, -O2, then lint. Lint has no
  baseline — a clang-tidy or cppcheck finding fails it; a check kept quiet is in the Makefile's
  list with ctui-wm's tools/lint.py saying why.
- **Every parser of outside input has a fuzz case** in `fuzz/`. A mode number, once given, is
  never reused: corpora outlive the code.
- **Dependencies stay libc, pthreads, mbedtls/tfpsacrypto and zlib** (and `-ldl` for the
  development host alone). No buffer type, no logger, no config of anyone's: a helper that needs
  a caller's buffer takes a callback (`cserve_httpd_escape`), and what the library says goes
  through `log.h`'s one hook, which a host points at its own log.
- **An app may be out of tree** (`EXTERNAL_APPS`), and is then held to every rule here: lint
  reaches it, and it carries a copy of `.clang-format`.
- **The app ABI only grows.** A slot is appended to `CSERVE_APP`, never inserted, renamed or
  retyped; a host reads one through `CSERVE_APP_SLOT`, so an app built against fewer slots
  still loads. Bump `CSERVE_APP_ABI` only for a break, and then every app is rebuilt.
- **A page is a tree, never a string.** Only `kit/markup.c` writes a `<`; lint fails a string
  literal holding a tag anywhere else in `kit/` or `apps/`. Escaping and the URL check live in
  render, so they hold however a tree was built.
- **Every visible word is a `CSERVE_TEXT`**, declared through an app's macro that takes each of
  its languages, so a missing one is a compiler error; init() checks the catalog for blanks.
- **A builder that is refused fails the request's arena and returns something harmless**; render
  then fails and the page is a 500 with why in the log. Nothing in `kit/` aborts or exits.
- **`kit/` decides as phpanta does.** Its render and readers are checked case by case against
  `tests/data/goldens.h`, which neurosys's `test/cserve/goldens.php` prints from Phpanta itself:
  regenerate it, never edit it, and a disagreement is a bug here unless Phpanta's answer is wrong.
- **The host takes flags, not a config file**: a config parser would be one more parser of
  outside input.
- **No header is named like a system one, nor like another here.** ctui-wm puts `src/` on every
  `-I`, and `-I` is searched for `<...>` too: a `spawn.h` here shadowed POSIX's `<spawn.h>` there
  (hence `process.h`). `src/` and `kit/` are both on it as well, so a kit header named like a
  `src/` one is never the one included (hence `kit/login.h` beside `src/tarpit.h`). Check
  `/usr/include` and both trees before naming a new header.

## The loop

`cserve` serves on `src/loop.c`; the threaded server (`listen.c`, `httpd.c`'s `serve()`) is
ctui-remote's and `cserve-front`'s alone, and the box's binary never calls it.

- **Only an entry point does I/O or closes a connection** — accept, a connection's readiness,
  the pool's fd, a deadline — and it returns at once after closing one. What moves a connection
  between states only sets its state, deadline and events; the loop comes back to it. A transition
  that closed would leave its caller holding a freed connection.
- **Every handler runs on the pool; nothing an app does runs on the loop** — except a pull,
  which the loop calls as the socket takes bytes. So a pull returns as soon as a file read does;
  one that waits (cgi.c's) is the threaded server's alone.
- **A connection that closes after its last reply lingers**: write side shut, what still comes
  read and dropped. A plain `close()` with unread bytes makes the kernel reset the connection,
  and the reset throws away the reply's unsent tail.
- **`tls.h`'s client wants a non-blocking socket.** Handed a blocking one it waits in `recv()`
  inside mbedtls, holding the process's TLS lock, and the loop's next handshake waits on that lock.
- **A TLS connection holds the certificate set it began under** (tls.c's refcount, under the TLS
  lock), so a reload never frees a config a handshake or a session still points at. A reload runs
  on the loop's thread (`cserve_loop_watch()`); a set that doesn't load leaves the old one.
- **The ACME account key never enters `cserve`.** `cserve-acme` is its own process and signals
  nothing; `cserve` only serves the answers it leaves in `--acme-dir`. `make acme` (Pebble) when
  either side changes.
- **mbedtls 4 parses an EC certificate through PSA**: `psa_crypto_init()` before the first
  `mbedtls_x509_crt_parse*()`, or a good certificate reads as none.
- **A route that checks a password is `slow`.** The loop keeps slow requests to half the
  workers, and past that answers 503 at once. A password route left unmarked would let a flood
  of them make every page wait.
- **A stream's pull runs on the loop and never waits.** It reads what is new, says it, and
  returns `CSERVE_PULL_WAIT` when there is nothing. A wake (`cserve_stream_wake()`, any thread)
  carries no data, only "look again", so a wake that is lost or doubled is harmless. The handle
  holds the slot's generation, so a wake for a stream that has gone lands on nothing.
- **Key slots and the RNG are taken under `cserve_crypto_lock()`.** mbedtls here has no
  `MBEDTLS_THREADING_C`, so anything outside `tls.c` that imports, signs, verifies or draws random
  bytes holds the lock that every TLS call holds. Keyless hashing and PBKDF2 over bytes don't,
  so a password check never holds up a handshake. A host calls `cserve_crypto_start()` before any
  thread exists.
- **`make abuse` when the loop, the pool or the tarpit change**: every attack in
  `tools/abuse.py` must leave a page prompt and the stop clean, under both sanitizers.
- **A test that races a password check times one first.** PBKDF2 under a sanitizer is several
  times slower, so a fixed sleep that works at -O2 lets the second guess in before the first
  has failed.
- Names are `cserve_*` / `CSERVE_*`. Functions return 0 or -1 with why in `err` (`err_cap`
  bytes); reject and say why rather than crash.
- `-std=c11`. Split a file past ~1000 lines. ctui's style (`.clang-format`, a copy); `make
  format` applies it.
- Commit only when asked. A change here reaches ctui-wm by bumping its submodule.
