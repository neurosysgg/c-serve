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
- **The app ABI only grows.** A slot is appended to `CSERVE_APP`, never inserted, renamed or
  retyped; a host reads one through `CSERVE_APP_SLOT`, so an app built against fewer slots
  still loads. Bump `CSERVE_APP_ABI` only for a break, and then every app is rebuilt.
- **The host takes flags, not a config file**: a config parser would be one more parser of
  outside input.
- **No header is named like a system one.** ctui-wm puts `src/` on every `-I`, and `-I` is
  searched for `<...>` too: a `spawn.h` here shadowed POSIX's `<spawn.h>` there (hence
  `process.h`). Check `/usr/include` before naming a new header.
- Names are `cserve_*` / `CSERVE_*`. Functions return 0 or -1 with why in `err` (`err_cap`
  bytes); reject and say why rather than crash.
- `-std=c11`. Split a file past ~1000 lines. ctui's style (`.clang-format`, a copy); `make
  format` applies it.
- Commit only when asked. A change here reaches ctui-wm by bumping its submodule.
