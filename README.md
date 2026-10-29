# c-serve

An HTTP/1.1 server and client over TLS, in C11, with no dependencies beyond libc, pthreads,
[mbedtls 4](https://www.trustedfirmware.org/projects/mbed-tls/) (with its PSA crypto) and zlib.
It came out of [ctui-wm](https://github.com/neurosysgg/ctui-wm)'s `plugins/net`, history and all,
and carries a small web host, `cserve`, whose sites are compiled in as first-class apps.

| File | What it is |
|---|---|
| `src/http.{c,h}` | URLs, a request formatted, a reply decoded as it arrives (Content-Length, chunked, to the end) — pure, on buffers |
| `src/httpd.{c,h}` | the server side: a request head parsed and bounded, its body read, a reply written or streamed |
| `src/listen.{c,h}` | listening sockets, a thread per connection, until a stop fd turns readable |
| `src/conn.{c,h}` | a TCP connection with a monotonic deadline, TLS on top; lines and bytes for IMAP / SMTP |
| `src/tls.{c,h}` | the TLS seam: everything that knows mbedtls — client, server, mutual TLS, a peer's certificate |
| `src/coding.{c,h}` | gzip and deflate undone, incrementally |
| `src/net.{c,h}` + `src/http_types.h` | the blocking client: redirects, keep-alive, a streamed body |
| `src/static.{c,h}` | a web root's files as phpanta's `.htaccess` serves them: the build stamp stripped, types, cache tiers, ETag / 304; everything else the front's |
| `src/cgi.{c,h}` + `src/process.{c,h}` | a front controller (php-cgi) per request: Apache's CGI variables, the body fed while the reply streams, every wait bounded |
| `src/route.{c,h}` | an app's routes: `/releases/{slug}`, a trailing `*`, a 405 with `Allow` |
| `src/app.{h}` | the app ABI: one vtable per app, `cserve_app_<name>`, slots only ever appended |
| `src/log.{c,h}` | the one hook everything says things through |
| `host/main.c` | `cserve`: listeners (plain, TLS, mutual TLS), then a file, an app's route, the front, or 404 |
| `apps/hello/` | the test app |

A host compiles `src/` into itself; there is nothing to install. `-ffunction-sections` and a
host's `--gc-sections` keep what it never calls out of its binary, so a server that makes no
requests carries no client.

The host, against a PHP site's web root, its front controller as CGI:

```bash
build/O2/bin/cserve --listen 127.0.0.1:8081 --root /srv/http/site/public --cgi php-cgi \
    --climb front --env PHPANTA_ENVIRONMENT=development [--app build/O2/bin/apps/hello.so] [-v]
```

`--climb front` hands a `..` path to the front (whose 404 it becomes) instead of answering 400;
`--tls CERT KEY` makes the listener TLS, and `--client-ca CA` mutual. `cserve` loads apps given as
a path (`dlopen`, for development); `cserve-static` is linked with `STATIC_APPS` (`make
STATIC_APPS="hello"`) and loads nothing — `--app hello` picks it from the table.

```bash
make            # build/O2/: libcserve.a, bin/cserve, bin/cserve-static, bin/apps/*.so
make test       # the suites (T=net for one)
make check      # ASan+UBSan, TSan, -O2, then clang-format, clang-tidy and cppcheck
make FUZZ=1 fuzz && fuzz/seeds.py build/corpus   # libFuzzer (clang), its seeds first
build/O2-fuzz/bin/fuzz-http build/corpus
```

Fuzz without `-fork`: clang 23.1's libFuzzer crashes in its own fork-mode bookkeeping
(`GlobalEnv::secondsSinceProcessStartUp`) and leaves an empty "crash" behind.

The tests' PKI in `tests/data/pki/` is a throwaway CA with a localhost certificate; its keys
protect nothing.

MIT licensed.
