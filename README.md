# c-serve

An HTTP/1.1 server and client over TLS, in C11, with no dependencies beyond libc, pthreads,
[mbedtls 4](https://www.trustedfirmware.org/projects/mbed-tls/) (with its PSA crypto) and zlib.
It came out of [ctui-wm](https://github.com/neurosysgg/ctui-wm)'s `plugins/net`, history and all,
and carries a small web host, `cserve`, whose sites are compiled in as first-class apps.

| File | What it is |
|---|---|
| `src/http.{c,h}` | URLs, a request formatted, a reply decoded as it arrives (Content-Length, chunked, to the end) — pure, on buffers |
| `src/httpd.{c,h}` | the server side's HTTP/1.1, pure where both servers share it: a head framed and parsed, a reply's head written, keep-alive decided; the threaded server, which reads a body and writes or pulls a reply |
| `src/loop.{c,h}` | the server for the open internet: one epoll loop owns every socket, every wait a deadline, every handler on the pool; caps per connection count and per network, a lingering close, the access log (never an address) |
| `src/heap.{c,h}` | the loop's timers: a min-heap of deadlines, each node inside what it times |
| `src/pool.{c,h}` | the loop's workers: a fixed set of threads, a bounded queue (past it, a 503), finished jobs handed back through an eventfd |
| `src/wake.{c,h}` | tags from any thread to the loop's: a locked ring and an eventfd, how a stream is woken |
| `src/stream.c` + `src/loop_conn.h` | a loop's streams: parked while they've nothing to say, woken and pulled again; the loop's insides that loop.c and stream.c share |
| `src/tarpit.{c,h}` | the brake on guessing: a failed login's wait doubling to a cap, keyed on network and account, in a fixed table a flood can't wash out |
| `src/listen.{c,h}` | listening sockets; the threaded server's thread per connection (ctui-remote's, and `cserve-front`'s) |
| `src/conn.{c,h}` | a TCP connection with a monotonic deadline, TLS on top; lines and bytes for IMAP / SMTP |
| `src/tls.{c,h}` | the TLS seam: everything that knows mbedtls — client, server (TLS 1.3 only), mutual TLS, a peer's certificate; a server of many names picked by SNI, read again on a reload while every connection keeps the set it began under |
| `src/acme.{c,h}` + `src/acme_client.c` | ACME (RFC 8555): the HTTP-01 token the host serves; the client's base64url, P-256 key and JWK, ES256 JWS, CSR, and the server's objects read |
| `src/coding.{c,h}` | gzip and deflate undone, incrementally |
| `src/net.{c,h}` + `src/http_types.h` | the blocking client: redirects, keep-alive, a streamed body |
| `src/static.{c,h}` | a web root's files as phpanta's `.htaccess` serves them: the build stamp stripped, types, cache tiers, ETag / 304; everything else the front's |
| `src/cgi.{c,h}` + `src/process.{c,h}` | a front controller (php-cgi) per request: Apache's CGI variables, the body fed while the reply streams, every wait bounded |
| `src/route.{c,h}` | an app's routes: `/releases/{slug}`, a trailing `*`, a 405 with `Allow` (or the app's own, `refuse`) |
| `src/app.{h}` | the app ABI: one vtable per app, `cserve_app_<name>`, slots only ever appended |
| `src/policy.{c,h}` | an app's security headers built from what it loads elsewhere: HSTS, the CSP, and the rest, phpanta's values |
| `src/log.{c,h}` | the one hook everything says things through |
| `kit/arena.{c,h}` | one request's memory, and its first error |
| `kit/reading.{c,h}` | a query parameter, a cookie, Accept-Language, If-None-Match, Range, the SPA's fetch, Basic credentials — pure, on strings |
| `kit/text.{c,h}` | languages and catalogs: every word in each language, a phrase's `{name}`, resolved at render |
| `kit/markup.{c,h}` + `kit/html.{c,h}` | the page as a tree, HTML's tags and attributes typed, render with escaping and the URL check in it |
| `kit/headers.{c,h}` | a reply's headers by name, refusing a value that would end one; a Basic challenge whose realm is qdtext |
| `kit/file.{c,h}` | a file answered, whole or the one range a GET asks for, read as it is sent |
| `kit/login.{c,h}` | a password gate's brake, as an app calls it: a 429 while its key waits, a wrong try's 401 held back |
| `kit/password.{c,h}` | a password against a `$pbkdf2-sha256$` digest (mbedtls), the time a wrong one or none costs the same |
| `kit/json.{c,h}` | a file an app reads at start-up, as a tree: ctui's parser, made strict; a JSON string written |
| `kit/cookie.{c,h}` | Set-Cookie one way: Secure, Path=/, no Domain, HttpOnly, SameSite; a bad name or value refused |
| `kit/sse.{c,h}` | server-sent events on a loop stream: an event no data can add a field to, the heartbeat, Last-Event-ID |
| `kit/passkey.{c,h}` | a passkey checked (ES256, SPKI, no CBOR): the client data, the authenticator data, the attested credential, the signature and its count |
| `kit/page.{c,h}` | a view answered: the shell or the fragment, the language, ETag / 304, Vary |
| `host/main.c` | `cserve`: listeners (plain or TLS) on the loop, then a file, an app's route, the app's 404, or 404; with certificates, plain HTTP is an ACME answer or a 308 |
| `host/acme.c` | `cserve-acme`: certificates from an ACME server by HTTP-01, a process of its own so the account key never shares one with the server |
| `host/front.c` | `cserve-front`: a PHP site's root with its front controller as CGI, on the threaded server — the reference a native app is diffed against, never deployed |
| `host/precompress.c` | `cserve-precompress ROOT`: a gzip copy beside each text-like file, which the host serves to a client that takes gzip |
| `apps/hello/` | the test app: the ABI, both ways of linking, and the toolkit end to end |

An app may live outside this tree: `EXTERNAL_APPS="name=DIR"` builds DIR's `*.c` (at any depth,
DIR and DIR/gen on the include path) as `apps/name`, in either link mode, and lints it with
everything else (neurosys's: `make EXTERNAL_APPS=neurosys=/srv/http/neurosys/app`).

`kit/` is an app's toolkit, what phpanta was to a site: an app builds a page as a tree of nodes
and never as a string, every word it says is a catalog entry in each of its languages (one missing
is a compiler error), and `cserve_page()` answers with it. Its render is phpanta's byte for byte, and
its readers decide as phpanta's do, each case's answer in `tests/data/goldens.h` printed by Phpanta
itself (neurosys's `test/cserve/goldens.php`), so a page can be moved off PHP and diffed.

A host compiles `src/` into itself; there is nothing to install. `-ffunction-sections` and a
host's `--gc-sections` keep what it never calls out of its binary, so a server that makes no
requests carries no client.

The host, a site's web root and its app:

```bash
build/O2/bin/cserve --listen 127.0.0.1:8081 --root /srv/http/site/public \
    --app build/O2/bin/apps/hello.so [--data DIR] [--workers N] \
    [--certs DIR --listen-tls HOST:PORT...] [--acme-dir DIR] \
    [--max-conns N] [--per-addr N] [--no-tarpit] [-v]
```

`--certs DIR` holds a directory per name, `DIR/<name>/{cert,key}.pem` (a P-256 key, a certificate
whose subjectAltName carries the name), and `--listen-tls` listeners serve them by SNI, TLS 1.3
only; a client that asks for no name, or one not there, is refused with `unrecognized_name`.
SIGHUP reads the directory again: a set that loads serves from the next handshake on, one that
doesn't leaves the old in place and says why on stderr. A directory with no names yet starts, and
refuses every handshake until a SIGHUP finds some. With `--certs` or `--acme-dir`, a plain
`--listen` answers an HTTP-01 challenge from `--acme-dir`, a `308` to https for one of the names,
and a 404 for anything else.

```bash
build/O2/bin/cserve-acme --directory https://acme-v02.api.letsencrypt.org/directory \
    --account /var/lib/cserve/account.key --certs /var/lib/cserve/certs \
    --challenges /var/lib/cserve/acme --name neurosys.gg [--name N]... [--days 30] [--force]
```

`cserve-acme` renews each name whose certificate is missing or has fewer than `--days` left, with
a fresh key, writing each file beside its place and renaming it in (the key first). It signals
nobody: what runs it (a systemd timer's `ExecStartPost`) sends cserve the SIGHUP. `--ca FILE` is
the ACME server's own CA, for a test server's. `-v` prints the access log (one line per reply, the
address family and never the address) along with the warnings. `--no-tarpit` turns the brake on
guessing off, and says so at start; it exists for a diff against a server that has none.
`cserve` loads apps given as a path (`dlopen`, for development); `cserve-static` is linked with
`STATIC_APPS` (`make STATIC_APPS="hello"`) and loads nothing — `--app hello` picks it from the
table. A PHP site with its front controller as CGI is `cserve-front`'s (`--cgi php-cgi [--front
FILE] [--env K=V]... [--climb 400|front]`), kept as the reference to diff a native app against.

`--app NAME --for HOST...` binds an app to names: it answers those alone, and an app given none
answers every name no app claims. `--app-root DIR` gives an app a web root of its own, so one host
serves two sites by name. A route marked `slow` (one that checks a password) holds at most half the
workers, so a flood of logins gets quick 503s and never makes a page wait. A reply marked `stream`
stays open: its pull may say "nothing now", and `cserve_stream_wake()` from any thread, or the
heartbeat, has it pulled again. That is how `kit/sse` serves an event stream.

```bash
make            # build/O2/: libcserve.a, bin/cserve, bin/cserve-static, bin/apps/*.so
make test       # the suites (T=net for one)
make check      # ASan+UBSan, TSan, -O2, then clang-format, clang-tidy and cppcheck
make abuse      # the host attacked (tools/abuse.py) under ASan+UBSan, then TSan
make acme       # cserve-acme against Pebble, cserve answering it (tools/acme.sh)
make FUZZ=1 fuzz && fuzz/seeds.py build/corpus   # libFuzzer (clang), its seeds first
build/O2-fuzz/bin/fuzz-http build/corpus
fuzz/seeds.py build/corpus-kit kit && build/O2-fuzz/bin/fuzz-kit build/corpus-kit
```

Fuzz without `-fork`: clang 23.1's libFuzzer crashes in its own fork-mode bookkeeping
(`GlobalEnv::secondsSinceProcessStartUp`) and leaves an empty "crash" behind.

The tests' PKI in `tests/data/pki/` is a throwaway CA with a localhost certificate, and
`tests/data/names/` is another for the names server (its `make.sh` makes them anew); their keys
protect nothing.

MIT licensed.
