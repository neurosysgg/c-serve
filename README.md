# c-serve

An HTTP/1.1 server and client over TLS, in C11, with no dependencies beyond libc, pthreads,
[mbedtls 4](https://www.trustedfirmware.org/projects/mbed-tls/) (with its PSA crypto) and zlib.
It came out of [ctui-wm](https://github.com/neurosysgg/ctui-wm)'s `plugins/net`, history and all,
and is headed towards a small web host whose sites are compiled in as first-class apps.

| File | What it is |
|---|---|
| `src/http.{c,h}` | URLs, a request formatted, a reply decoded as it arrives (Content-Length, chunked, to the end) — pure, on buffers |
| `src/httpd.{c,h}` | the server side: a request head parsed and bounded, its body read, a reply written or streamed |
| `src/listen.{c,h}` | listening sockets, a thread per connection, until a stop fd turns readable |
| `src/conn.{c,h}` | a TCP connection with a monotonic deadline, TLS on top; lines and bytes for IMAP / SMTP |
| `src/tls.{c,h}` | the TLS seam: everything that knows mbedtls — client, server, mutual TLS, a peer's certificate |
| `src/coding.{c,h}` | gzip and deflate undone, incrementally |
| `src/net.{c,h}` + `src/http_types.h` | the blocking client: redirects, keep-alive, a streamed body |

A host compiles `src/` into itself; there is nothing to install. `-ffunction-sections` and a
host's `--gc-sections` keep what it never calls out of its binary, so a server that makes no
requests carries no client.

```bash
make            # build/O2/libcserve.a
make test       # the suites (T=net for one)
make check      # ASan+UBSan, TSan, -O2, then clang-format, clang-tidy and cppcheck
make FUZZ=1 fuzz && fuzz/seeds.py build/corpus   # libFuzzer (clang), its seeds first
build/O2-fuzz/bin/fuzz-http build/corpus
```

The tests' PKI in `tests/data/pki/` is a throwaway CA with a localhost certificate; its keys
protect nothing.

MIT licensed.
