#!/usr/bin/env python3
"""The fuzzers' seeds: fuzz/seeds.py DIR writes fuzz-http's into DIR
(made if missing), one file per seed. libFuzzer starts from them and
grows DIR as it finds more:

    fuzz/seeds.py build/corpus && build/O2-fuzz/bin/fuzz-http build/corpus

The first byte picks what fuzz/http.c does with the rest."""
import gzip
import hashlib
import os
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def j(*parts):
    return b"\0".join(p if isinstance(p, bytes) else p.encode()
                      for p in parts)


def http():
    with open(os.path.join(ROOT, "tests/data/pki/ca.crt"), "rb") as f:
        ca = f.read()
    return [b"\x00HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 11\r\n\r\n{\"a\": 1.5}",
            b"\x00HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n4;x=y\r\nWiki\r\n"
            b"0\r\nTrailer: t\r\n\r\n",
            b"\x00HTTP/1.0 302 Found\nLocation: /next?a=1\n\nbody",
            j(b"\x01https://api.open-meteo.com/v1/forecast?latitude=1",
              "//geocoding-api.open-meteo.com/v1/search"),
            j(b"\x01http://[::1]:8080/dir/page#frag", "../other"),
            b"\x02\x07HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n4;x=y\r\nWiki\r\n"
            b"5\r\npedia\r\n0\r\n\r\n",
            b"\x02\x2aHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloXX",
            b"\x03GET /a%20b/c?x=1 HTTP/1.1\r\nHost: h\r\n"
            b"Connection: keep-alive, x\r\nContent-Length: 12\r\n",
            b"\x03POST /clear HTTP/1.0\nTransfer-Encoding: chunked\n"
            b"X:  y \n",
            # a body under gzip, zlib's deflate, raw deflate
            b"\x04\x07" + gzip.compress(b"<p>hello, hello, hello</p>" * 9,
                                         mtime=0),
            b"\x04\x06" + zlib.compress(b"{\"a\": [1, 2, 3]}" * 20),
            b"\x04\x0a" + zlib.compress(b"body { color: red }" * 30)[2:-4],
            # CA bundles' PEM: the test CA, padding, a broken block
            b"\x06" + ca,
            b"\x06x\n-----BEGIN CERTIFICATE-----\r\nAQ  \r\nI=\r\n-----END "
            b"CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAQ=D\n"
            b"-----END CERTIFICATE-----\n"]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: fuzz/seeds.py DIR")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for seed in http():
        name = hashlib.sha1(seed).hexdigest()
        with open(os.path.join(out, name), "wb") as f:
            f.write(seed)


if __name__ == "__main__":
    main()
