#!/usr/bin/env python3
"""The fuzzers' seeds: fuzz/seeds.py DIR [NAME] writes fuzz-NAME's (http
when not said) into DIR (made if missing), one file per seed. libFuzzer
starts from them and grows DIR as it finds more:

    fuzz/seeds.py build/corpus && build/O2-fuzz/bin/fuzz-http build/corpus
    fuzz/seeds.py build/corpus-kit kit && build/O2-fuzz/bin/fuzz-kit build/corpus-kit

The first byte picks what fuzz/NAME.c does with the rest."""
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
            # a CGI's reply head (php-cgi's, ctui-remote's)
            b"\x05Content-type: text/html; charset=UTF-8\r\n"
            b"Set-Cookie: s=1; HttpOnly\r\nX-Powered-By: PHP\r\n\r\n<p>",
            b"\x05Status: 404 Not Found\nLocation: /x\nConnection: "
            b"close\nContent-Length: 3\n\nabc",
            b"\x05Location: /there\r\n\n",
            # CA bundles' PEM: the test CA, padding, a broken block
            b"\x06" + ca,
            b"\x06x\n-----BEGIN CERTIFICATE-----\r\nAQ  \r\nI=\r\n-----END "
            b"CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAQ=D\n"
            b"-----END CERTIFICATE-----\n",
            # paths routed: a method byte, then the path
            b"\x07\x00/assets/js/v-0123abcd/main.js",
            b"\x07\x00/a.css",
            b"\x07\x02/releases/ill/flac",
            b"\x07\x03/assets/js/v-00000000/../../index.php",
            b"\x07\x00//sub//page.html",
            b"\x07\x04/x/y/z/rest/of/it",
            b"\x07\x00/releases/.user.ini",
            # a head framed whole and in pieces: blank lines first, LF and
            # CRLF, a pipelined second request, a line past the cap
            b"\x08\x05\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\n",
            b"\x08\x09POST /p HTTP/1.0\nContent-Length: 3\n\nabc",
            b"\x08\x11GET / HTTP/1.1\r\nX: " + b"a" * 600 + b"\r\n\r\n",
            b"\x08\x01\n\n\n\n\nGET / HTTP/1.1\r\n\r\n",
            # an Accept-Encoding: lists, q values, the wildcard
            b"\x09gzip, deflate, br",
            b"\x09br;q=1.0, gzip;q=0.8, *;q=0.1",
            b"\x09*;q=0, x-gzip; q=0.000",
            b"\x09identity"]


def kit():
    return [b"\x00a=1&b=two+words&c=%C3%BC",
            b"\x00a&a=2&%61=%FF",
            b"\x01theme=dark; lang=\"de\"; x",
            b"\x01 lang = en ;lang=de",
            b"\x02de-AT, en;q=0.9, *;q=0.1",
            b"\x02fr;q=0, *, en;Q=1.000;level=1",
            b"\x03W/\"abc-gzip\", \"0123456789abcdef0123456789abcdef\"",
            b"\x03 * ",
            b"\x04\x01\x00bytes=0-99",
            b"\x04\x00\x0aBYTES=-5",
            b"\x04\x00\x00bytes=9223372036854775808-",
            j(b"\x05a < b & 'c' \"d\" \xc3\xbc \xc3", "/releases/ill"),
            j(b"\x05\xed\xa0\x80\xf4\x90\x80\x80", "/\t/evil.example"),
            j(b"\x05x", "mailto:x@y"),
            j(b"\x05x", " \\\\host"),
            j(b"\x05x", "javascript:alert(1)"),
            b'\x06{"wna-bootleg": {"title": "t\\u00fc", "tracks": '
            b'[{"label": "v3", "file": "v3.mp3", "seconds": 212}]}}',
            b'\x06[1, -0.5e+3, true, null, "\\ud834\\udd1e"]',
            b"\x07Basic ZGVtbzpwdw==",
            b"\x07basic  ZG Vt bzp wdw",
            b"\x08$pbkdf2-sha256$600000$jWXwxWGgMNM2dKmTGRBisg==$"
            b"bDb5fZLtrtLDo8Z4gNiC4h5z6lYAShkliLFKEZ/JmOU=",
            b"\x09wna-bootleg \xc3\xbc\"%"]


SEEDS = {"http": http, "kit": kit}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and
                                         sys.argv[2] not in SEEDS):
        sys.exit("usage: fuzz/seeds.py DIR [http|kit]")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for seed in SEEDS[sys.argv[2] if len(sys.argv) == 3 else "http"]():
        name = hashlib.sha1(seed).hexdigest()
        with open(os.path.join(out, name), "wb") as f:
            f.write(seed)


if __name__ == "__main__":
    main()
