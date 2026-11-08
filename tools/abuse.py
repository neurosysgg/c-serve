#!/usr/bin/env python3
"""The host under attack: tools/abuse.py BIN starts BIN/cserve-static with
the hello app on a scratch root, then runs each attack the loop is built
to survive while a well-behaved client keeps asking for a page. An attack
passes when that client is answered every time, promptly, and the host
ends cleanly on SIGTERM with nothing from a sanitizer in its log.

    make abuse                         # under ASan+UBSan, then TSan
    python3 -I tools/abuse.py build/O2/bin [--prompt SECONDS]

Attackers bind to their own loopback addresses (127.0.0.2 and up), each
of them a network to the loop (an IPv4 address whole), so the per-network
limit sees them as strangers do; the good client is 127.0.0.1.

  slowloris     heads sent a byte at a time, from 10 networks
  slow-read     a 4 MiB file asked for and never read, 30 times over
  per-network   200 connections from one network (the limit is 32)
  flood         900 idle connections from 30 networks
  pool          200 password checks at once (PBKDF2 each): 200 or 503.
                They hold at most half the workers (the slow lane), so a
                page never waits behind them: it must come back within
                LANE_PROMPT (1 s), whatever --prompt says
  parked        wrong passwords from 40 networks: every 401 held back,
                none of them holding up anyone else
  streams       400 streams opened from 20 networks and never read: as
                many as the cap (256) and the per-network limit let in,
                503 for the rest, none of it holding a worker
"""
import os
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

# a page must come back within this, attack or not (--prompt)
PROMPT = 3.0
# ... and within this during a password flood, under any sanitizer: the
# slow lane keeps half the workers for pages
LANE_PROMPT = 1.0
GOOD = ("GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
WRONG = "aGVsbG86d3Jvbmc="  # hello:wrong
RIGHT = "aGVsbG86b3BlbiBzZXNhbWU="  # hello:open sesame


def start(bin_dir, root, data, log):
    host = subprocess.Popen(
        [os.path.join(bin_dir, "cserve-static"), "--listen", "127.0.0.1:0",
         "--root", root, "--app", "hello", "--data", data],
        stdout=subprocess.PIPE, stderr=log, text=True)
    line = host.stdout.readline()
    if not line:
        raise SystemExit("the host didn't start")
    return host, int(line.rsplit(":", 1)[1])


def dial(port, src="127.0.0.1", timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src, 0))
    s.connect(("127.0.0.1", port))
    return s


def ask(port, req=GOOD, src="127.0.0.1", timeout=10):
    """a request on its own connection: (status, seconds)"""
    t = time.monotonic()
    try:
        with dial(port, src, timeout) as s:
            s.sendall(req.encode())
            got = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
        status = int(got.split(b" ", 2)[1]) if got else 0
    except (OSError, ValueError, IndexError):
        status = 0
    return status, time.monotonic() - t


def good_client(port, during, results):
    """the page, asked for again and again while the attack runs"""
    end = time.monotonic() + during
    while time.monotonic() < end:
        results.append(ask(port))
        time.sleep(0.05)


def run_attack(name, port, attack, seconds=4, bound=None):
    results = []
    held = []
    stop = threading.Event()
    t = threading.Thread(target=attack, args=(port, held, stop))
    t.start()
    time.sleep(0.5)  # the attack under way first
    good_client(port, seconds, results)
    stop.set()
    t.join()
    for s in held:
        try:
            s.close()
        except OSError:
            pass
    slow = max(sec for _, sec in results)
    wrong = [st for st, _ in results if st != 200]
    ok = results and not wrong and slow < (bound or PROMPT)
    print(("  ok  " if ok else "FAIL  ") +
          f"{name}: {len(results)} pages, the slowest {slow:.2f} s" +
          (f", {len(wrong)} not 200 ({wrong[:5]})" if wrong else ""))
    return ok


def src(i):
    return f"127.0.0.{2 + i}"


def slowloris(port, held, stop):
    for i in range(10):
        for _ in range(20):
            try:
                held.append(dial(port, src(i)))
            except OSError:
                pass
    head = b"GET /hello HTTP/1.1\r\nHost: x\r\nX-Slow: "
    k = 0
    while not stop.is_set():
        for s in held:
            try:
                s.send(head[k % len(head):k % len(head) + 1])
            except OSError:
                pass
        k += 1
        time.sleep(0.2)


def slow_read(port, held, stop):
    for i in range(30):
        try:
            s = dial(port, src(i % 10))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
            held.append(s)  # and never read
        except OSError:
            pass
    stop.wait()


def per_network(port, held, stop):
    refused = 0
    for _ in range(200):
        try:
            held.append(dial(port, src(20)))
        except OSError:
            refused += 1
    stop.wait()


def flood(port, held, stop):
    for i in range(30):
        for _ in range(30):
            try:
                held.append(dial(port, src(30 + i)))
            except OSError:
                pass
    stop.wait()


def pool(port, held, stop):
    req = ("GET /hello-file/f.txt HTTP/1.1\r\nHost: x\r\n"
           f"Authorization: Basic {RIGHT}\r\nConnection: close\r\n\r\n")
    statuses = []

    def one(i):
        statuses.append(ask(port, req, src(70 + i % 20))[0])

    ts = [threading.Thread(target=one, args=(i,)) for i in range(200)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    bad = [s for s in statuses if s not in (200, 503)]
    if bad:
        print(f"    the flood got {bad[:5]}")
    stop.wait()


def parked(port, held, stop):
    for i in range(40):
        try:
            s = dial(port, src(100 + i))
            s.sendall((f"GET /hello-file/f{i}.txt HTTP/1.1\r\nHost: x\r\n"
                       f"Authorization: Basic {WRONG}\r\n\r\n").encode())
            held.append(s)
        except OSError:
            pass
    stop.wait()


def streams(port, held, stop):
    req = b"GET /hello-stream HTTP/1.1\r\nHost: x\r\n\r\n"
    for i in range(400):
        try:
            s = dial(port, src(130 + i % 20))
            s.sendall(req)
            held.append(s)
        except OSError:
            pass
    stop.wait()


def main():
    global PROMPT
    args = sys.argv[1:]
    if len(args) == 3 and args[1] == "--prompt":
        PROMPT = float(args[2])
        args = args[:1]
    if len(args) != 1:
        raise SystemExit("usage: tools/abuse.py BIN [--prompt SECONDS]")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 8192), hard))
    scratch = tempfile.mkdtemp(prefix="cserve-abuse-")
    root, data = os.path.join(scratch, "public"), os.path.join(scratch, "data")
    os.makedirs(root)
    os.makedirs(data)
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(os.urandom(4 << 20))
    with open(os.path.join(data, "f.txt"), "w") as f:
        f.write("0123456789")
    log_path = os.path.join(scratch, "host.log")
    log_file = open(log_path, "w")
    host, port = start(args[0], root, data, log_file)
    ok = True
    try:
        for name, attack, bound in [("slowloris", slowloris, None),
                                    ("slow-read", slow_read, None),
                                    ("per-network", per_network, None),
                                    ("flood", flood, None),
                                    ("pool", pool, LANE_PROMPT),
                                    ("parked", parked, None),
                                    ("streams", streams, None)]:
            ok = run_attack(name, port, attack, bound=bound) and ok
            time.sleep(0.5)
    finally:
        host.send_signal(signal.SIGTERM)
        try:
            code = host.wait(timeout=30)
        except subprocess.TimeoutExpired:
            host.kill()
            code = -1
        log_file.close()
        with open(log_path) as f:
            log = f.read()
        shutil.rmtree(scratch, ignore_errors=True)
    said = [l for l in log.splitlines()
            if "Sanitizer" in l or "runtime error" in l]
    clean = code == 0 and not said
    print(("  ok  " if clean else "FAIL  ") +
          f"and a clean stop (exit {code})" +
          ("".join("\n    " + l for l in said[:10])))
    sys.exit(0 if ok and clean else 1)


if __name__ == "__main__":
    main()
