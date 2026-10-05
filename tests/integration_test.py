#!/usr/bin/env python3
"""End-to-end integration tests for the proxy-login shim.

Starts a mock upstream (stands in for the MikroTik Web-Proxy) that records the
exact bytes it receives, launches the compiled proxy against it, and drives a
battery of scenarios over real sockets. Focus areas:

  * auth enforcement (missing / wrong / valid, multi-user)
  * the core promise: Proxy-Authorization is never forwarded upstream
  * CONNECT tunnelling and plain-HTTP relay correctness
  * robustness: oversized headers, slow-loris, garbage, pipelining
  * resource hygiene: fd count and RSS stay flat under churn (no leaks)

Exit code 0 == all passed. No external dependencies (stdlib only).
"""
import base64
import os
import socket
import subprocess
import sys
import threading
import time

HOST = "127.0.0.1"
PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


class MockUpstream(threading.Thread):
    """Minimal upstream: records each request's bytes, replies 200. For CONNECT
    it replies 200 and then echoes tunnelled bytes back."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.requests = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, port))
        self.sock.listen(128)
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(5)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 1 << 20:
                    break
            with self.lock:
                self.requests.append(data)
            first = data.split(b"\r\n", 1)[0]
            if first.startswith(b"CONNECT"):
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if b"silent" in first:
                    # Hold the tunnel open but send/recv nothing. Used to prove
                    # the relay does not busy-spin when the client half-closes.
                    time.sleep(8)
                    return
                # echo tunnel
                while True:
                    b = conn.recv(4096)
                    if not b:
                        break
                    conn.sendall(b)
            else:
                body = b"UPSTREAM-OK"
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                    % (len(body), body)
                )
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def raw_send(port, payload, read=True, timeout=3.0, recv_all=False):
    """Send raw bytes to the proxy, optionally read the response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((HOST, port))
        s.sendall(payload)
        if not read:
            return b""
        out = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
            if not recv_all and b"\r\n\r\n" in out:
                break
        return out
    finally:
        s.close()


def http_get_via_proxy(port, auth=None, host="example.com"):
    req = f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n"
    if auth is not None:
        token = base64.b64encode(auth.encode()).decode()
        req += f"Proxy-Authorization: Basic {token}\r\n"
    req += "Connection: close\r\n\r\n"
    return raw_send(port, req.encode(), recv_all=True)


def status_code(resp):
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def proc_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def proc_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def proc_cpu_jiffies(pid):
    """utime+stime in clock ticks, to detect a busy-spin event loop."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        # after the ')' field, index 11=utime, 12=stime (0-based in this slice)
        return int(parts[11]) + int(parts[12])
    except (OSError, IndexError, ValueError):
        return -1


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./builds/proxy-login-dev"
    if not os.path.exists(binary):
        print(f"binary not found: {binary}")
        return 2

    up_port = free_port()
    listen_port = free_port()
    upstream = MockUpstream(up_port)
    upstream.start()

    env = dict(os.environ)
    env.update({
        "UPSTREAM_HOST": HOST,
        "UPSTREAM_PORT": str(up_port),
        "LISTEN_PORT": str(listen_port),
        "PROXY_USER": "alice",
        "PROXY_PASS": "s3cret",
        "PROXY_USERS": "bob:bobpass,carol:carolpass",
        "WORKERS": "2",
        "MAX_CONN": "64",
        "HEADER_TIMEOUT_MS": "1200",
        # ASan niceties when the binary is instrumented
        "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1:exitcode=99",
    })

    wrap = os.environ.get("PROXY_WRAP", "").split()
    relax = os.environ.get("RELAX_RES") == "1"
    launch = wrap + [binary]
    proc = subprocess.Popen(launch, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # wait for listen (valgrind/tsan start slowly)
    ok = False
    for _ in range(400):
        try:
            s = socket.create_connection((HOST, listen_port), timeout=0.2)
            s.close()
            ok = True
            break
        except OSError:
            time.sleep(0.05)
    if not ok:
        print("proxy failed to start")
        print(proc.stdout.read().decode(errors="replace"))
        proc.kill()
        upstream.stop()
        return 2

    try:
        print("== AUTH ENFORCEMENT ==")
        check("no credentials -> 407", status_code(http_get_via_proxy(listen_port)) == 407)
        check("wrong password -> 407",
              status_code(http_get_via_proxy(listen_port, "alice:wrong")) == 407)
        check("empty user:pass -> 407",
              status_code(http_get_via_proxy(listen_port, ":")) == 407)
        check("unknown user -> 407",
              status_code(http_get_via_proxy(listen_port, "mallory:x")) == 407)

        print("== VALID AUTH (multi-user) ==")
        upstream.requests.clear()
        r = http_get_via_proxy(listen_port, "alice:s3cret")
        check("PROXY_USER alice -> 200 + body", status_code(r) == 200 and b"UPSTREAM-OK" in r,
              f"resp={r[:60]!r}")
        check("PROXY_USERS bob -> 200",
              status_code(http_get_via_proxy(listen_port, "bob:bobpass")) == 200)
        check("PROXY_USERS carol -> 200",
              status_code(http_get_via_proxy(listen_port, "carol:carolpass")) == 200)

        print("== CREDENTIAL LEAK GUARD ==")
        time.sleep(0.2)
        leaked = any(b"proxy-authorization" in req.lower() for req in upstream.requests)
        check("Proxy-Authorization never reaches upstream", not leaked,
              f"requests_seen={len(upstream.requests)}")
        saw_get = any(req.startswith(b"GET ") for req in upstream.requests)
        check("upstream still received the forwarded GET", saw_get)

        print("== CONNECT TUNNEL ==")
        token = base64.b64encode(b"alice:s3cret").decode()
        s = socket.create_connection((HOST, listen_port), timeout=3)
        s.sendall(f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                  f"Proxy-Authorization: Basic {token}\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            c = s.recv(4096)
            if not c:
                break
            resp += c
        check("CONNECT -> 200 established", status_code(resp) == 200, f"resp={resp[:60]!r}")
        s.sendall(b"PING-THROUGH-TUNNEL")
        echoed = s.recv(4096)
        check("tunnel echoes payload", echoed == b"PING-THROUGH-TUNNEL", f"got={echoed!r}")
        s.close()

        print("== HALF-CLOSE / NO BUSY-SPIN ==")
        # Open a tunnel to a silent upstream, half-close the client's write side,
        # then confirm the event loop stays idle (CPU does not spin) while the
        # other half is still open. Regression guard for level-triggered EPOLLRDHUP.
        sp = socket.create_connection((HOST, listen_port), timeout=3)
        sp.sendall(f"CONNECT silent.test:443 HTTP/1.1\r\nHost: silent.test:443\r\n"
                   f"Proxy-Authorization: Basic {token}\r\n\r\n".encode())
        est = b""
        while b"\r\n\r\n" not in est:
            c = sp.recv(4096)
            if not c:
                break
            est += c
        sp.shutdown(socket.SHUT_WR)   # client EOF -> proxy sees read-closed half
        cpu0 = proc_cpu_jiffies(proc.pid)
        time.sleep(1.2)
        cpu1 = proc_cpu_jiffies(proc.pid)
        # A pegged core would add ~120 jiffies/s; idle epoll adds ~0.
        check("event loop does not busy-spin on half-close",
              cpu0 >= 0 and (cpu1 - cpu0) < 30, f"cpu jiffies +{cpu1 - cpu0}")
        sp.close()

        # Full close (EPOLLHUP) against a silent upstream must also stay idle.
        sp2 = socket.create_connection((HOST, listen_port), timeout=3)
        sp2.sendall(f"CONNECT silent.test:443 HTTP/1.1\r\nHost: silent.test:443\r\n"
                    f"Proxy-Authorization: Basic {token}\r\n\r\n".encode())
        est = b""
        while b"\r\n\r\n" not in est:
            c = sp2.recv(4096)
            if not c:
                break
            est += c
        sp2.close()                   # full close -> EPOLLHUP on the proxy
        cpu0 = proc_cpu_jiffies(proc.pid)
        time.sleep(1.0)
        cpu1 = proc_cpu_jiffies(proc.pid)
        check("event loop does not busy-spin on full close",
              cpu0 >= 0 and (cpu1 - cpu0) < 30, f"cpu jiffies +{cpu1 - cpu0}")

        print("== ROBUSTNESS (no crash) ==")
        # oversized header block
        big = b"GET http://x/ HTTP/1.1\r\nHost: x\r\nX-Big: " + b"A" * 20000 + b"\r\n\r\n"
        raw_send(listen_port, big)
        # garbage / binary
        raw_send(listen_port, bytes(range(256)) * 4)
        # bare LF, partial
        raw_send(listen_port, b"GET / HTTP/1.0\n\n")
        raw_send(listen_port, b"\r\n\r\n")
        # pipelined second request after a valid first
        raw_send(listen_port,
                 (f"GET http://x/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                  f"GET http://y/ HTTP/1.1\r\nHost: y\r\n\r\n").encode())
        time.sleep(0.2)
        check("daemon alive after malformed/oversized input",
              status_code(http_get_via_proxy(listen_port, "alice:s3cret")) == 200)

        print("== SLOWLORIS DEADLINE ==")
        slow = socket.create_connection((HOST, listen_port), timeout=5)
        slow.sendall(b"GET http://x/ HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        # never complete the header; the server must drop us via the header
        # deadline (HEADER_TIMEOUT_MS=1200 for the test run).
        check("daemon responsive while slowloris pending",
              status_code(http_get_via_proxy(listen_port, "alice:s3cret")) == 200)
        slow.settimeout(4)
        reaped = False
        try:
            # once reaped, recv returns b"" (clean close) rather than blocking
            if slow.recv(16) == b"":
                reaped = True
        except socket.timeout:
            reaped = False
        check("slowloris connection reaped by header deadline", reaped)
        slow.close()

        print("== BRUTE-FORCE THROTTLE ==")
        # Many failures from this IP should eventually get throttled; since all
        # traffic is 127.0.0.1 we just confirm failures keep returning 407 and
        # the valid path is unaffected from the same host only after reset window
        # is impractical here, so we assert the daemon stays healthy under a burst.
        for _ in range(15):
            http_get_via_proxy(listen_port, "alice:wrong")
        check("daemon healthy after failed-auth burst",
              status_code(http_get_via_proxy(listen_port)) == 407)

        print("== RESOURCE HYGIENE (fd / RSS stability) ==")
        time.sleep(0.3)
        n_req = 80 if relax else 600
        n_churn = 40 if relax else 300
        fd0 = proc_fd_count(proc.pid)
        rss0 = proc_rss_kb(proc.pid)
        for _ in range(n_req):
            http_get_via_proxy(listen_port, "alice:s3cret")
        # churn of half-open connections
        for _ in range(n_churn):
            try:
                c = socket.create_connection((HOST, listen_port), timeout=1)
                c.close()
            except OSError:
                pass
        time.sleep(0.5)
        fd1 = proc_fd_count(proc.pid)
        rss1 = proc_rss_kb(proc.pid)
        check(f"fd count stable after {n_req + n_churn} connections",
              fd1 >= 0 and fd1 <= fd0 + 5, f"fd {fd0} -> {fd1}")
        if not relax:
            check("RSS stable after churn (<1.5x and <20MB growth)",
                  rss1 >= 0 and rss1 <= rss0 + 20000 and rss1 <= int(rss0 * 1.5) + 4000,
                  f"rss {rss0}KB -> {rss1}KB")

        check("proxy process still running", proc.poll() is None,
              f"exit={proc.poll()}")

    finally:
        proc.send_signal(subprocess.signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        upstream.stop()
        out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        if wrap and "valgrind" in " ".join(wrap):
            print("== VALGRIND ==")
            check("valgrind: 0 errors", "ERROR SUMMARY: 0 errors" in out,
                  "(see log below)")
            check("valgrind: no definitely-lost leaks",
                  "definitely lost: 0 bytes" in out or "All heap blocks were freed" in out,
                  "(see log below)")
        if FAIL or os.environ.get("VERBOSE") or (wrap and "valgrind" in " ".join(wrap)):
            print("\n--- proxy log ---")
            print(out)

    print(f"\nintegration: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
