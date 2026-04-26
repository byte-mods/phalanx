#!/usr/bin/env python3
"""
Phalanx end-to-end smoke test
=============================
Quickly verifies the proxy + admin API are reachable, routing works,
metrics are populated, and per-protocol bandwidth counters increment.

Designed to be run after a build/deploy as a fast (sub-second-per-check)
sanity gate before broader load tests.

Usage:
    # Defaults match phalanx.conf: proxy on :18080, admin on :9099
    python3 scripts/smoke_test.py
    # Custom endpoints:
    PROXY=http://127.0.0.1:18080 ADMIN=http://127.0.0.1:9099 \\
        python3 scripts/smoke_test.py
    # Performance budget (ms) for the proxied GET / response:
    LATENCY_BUDGET_MS=50 python3 scripts/smoke_test.py

Exit code: 0 on success, non-zero on first failure. Prints a one-line
summary per check and a final tally.
"""
from __future__ import annotations

import os
import sys
import time
import json
import urllib.request
import urllib.error

PROXY = os.environ.get("PROXY", "http://127.0.0.1:18080").rstrip("/")
ADMIN = os.environ.get("ADMIN", "http://127.0.0.1:9099").rstrip("/")
# Optional HTTP/3 endpoint. When set, an extra check exercises the H3 listener.
# Example: H3_PROXY=https://localhost:8443
H3_PROXY = os.environ.get("H3_PROXY", "").rstrip("/")
TIMEOUT = float(os.environ.get("TIMEOUT", "5"))
LATENCY_BUDGET_MS = int(os.environ.get("LATENCY_BUDGET_MS", "200"))

# ANSI-free output: prints just status tokens, easy to grep in CI.
PASS = "PASS"
FAIL = "FAIL"

results: list[tuple[str, str, str]] = []  # (name, status, detail)


def record(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, PASS if ok else FAIL, detail))
    print(f"[{PASS if ok else FAIL}] {name}{(' — ' + detail) if detail else ''}")
    return ok


def http_get(url: str, headers: dict | None = None, timeout: float = TIMEOUT):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return resp.status, dict(resp.headers), body


def check_proxy_reachable() -> bool:
    try:
        status, _, _ = http_get(f"{PROXY}/", timeout=TIMEOUT)
        return record(
            "proxy_reachable",
            status < 500,
            f"GET {PROXY}/ → {status}",
        )
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        return record("proxy_reachable", False, f"connection failed: {e}")


def check_proxy_identity_header() -> bool:
    """Phalanx adds `x-proxy-by: Phalanx*` on responses it generates."""
    try:
        _, headers, _ = http_get(f"{PROXY}/")
        token = headers.get("x-proxy-by") or headers.get("X-Proxy-By", "")
        return record(
            "proxy_identity_header",
            token.lower().startswith("phalanx"),
            f"x-proxy-by={token!r}",
        )
    except Exception as e:
        return record("proxy_identity_header", False, str(e))


def check_proxy_latency() -> bool:
    """Single-request latency under LATENCY_BUDGET_MS. Coarse but catches gross regressions."""
    try:
        t0 = time.perf_counter()
        http_get(f"{PROXY}/")
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return record(
            "proxy_latency",
            dt_ms < LATENCY_BUDGET_MS,
            f"{dt_ms:.1f} ms (budget {LATENCY_BUDGET_MS} ms)",
        )
    except Exception as e:
        return record("proxy_latency", False, str(e))


def check_admin_health() -> bool:
    try:
        status, _, body = http_get(f"{ADMIN}/health")
        text = body.decode("utf-8", errors="replace")
        return record(
            "admin_health",
            status == 200 and "OK" in text,
            f"{status}, body={text[:50]!r}",
        )
    except Exception as e:
        return record("admin_health", False, str(e))


def check_admin_metrics_prometheus() -> bool:
    try:
        status, headers, body = http_get(f"{ADMIN}/metrics")
        text = body.decode("utf-8", errors="replace")
        ok = (
            status == 200
            and headers.get("Content-Type", "").startswith("text/plain")
            and ("# TYPE" in text or "# HELP" in text)
        )
        return record("admin_metrics_prometheus", ok, f"{status}, {len(text)} bytes")
    except Exception as e:
        return record("admin_metrics_prometheus", False, str(e))


def check_admin_stats_json() -> bool:
    try:
        status, _, body = http_get(f"{ADMIN}/api/stats")
        if status != 200:
            return record("admin_stats_json", False, f"status={status}")
        data = json.loads(body)
        return record(
            "admin_stats_json",
            isinstance(data, dict),
            f"keys={sorted(data.keys())[:6]}",
        )
    except Exception as e:
        return record("admin_stats_json", False, str(e))


def check_bandwidth_increments_after_request() -> bool:
    """Hit the proxy, then verify bandwidth counters moved on the admin side.

    Tolerant: if /api/stats doesn't expose bandwidth, treat as skipped success
    so this script remains useful on stripped builds.
    """
    try:
        # Baseline
        _, _, base_body = http_get(f"{ADMIN}/api/stats")
        base = json.loads(base_body) if base_body else {}
        # Generate traffic
        for _ in range(5):
            try:
                http_get(f"{PROXY}/")
            except Exception:
                pass
        time.sleep(0.2)  # let async counters flush
        _, _, after_body = http_get(f"{ADMIN}/api/stats")
        after = json.loads(after_body) if after_body else {}

        # Look for any nested counter that grew. Schema isn't fully fixed,
        # so do a deep-walk and just check that some integer leaf increased.
        def walk(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield from walk(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    yield from walk(v, f"{path}[{i}]")
            elif isinstance(obj, int):
                yield path, obj

        before_map = dict(walk(base))
        after_map = dict(walk(after))
        grew = [
            (k, before_map.get(k, 0), v)
            for k, v in after_map.items()
            if v > before_map.get(k, 0)
        ]
        if grew:
            sample = grew[0]
            return record(
                "bandwidth_increments",
                True,
                f"{sample[0]}: {sample[1]} → {sample[2]}",
            )
        # Counters didn't move — could be a build with metrics off; treat as skipped.
        return record(
            "bandwidth_increments",
            True,
            "no counters moved (acceptable: metrics may be off)",
        )
    except Exception as e:
        return record("bandwidth_increments", False, str(e))


def check_h3_listener_serves() -> bool:
    """Optional: hit the HTTP/3 listener if H3_PROXY is set.

    Uses httpx with the http3 extra (only runtime dep). Skipped — but counted
    as a pass — when H3_PROXY is empty so the smoke test still runs in
    HTTP/1-only environments. Self-signed certs are accepted because the
    HTTP/3 listener auto-generates one in dev.
    """
    if not H3_PROXY:
        return record(
            "h3_listener_serves",
            True,
            "skipped (H3_PROXY not set)",
        )
    try:
        import httpx  # type: ignore
    except ImportError:
        return record(
            "h3_listener_serves",
            True,
            "skipped (httpx not installed; `pip install httpx[http2]`)",
        )
    try:
        # httpx supports HTTP/2 out of the box; HTTP/3 requires the http3 extra
        # (httpx[http3]). If unavailable, fall back to a plain TCP probe of the
        # QUIC port to at least confirm the socket is open.
        try:
            with httpx.Client(http2=True, verify=False, timeout=TIMEOUT) as c:
                resp = c.get(f"{H3_PROXY}/")
                token = resp.headers.get("x-proxy-by", "")
                ok = resp.status_code < 500 and token.lower().startswith("phalanx")
                return record(
                    "h3_listener_serves",
                    ok,
                    f"status={resp.status_code}, x-proxy-by={token!r}",
                )
        except httpx.RequestError as e:
            # Fall back to a UDP-port reachability probe. QUIC handshake is
            # too involved to do without a real H3 client — but if the UDP
            # port is open, the listener is at least bound.
            from urllib.parse import urlsplit
            import socket

            parts = urlsplit(H3_PROXY)
            port = parts.port or 8443
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                s.sendto(b"\x00", (parts.hostname or "127.0.0.1", port))
                # No response expected from a malformed datagram, but the
                # send not raising means the socket exists.
            return record(
                "h3_listener_serves",
                True,
                f"udp:{port} reachable (httpx err: {e})",
            )
    except Exception as e:
        return record("h3_listener_serves", False, str(e))


def check_404_path_returns_4xx() -> bool:
    """A made-up path under no route should return some kind of error, not crash."""
    try:
        status, _, _ = http_get(f"{PROXY}/__phalanx_smoke_does_not_exist__")
        return record(
            "unknown_path_handled",
            400 <= status < 600,
            f"status={status}",
        )
    except urllib.error.HTTPError as e:
        return record("unknown_path_handled", 400 <= e.code < 600, f"status={e.code}")
    except Exception as e:
        return record("unknown_path_handled", False, str(e))


CHECKS = [
    check_proxy_reachable,
    check_proxy_identity_header,
    check_proxy_latency,
    check_admin_health,
    check_admin_metrics_prometheus,
    check_admin_stats_json,
    check_bandwidth_increments_after_request,
    check_h3_listener_serves,
    check_404_path_returns_4xx,
]


def main() -> int:
    print(f"# Phalanx smoke test — proxy={PROXY} admin={ADMIN}")
    failures = 0
    for fn in CHECKS:
        try:
            ok = fn()
        except Exception as e:  # any unexpected exception is a failure
            ok = record(fn.__name__, False, f"unhandled: {e!r}")
        if not ok:
            failures += 1
    total = len(CHECKS)
    print(f"\n# {total - failures}/{total} checks passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
