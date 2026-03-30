#!/usr/bin/env python3
"""
Phalanx Load Test — Locust + standalone runner
================================================
Simulates realistic traffic across all proxy features:
  • HTTP proxy requests (GET / POST / static)
  • WAF bypass attempts (should all be blocked)
  • Admin API reads (stats, bandwidth, alerts)
  • Keyval store read/write churn
  • Cache-busting requests
  • Concurrent ban/unban cycles

Usage with Locust (recommended):
    pip install locust
    locust -f scripts/load_test.py --host=http://127.0.0.1:18080 \
        --users=200 --spawn-rate=20 --run-time=60s --headless

Usage standalone (no locust):
    python scripts/load_test.py --users=50 --duration=30

Environment vars:
    ADMIN=http://127.0.0.1:9099   Admin API base
    PROXY=http://127.0.0.1:18080  Proxy base
"""

import os
import time
import random
import string
import argparse
import threading
import statistics
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ── Config ───────────────────────────────────────────────────────────────────

PROXY_HOST  = os.environ.get("PROXY", "http://127.0.0.1:18080")
ADMIN_HOST  = os.environ.get("ADMIN", "http://127.0.0.1:9099")

# ── Locust user classes (used when locust is installed) ───────────────────────

try:
    from locust import HttpUser, task, between, events
    import random

    class ProxyUser(HttpUser):
        """Simulates a real end-user hitting the proxy."""
        host = PROXY_HOST
        wait_time = between(0.05, 0.5)

        @task(40)
        def get_root(self):
            self.client.get("/", name="GET /")

        @task(20)
        def get_api(self):
            self.client.get("/api", name="GET /api")

        @task(10)
        def get_static(self):
            path = random.choice(["/static/index.html", "/static/app.js",
                                   "/static/style.css", "/static/logo.png"])
            self.client.get(path, name="GET /static/*")

        @task(5)
        def post_api(self):
            self.client.post("/api/data",
                             json={"id": random.randint(1, 10000), "value": "test"},
                             name="POST /api/data")

        @task(3)
        def get_with_query(self):
            self.client.get(f"/api?page={random.randint(1, 100)}&limit=20",
                             name="GET /api?page=N")

        @task(2)
        def get_health_via_proxy(self):
            self.client.get("/health", name="GET /health (proxy)")


    class WafAttackUser(HttpUser):
        """Simulates attack traffic that the WAF should block (expect 403)."""
        host = PROXY_HOST
        wait_time = between(0.1, 1.0)

        SQLI = [
            "/?q=1' OR '1'='1",
            "/?id=1 UNION SELECT null,null,null--",
            "/?search='; DROP TABLE users--",
            "/?q=1%20UNION%20SELECT%20password%20FROM%20users",
        ]
        XSS = [
            "/?q=<script>alert(1)</script>",
            "/?name=<img src=x onerror=alert(1)>",
            "/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        ]
        TRAVERSAL = [
            "/../../../etc/passwd",
            "/api/../../etc/shadow",
            "/?file=../../../../etc/hosts",
        ]

        @task(5)
        def sqli_attempt(self):
            with self.client.get(random.choice(self.SQLI),
                                  name="ATTACK:SQLi", catch_response=True) as r:
                if r.status_code == 403:
                    r.success()
                else:
                    r.failure(f"WAF missed SQLi! Got {r.status_code}")

        @task(5)
        def xss_attempt(self):
            with self.client.get(random.choice(self.XSS),
                                  name="ATTACK:XSS", catch_response=True) as r:
                if r.status_code == 403:
                    r.success()
                else:
                    r.failure(f"WAF missed XSS! Got {r.status_code}")

        @task(3)
        def traversal_attempt(self):
            with self.client.get(random.choice(self.TRAVERSAL),
                                  name="ATTACK:Traversal", catch_response=True) as r:
                if r.status_code in (400, 403, 404):
                    r.success()
                else:
                    r.failure(f"WAF missed traversal! Got {r.status_code}")


    class AdminApiUser(HttpUser):
        """Simulates dashboard polling — read-heavy admin API traffic."""
        host = ADMIN_HOST
        wait_time = between(0.5, 3.0)

        @task(10)
        def get_stats(self):
            self.client.get("/api/stats", name="ADMIN:stats")

        @task(8)
        def get_bandwidth(self):
            self.client.get("/api/bandwidth", name="ADMIN:bandwidth")

        @task(6)
        def get_bans(self):
            self.client.get("/api/waf/bans", name="ADMIN:bans")

        @task(6)
        def get_attacks(self):
            self.client.get("/api/waf/attacks", name="ADMIN:attacks")

        @task(5)
        def get_top_ips(self):
            self.client.get("/api/rates/top?n=20", name="ADMIN:top-ips")

        @task(4)
        def get_upstreams(self):
            self.client.get("/api/upstreams/detail", name="ADMIN:upstreams")

        @task(3)
        def get_alerts(self):
            self.client.get("/api/alerts?n=20", name="ADMIN:alerts")

        @task(2)
        def get_cluster(self):
            self.client.get("/api/cluster/nodes", name="ADMIN:cluster")

        @task(2)
        def get_metrics(self):
            self.client.get("/metrics", name="ADMIN:metrics")

        @task(1)
        def trigger_alert_check(self):
            self.client.post("/api/alerts/check", name="ADMIN:alert-check")


    class KeyvalChurnUser(HttpUser):
        """Rapid keyval read/write/delete cycles."""
        host = ADMIN_HOST
        wait_time = between(0.01, 0.1)

        def _random_key(self):
            return "load-" + "".join(random.choices(string.ascii_lowercase, k=8))

        @task(5)
        def set_key(self):
            k = self._random_key()
            self.client.post(f"/api/keyval/{k}",
                              json={"value": "load-test", "ttl_secs": 30},
                              name="KV:set")

        @task(3)
        def get_key(self):
            k = self._random_key()
            self.client.get(f"/api/keyval/{k}", name="KV:get")

        @task(2)
        def list_keys(self):
            self.client.get("/api/keyval", name="KV:list")

        @task(1)
        def delete_key(self):
            k = self._random_key()
            self.client.delete(f"/api/keyval/{k}", name="KV:delete")


    class WafBanChurnUser(HttpUser):
        """Rapid ban/unban cycles to stress the reputation engine."""
        host = ADMIN_HOST
        wait_time = between(0.05, 0.3)

        BAN_POOL = [f"192.168.{i}.{j}" for i in range(10) for j in range(1, 11)]

        @task(3)
        def ban_random_ip(self):
            ip = random.choice(self.BAN_POOL)
            self.client.post(f"/api/waf/ban/{ip}", name="WAF:ban")

        @task(2)
        def unban_random_ip(self):
            ip = random.choice(self.BAN_POOL)
            self.client.delete(f"/api/waf/ban/{ip}", name="WAF:unban")

        @task(1)
        def list_bans(self):
            self.client.get("/api/waf/bans", name="WAF:list-bans")


    print("[locust] Locust classes loaded. Use: locust -f scripts/load_test.py")

except ImportError:
    print("[info] Locust not installed — using standalone runner below.")
    print("[info] Install: pip install locust")


# ════════════════════════════════════════════════════════════════════════════
# Standalone runner (no locust dependency)
# ════════════════════════════════════════════════════════════════════════════

class Result:
    __slots__ = ("url", "status", "latency_ms", "error")
    def __init__(self, url, status, latency_ms, error=None):
        self.url = url
        self.status = status
        self.latency_ms = latency_ms
        self.error = error


def http_get(url: str, timeout: float = 3.0) -> Result:
    t0 = time.perf_counter()
    try:
        req = Request(url, headers={"User-Agent": "PhalanxLoadTest/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            resp.read()
            return Result(url, resp.status, (time.perf_counter() - t0) * 1000)
    except HTTPError as e:
        return Result(url, e.code, (time.perf_counter() - t0) * 1000)
    except URLError as e:
        return Result(url, 0, (time.perf_counter() - t0) * 1000, str(e))


def http_post(url: str, body: bytes, timeout: float = 3.0) -> Result:
    t0 = time.perf_counter()
    try:
        req = Request(url, data=body,
                      headers={"Content-Type": "application/json",
                               "User-Agent": "PhalanxLoadTest/1.0"},
                      method="POST")
        with urlopen(req, timeout=timeout) as resp:
            resp.read()
            return Result(url, resp.status, (time.perf_counter() - t0) * 1000)
    except HTTPError as e:
        return Result(url, e.code, (time.perf_counter() - t0) * 1000)
    except URLError as e:
        return Result(url, 0, (time.perf_counter() - t0) * 1000, str(e))


SCENARIOS = [
    # (weight, url_template, method)
    (40, PROXY_HOST + "/",        "GET"),
    (20, PROXY_HOST + "/api",     "GET"),
    (10, PROXY_HOST + "/health",  "GET"),
    (10, ADMIN_HOST + "/api/stats",     "GET"),
    (10, ADMIN_HOST + "/api/bandwidth", "GET"),
    (5,  ADMIN_HOST + "/api/waf/bans",  "GET"),
    (3,  ADMIN_HOST + "/api/alerts",    "GET"),
    (2,  ADMIN_HOST + "/api/cluster/nodes", "GET"),
    # WAF attacks — expect 403
    (5,  PROXY_HOST + "/?q=1%27%20UNION%20SELECT%201%2C2%2C3--", "GET"),
    (5,  PROXY_HOST + "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "GET"),
]

def _weighted_choice(scenarios):
    weights = [s[0] for s in scenarios]
    total = sum(weights)
    r = random.uniform(0, total)
    acc = 0
    for s in scenarios:
        acc += s[0]
        if r <= acc:
            return s
    return scenarios[-1]


def worker(results: list, stop_event: threading.Event):
    while not stop_event.is_set():
        _, url_t, method = _weighted_choice(SCENARIOS)
        if method == "GET":
            res = http_get(url_t)
        else:
            res = http_post(url_t, b'{"test":true}')
        results.append(res)


def run_standalone(users: int = 50, duration: int = 30):
    print(f"\n{'═'*60}")
    print(f"  Phalanx Standalone Load Test")
    print(f"  Users: {users}  |  Duration: {duration}s")
    print(f"  Proxy:  {PROXY_HOST}")
    print(f"  Admin:  {ADMIN_HOST}")
    print(f"{'═'*60}\n")

    results = []
    stop = threading.Event()

    threads = [
        threading.Thread(target=worker, args=(results, stop), daemon=True)
        for _ in range(users)
    ]
    for t in threads:
        t.start()

    start = time.time()
    last_count = 0
    while time.time() - start < duration:
        time.sleep(5)
        n = len(results)
        delta = n - last_count
        last_count = n
        elapsed = time.time() - start
        rps = delta / 5
        print(f"  [{elapsed:5.0f}s]  requests: {n:6d}  RPS: {rps:6.1f}")

    stop.set()
    for t in threads:
        t.join(timeout=2)

    _print_report(results, duration)


def _print_report(results: list, duration: int):
    total = len(results)
    errors = [r for r in results if r.error]
    by_status = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1

    latencies = [r.latency_ms for r in results if not r.error]
    latencies.sort()

    print(f"\n{'═'*60}")
    print(f"  RESULTS")
    print(f"{'═'*60}")
    print(f"  Total requests   : {total}")
    print(f"  Throughput       : {total / duration:.1f} req/s")
    print(f"  Errors           : {len(errors)}  ({100*len(errors)/max(total,1):.1f}%)")
    print()
    print(f"  Status codes:")
    for status, count in sorted(by_status.items()):
        pct = 100 * count / max(total, 1)
        bar = "█" * int(pct / 2)
        label = "  (WAF block ✓)" if status == 403 else ""
        print(f"    {status:4d}  {count:6d}  {pct:5.1f}%  {bar}{label}")
    print()
    if latencies:
        def pct(p):
            idx = int(len(latencies) * p / 100)
            return latencies[min(idx, len(latencies)-1)]
        print(f"  Latency (ms):")
        print(f"    min   : {min(latencies):.1f}")
        print(f"    p50   : {pct(50):.1f}")
        print(f"    p90   : {pct(90):.1f}")
        print(f"    p99   : {pct(99):.1f}")
        print(f"    max   : {max(latencies):.1f}")
        print(f"    mean  : {statistics.mean(latencies):.1f}")
        print(f"    stdev : {statistics.stdev(latencies):.1f}" if len(latencies) > 1 else "")
    print(f"{'═'*60}\n")

    # Validate WAF
    waf_urls = [r for r in results if "UNION" in r.url or "script" in r.url]
    if waf_urls:
        blocked = sum(1 for r in waf_urls if r.status == 403)
        print(f"  WAF validation: {blocked}/{len(waf_urls)} attack requests blocked (403)")
        if blocked < len(waf_urls) * 0.9:
            print("  ⚠️  WARNING: WAF is NOT blocking all attacks!")
        else:
            print("  ✓  WAF is correctly blocking attack traffic")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phalanx standalone load test")
    parser.add_argument("--users",    type=int, default=50,
                        help="Concurrent virtual users (default: 50)")
    parser.add_argument("--duration", type=int, default=30,
                        help="Test duration in seconds (default: 30)")
    args = parser.parse_args()
    run_standalone(args.users, args.duration)
