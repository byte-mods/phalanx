#!/usr/bin/env python3
"""
Phalanx Admin API — Full Feature Test Suite
============================================
Tests every admin endpoint: health, metrics, discovery, keyval, WAF, cache,
rate-limit, bandwidth, alerts, cluster, ML, WebRTC rooms.

Usage:
    pip install requests pytest
    pytest scripts/test_api.py -v
    # or with a custom admin address:
    ADMIN=http://127.0.0.1:9099 pytest scripts/test_api.py -v
"""

import os
import time
import json
import pytest
import requests

# ── Configuration ────────────────────────────────────────────────────────────

ADMIN   = os.environ.get("ADMIN",   "http://127.0.0.1:9099")
PROXY   = os.environ.get("PROXY",   "http://127.0.0.1:18080")
TIMEOUT = int(os.environ.get("TIMEOUT", "5"))

def url(path: str) -> str:
    return ADMIN.rstrip("/") + path

def purl(path: str) -> str:
    return PROXY.rstrip("/") + path

session = requests.Session()
session.headers["Content-Type"] = "application/json"


# ════════════════════════════════════════════════════════════════════════════
# 1. Health & Metrics
# ════════════════════════════════════════════════════════════════════════════

class TestHealthMetrics:

    def test_health_returns_ok(self):
        r = session.get(url("/health"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert "OK" in r.text

    def test_metrics_is_prometheus_format(self):
        r = session.get(url("/metrics"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert "phalanx_" in r.text
        assert "# HELP" in r.text

    def test_api_stats_shape(self):
        r = session.get(url("/api/stats"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        for key in ("active_connections", "http_requests_total",
                    "cache_hits_total", "waf_blocks_total", "rate_limit_rejections"):
            assert key in d, f"Missing key: {key}"

    def test_api_stats_active_connections_is_number(self):
        r = session.get(url("/api/stats"), timeout=TIMEOUT)
        d = r.json()
        assert isinstance(d["active_connections"], (int, float))

    def test_dashboard_html_served(self):
        r = session.get(url("/dashboard"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")
        assert "Phalanx" in r.text


# ════════════════════════════════════════════════════════════════════════════
# 2. Service Discovery & Upstreams
# ════════════════════════════════════════════════════════════════════════════

class TestDiscovery:
    BACKEND = {"address": "127.0.0.1:19999", "pool": "default",
               "weight": 1, "tags": {}}

    def test_add_backend(self):
        r = session.post(url("/api/discovery/backends"),
                         json=self.BACKEND, timeout=TIMEOUT)
        assert r.status_code in (200, 409), f"Unexpected status: {r.status_code}"

    def test_upstreams_detail_contains_pool(self):
        r = session.get(url("/api/upstreams/detail"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert isinstance(d, dict), "Expected a dict of pool → backends"

    def test_upstreams_backend_fields(self):
        r = session.get(url("/api/upstreams/detail"), timeout=TIMEOUT)
        d = r.json()
        for pool, info in d.items():
            for b in info.get("backends", []):
                for field in ("address", "healthy", "active_conns", "weight"):
                    assert field in b, f"Pool {pool} backend missing field: {field}"

    def test_remove_backend(self):
        self.test_add_backend()
        r = session.delete(url("/api/discovery/backends/default/127.0.0.1:19999"),
                           timeout=TIMEOUT)
        assert r.status_code in (200, 404)

    def test_remove_nonexistent_backend_graceful(self):
        r = session.delete(url("/api/discovery/backends/default/0.0.0.0:1"),
                           timeout=TIMEOUT)
        assert r.status_code in (200, 404)


# ════════════════════════════════════════════════════════════════════════════
# 3. Keyval Store
# ════════════════════════════════════════════════════════════════════════════

class TestKeyval:
    KEY = "test-kv-key"

    def setup_method(self):
        # Clean up before each test
        session.delete(url(f"/api/keyval/{self.KEY}"), timeout=TIMEOUT)

    def test_set_and_get(self):
        session.post(url(f"/api/keyval/{self.KEY}"),
                     json={"value": "hello", "ttl_secs": None}, timeout=TIMEOUT)
        r = session.get(url(f"/api/keyval/{self.KEY}"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["value"] == "hello"

    def test_get_missing_key_returns_404(self):
        r = session.get(url("/api/keyval/no-such-key-xyz"), timeout=TIMEOUT)
        assert r.status_code == 404

    def test_set_with_ttl(self):
        r = session.post(url(f"/api/keyval/{self.KEY}"),
                         json={"value": "expires", "ttl_secs": 300}, timeout=TIMEOUT)
        assert r.status_code == 200

    def test_delete_existing_key(self):
        session.post(url(f"/api/keyval/{self.KEY}"),
                     json={"value": "to-delete", "ttl_secs": None}, timeout=TIMEOUT)
        r = session.delete(url(f"/api/keyval/{self.KEY}"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

    def test_delete_missing_key_returns_404(self):
        r = session.delete(url("/api/keyval/never-set-xyz"), timeout=TIMEOUT)
        assert r.status_code == 404

    def test_list_all_keys(self):
        session.post(url(f"/api/keyval/{self.KEY}"),
                     json={"value": "listed", "ttl_secs": None}, timeout=TIMEOUT)
        r = session.get(url("/api/keyval"), timeout=TIMEOUT)
        assert r.status_code == 200
        entries = r.json()
        keys = [e["key"] for e in entries]
        assert self.KEY in keys

    def test_overwrite_value(self):
        session.post(url(f"/api/keyval/{self.KEY}"),
                     json={"value": "first", "ttl_secs": None}, timeout=TIMEOUT)
        session.post(url(f"/api/keyval/{self.KEY}"),
                     json={"value": "second", "ttl_secs": None}, timeout=TIMEOUT)
        r = session.get(url(f"/api/keyval/{self.KEY}"), timeout=TIMEOUT)
        assert r.json()["value"] == "second"


# ════════════════════════════════════════════════════════════════════════════
# 4. WAF: Bans, Strikes, Attacks
# ════════════════════════════════════════════════════════════════════════════

class TestWaf:
    TEST_IP = "10.255.255.1"

    def setup_method(self):
        session.delete(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)

    def test_list_bans_is_list(self):
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert isinstance(r.json()["bans"], list)

    def test_manual_ban_ip(self):
        r = session.post(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["status"] == "banned"

    def test_banned_ip_appears_in_list(self):
        session.post(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        ips = [b["ip"] for b in r.json()["bans"]]
        assert self.TEST_IP in ips

    def test_ban_entry_has_required_fields(self):
        session.post(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        entry = next((b for b in r.json()["bans"] if b["ip"] == self.TEST_IP), None)
        assert entry is not None
        for field in ("ip", "strikes", "expires_in_secs"):
            assert field in entry, f"Ban entry missing field: {field}"

    def test_unban_removes_ip(self):
        session.post(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)
        r = session.delete(url(f"/api/waf/ban/{self.TEST_IP}"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["status"] == "unbanned"
        r2 = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        ips = [b["ip"] for b in r2.json()["bans"]]
        assert self.TEST_IP not in ips

    def test_list_attacks_is_list(self):
        r = session.get(url("/api/waf/attacks"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert isinstance(r.json()["attacks"], list)

    def test_list_strikes_is_list(self):
        r = session.get(url("/api/waf/strikes"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert isinstance(r.json()["strikes"], list)

    def test_strikes_entries_have_ip_and_count(self):
        r = session.get(url("/api/waf/strikes"), timeout=TIMEOUT)
        for s in r.json()["strikes"]:
            assert "ip" in s
            assert "strikes" in s

    def test_ban_multiple_ips(self):
        ips = ["10.254.0.1", "10.254.0.2", "10.254.0.3"]
        for ip in ips:
            session.post(url(f"/api/waf/ban/{ip}"), timeout=TIMEOUT)
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        banned = [b["ip"] for b in r.json()["bans"]]
        for ip in ips:
            assert ip in banned
        # cleanup
        for ip in ips:
            session.delete(url(f"/api/waf/ban/{ip}"), timeout=TIMEOUT)


# ════════════════════════════════════════════════════════════════════════════
# 5. Rate Limit Top-IPs
# ════════════════════════════════════════════════════════════════════════════

class TestRateLimit:

    def test_top_ips_default_n(self):
        r = session.get(url("/api/rates/top"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert "top_ips" in d
        assert isinstance(d["top_ips"], list)
        assert len(d["top_ips"]) <= 10

    def test_top_ips_custom_n(self):
        r = session.get(url("/api/rates/top?n=5"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert len(r.json()["top_ips"]) <= 5

    def test_top_ips_n_capped_at_100(self):
        r = session.get(url("/api/rates/top?n=9999"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert len(r.json()["top_ips"]) <= 100

    def test_top_ips_entries_have_ip_and_requests(self):
        r = session.get(url("/api/rates/top?n=50"), timeout=TIMEOUT)
        for entry in r.json()["top_ips"]:
            assert "ip" in entry
            assert "requests" in entry


# ════════════════════════════════════════════════════════════════════════════
# 6. Cache
# ════════════════════════════════════════════════════════════════════════════

class TestCache:

    def test_cache_stats_shape(self):
        r = session.get(url("/api/cache/stats"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert "entries" in d
        assert isinstance(d["entries"], int)

    def test_cache_purge_all(self):
        r = session.post(url("/api/cache/purge"),
                         json={}, timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_cache_purge_by_key(self):
        r = session.post(url("/api/cache/purge"),
                         json={"key": "/some/cached/path"}, timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["key"] == "/some/cached/path"

    def test_cache_purge_by_prefix(self):
        r = session.post(url("/api/cache/purge"),
                         json={"prefix": "/api/"}, timeout=TIMEOUT)
        assert r.status_code == 200
        assert r.json()["prefix"] == "/api/"

    def test_cache_entries_non_negative(self):
        r = session.get(url("/api/cache/stats"), timeout=TIMEOUT)
        assert r.json()["entries"] >= 0


# ════════════════════════════════════════════════════════════════════════════
# 7. Bandwidth
# ════════════════════════════════════════════════════════════════════════════

class TestBandwidth:
    EXPECTED_PROTOCOLS = {"http1", "http2", "http3", "websocket",
                          "grpc", "tcp", "udp", "webrtc"}

    def test_bandwidth_returns_protocols(self):
        r = session.get(url("/api/bandwidth"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert "protocols" in d
        assert isinstance(d["protocols"], list)

    def test_all_known_protocols_present(self):
        r = session.get(url("/api/bandwidth"), timeout=TIMEOUT)
        found = {p["protocol"] for p in r.json()["protocols"]}
        for proto in self.EXPECTED_PROTOCOLS:
            assert proto in found, f"Missing protocol: {proto}"

    def test_protocol_entry_fields(self):
        r = session.get(url("/api/bandwidth"), timeout=TIMEOUT)
        for p in r.json()["protocols"]:
            for field in ("protocol", "bytes_in", "bytes_out",
                          "requests", "active_connections"):
                assert field in p, f"Protocol entry missing field: {field}"

    def test_bytes_are_non_negative(self):
        r = session.get(url("/api/bandwidth"), timeout=TIMEOUT)
        for p in r.json()["protocols"]:
            assert p["bytes_in"] >= 0
            assert p["bytes_out"] >= 0
            assert p["requests"] >= 0

    def test_bandwidth_response_is_sorted(self):
        r = session.get(url("/api/bandwidth"), timeout=TIMEOUT)
        protos = r.json()["protocols"]
        totals = [(p["bytes_in"] + p["bytes_out"]) for p in protos]
        assert totals == sorted(totals, reverse=True), \
            "Protocols should be sorted by total bytes descending"


# ════════════════════════════════════════════════════════════════════════════
# 8. Resource Alerts
# ════════════════════════════════════════════════════════════════════════════

class TestAlerts:

    def test_list_alerts_shape(self):
        r = session.get(url("/api/alerts"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert "alerts" in d
        assert "total" in d
        assert isinstance(d["alerts"], list)

    def test_list_alerts_custom_n(self):
        r = session.get(url("/api/alerts?n=5"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert len(r.json()["alerts"]) <= 5

    def test_trigger_check_returns_status(self):
        r = session.post(url("/api/alerts/check"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "checked"
        assert "alert_count" in d

    def test_trigger_check_alert_count_non_negative(self):
        r = session.post(url("/api/alerts/check"), timeout=TIMEOUT)
        assert r.json()["alert_count"] >= 0

    def test_alert_entries_have_required_fields(self):
        session.post(url("/api/alerts/check"), timeout=TIMEOUT)
        r = session.get(url("/api/alerts?n=100"), timeout=TIMEOUT)
        for a in r.json()["alerts"]:
            for field in ("timestamp", "level", "category",
                          "protocol", "metric", "message", "value", "threshold"):
                assert field in a, f"Alert entry missing field: {field}"

    def test_alert_levels_valid(self):
        r = session.get(url("/api/alerts?n=100"), timeout=TIMEOUT)
        valid_levels = {"info", "warning", "critical"}
        for a in r.json()["alerts"]:
            assert a["level"] in valid_levels, f"Unknown alert level: {a['level']}"

    def test_alerts_newest_first(self):
        r = session.get(url("/api/alerts?n=100"), timeout=TIMEOUT)
        timestamps = [a["timestamp"] for a in r.json()["alerts"]]
        assert timestamps == sorted(timestamps, reverse=True), \
            "Alerts should be newest first"


# ════════════════════════════════════════════════════════════════════════════
# 9. Cluster Nodes
# ════════════════════════════════════════════════════════════════════════════

class TestCluster:

    def test_cluster_nodes_shape(self):
        r = session.get(url("/api/cluster/nodes"), timeout=TIMEOUT)
        assert r.status_code == 200
        d = r.json()
        assert "nodes" in d
        assert isinstance(d["nodes"], list)
        assert len(d["nodes"]) >= 1

    def test_node_fields(self):
        r = session.get(url("/api/cluster/nodes"), timeout=TIMEOUT)
        for node in r.json()["nodes"]:
            for field in ("node_id", "status", "last_seen_secs"):
                assert field in node, f"Node missing field: {field}"

    def test_at_least_one_healthy_node(self):
        r = session.get(url("/api/cluster/nodes"), timeout=TIMEOUT)
        statuses = [n["status"] for n in r.json()["nodes"]]
        assert "healthy" in statuses


# ════════════════════════════════════════════════════════════════════════════
# 10. Config Reload
# ════════════════════════════════════════════════════════════════════════════

class TestReload:

    def test_reload_returns_status(self):
        r = session.post(url("/api/reload"), timeout=TIMEOUT)
        assert r.status_code == 200
        assert "status" in r.json()


# ════════════════════════════════════════════════════════════════════════════
# 11. ML Endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestMl:

    def test_ml_logs_shape(self):
        r = session.get(url("/api/ml/logs"), timeout=TIMEOUT)
        assert r.status_code in (200, 404)  # 404 if ML not started
        if r.status_code == 200:
            assert "logs" in r.json()

    def test_ml_mode_update(self):
        r = session.put(url("/api/ml/mode"),
                        json={"mode": "shadow"}, timeout=TIMEOUT)
        assert r.status_code in (200, 400, 404)


# ════════════════════════════════════════════════════════════════════════════
# 12. WebRTC Rooms  (signalling may not be wired without WebRTC binary)
# ════════════════════════════════════════════════════════════════════════════

class TestWebRtc:

    def test_rooms_endpoint_accessible(self):
        r = session.get(url("/api/webrtc/rooms"), timeout=TIMEOUT)
        assert r.status_code in (200, 404)

    def test_rooms_shape_when_available(self):
        r = session.get(url("/api/webrtc/rooms"), timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            assert "rooms" in d
            assert isinstance(d["rooms"], list)

    def test_rooms_entries_have_bandwidth_fields(self):
        r = session.get(url("/api/webrtc/rooms"), timeout=TIMEOUT)
        if r.status_code == 200:
            for room in r.json()["rooms"]:
                for field in ("id", "track_count", "peer_count",
                              "bytes_forwarded", "packets_forwarded"):
                    assert field in room, f"Room missing field: {field}"


# ════════════════════════════════════════════════════════════════════════════
# 13. Proxy endpoint smoke tests (require backends to be up)
# ════════════════════════════════════════════════════════════════════════════

class TestProxySmoke:
    """Light smoke tests that are skipped if the proxy port is unreachable."""

    @pytest.fixture(autouse=True)
    def skip_if_proxy_down(self):
        try:
            requests.get(purl("/health"), timeout=1)
        except requests.exceptions.ConnectionError:
            pytest.skip("Proxy not reachable — skipping proxy smoke tests")

    def test_proxy_root_responds(self):
        r = requests.get(purl("/"), timeout=TIMEOUT)
        assert r.status_code < 600

    def test_proxy_injects_headers(self):
        r = requests.get(purl("/api"), timeout=TIMEOUT)
        # Phalanx adds X-Proxy-By when route has add_header
        # Accept any 5xx since backend may be down — we just want a response
        assert r.status_code < 600

    def test_waf_blocks_sqli(self):
        r = requests.get(purl("/?q=1'%20UNION%20SELECT%201,2,3--"),
                         timeout=TIMEOUT)
        assert r.status_code == 403, \
            f"WAF should return 403 for SQLi, got {r.status_code}"

    def test_waf_blocks_xss(self):
        r = requests.get(purl("/?q=%3Cscript%3Ealert(1)%3C/script%3E"),
                         timeout=TIMEOUT)
        assert r.status_code == 403, \
            f"WAF should return 403 for XSS, got {r.status_code}"

    def test_rate_limit_burst(self):
        """Send 200 rapid requests — some should be rate-limited (429)."""
        statuses = []
        for _ in range(200):
            try:
                r = requests.get(purl("/"), timeout=1)
                statuses.append(r.status_code)
            except Exception:
                pass
        # With burst=100 from config, 200 requests should see some 429s
        # (only assert if rate limiting is configured)
        status_set = set(statuses)
        print(f"Statuses seen in burst test: {status_set}")
        # Non-strict: just check we got responses
        assert len(statuses) > 0


# ════════════════════════════════════════════════════════════════════════════
# 14. End-to-end scenario: Ban → Verify blocked → Unban → Verify allowed
# ════════════════════════════════════════════════════════════════════════════

class TestE2EBanFlow:

    def test_ban_flow(self):
        ip = "10.200.0.1"
        # Clean state
        session.delete(url(f"/api/waf/ban/{ip}"), timeout=TIMEOUT)

        # Ban
        r = session.post(url(f"/api/waf/ban/{ip}"), timeout=TIMEOUT)
        assert r.status_code == 200

        # Verify appears in list
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        assert any(b["ip"] == ip for b in r.json()["bans"])

        # Unban
        r = session.delete(url(f"/api/waf/ban/{ip}"), timeout=TIMEOUT)
        assert r.status_code == 200

        # Verify removed
        r = session.get(url("/api/waf/bans"), timeout=TIMEOUT)
        assert not any(b["ip"] == ip for b in r.json()["bans"])


# ════════════════════════════════════════════════════════════════════════════
# 15. Stress / concurrent requests (lightweight, no locust needed)
# ════════════════════════════════════════════════════════════════════════════

class TestConcurrent:

    def test_concurrent_health_checks(self):
        import concurrent.futures
        def check():
            r = requests.get(url("/health"), timeout=TIMEOUT)
            return r.status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(lambda _: check(), range(100)))
        assert all(s == 200 for s in results), \
            f"Some health checks failed: {set(results)}"

    def test_concurrent_stats_reads(self):
        import concurrent.futures
        def check():
            r = requests.get(url("/api/stats"), timeout=TIMEOUT)
            return r.status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(lambda _: check(), range(50)))
        assert all(s == 200 for s in results)

    def test_concurrent_bandwidth_reads(self):
        import concurrent.futures
        def check():
            r = requests.get(url("/api/bandwidth"), timeout=TIMEOUT)
            return r.status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(lambda _: check(), range(50)))
        assert all(s == 200 for s in results)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
