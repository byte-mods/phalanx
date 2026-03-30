#!/usr/bin/env bash
# =============================================================================
# Phalanx — Full Test Orchestrator
# =============================================================================
# Runs: Rust unit tests, Rust integration tests, Python API tests,
#       standalone load test, nload monitoring, and generates an HTML report.
#
# Usage:
#   ./scripts/run_tests.sh                   # full suite
#   ./scripts/run_tests.sh --quick           # skip load test
#   ./scripts/run_tests.sh --load-only       # load test only
#   ./scripts/run_tests.sh --monitor         # network monitoring only
#
# Requirements:
#   - cargo (Rust toolchain)
#   - python3 + pip (pytest, requests, locust optional)
#   - nc / nmap (port checks)
#   - nload / iftop / nethogs (optional, for bandwidth monitoring)
# =============================================================================

set -euo pipefail

ADMIN="${ADMIN:-http://127.0.0.1:9099}"
PROXY="${PROXY:-http://127.0.0.1:18080}"
LOAD_USERS="${LOAD_USERS:-50}"
LOAD_DURATION="${LOAD_DURATION:-30}"
REPORT_DIR="target/test-reports"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="${REPORT_DIR}/report_${TIMESTAMP}.html"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

pass_count=0
fail_count=0
skip_count=0

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; ((pass_count++)); }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; ((fail_count++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; ((skip_count++)); }
sep()   { echo -e "${BOLD}$(printf '═%.0s' {1..70})${NC}"; }

check_port() {
  local host="${1%:*}"
  local port="${1##*:}"
  # strip http:// prefix if present
  host="${host#http://}"
  host="${host#https://}"
  nc -z -w2 "$host" "$port" 2>/dev/null
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# ─── Parse args ──────────────────────────────────────────────────────────────

QUICK=false
LOAD_ONLY=false
MONITOR_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --quick)       QUICK=true ;;
    --load-only)   LOAD_ONLY=true ;;
    --monitor)     MONITOR_ONLY=true ;;
  esac
done

mkdir -p "$REPORT_DIR"

# ─── Banner ───────────────────────────────────────────────────────────────────

sep
echo -e "${BOLD}  Phalanx Test Suite — $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "  Admin:  ${ADMIN}"
echo -e "  Proxy:  ${PROXY}"
echo -e "  Mode:   quick=${QUICK} load_only=${LOAD_ONLY} monitor=${MONITOR_ONLY}"
sep

# ─── Network Monitoring (optional standalone mode) ────────────────────────────

if $MONITOR_ONLY; then
  echo ""
  info "Network monitoring mode — choose a tool:"
  echo ""
  echo "  1. nload (real-time bandwidth per interface):"
  echo "     nload -u H -U H eth0"
  echo ""
  echo "  2. iftop (per-connection bandwidth):"
  echo "     sudo iftop -i eth0 -P"
  echo ""
  echo "  3. nethogs (per-process bandwidth):"
  echo "     sudo nethogs eth0"
  echo ""
  echo "  4. ss (socket stats — connections to proxy port):"
  echo "     watch -n1 'ss -tnp | grep :18080'"
  echo ""
  echo "  5. Python inline bandwidth sampler:"
  python3 - <<'PYEOF'
import time, subprocess, sys

def get_bytes(iface="lo"):
    try:
        with open(f"/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    fields = line.split()
                    return int(fields[1]), int(fields[9])
    except:
        return 0, 0
    return 0, 0

IFACE = "lo"  # change to eth0/en0 for real traffic
print(f"Monitoring {IFACE} — Ctrl+C to stop\n")
print(f"{'Time':12s} {'RX (KB/s)':>12s} {'TX (KB/s)':>12s}")
print("-" * 38)

prev_rx, prev_tx = get_bytes(IFACE)
prev_t = time.time()

try:
    while True:
        time.sleep(2)
        rx, tx = get_bytes(IFACE)
        t = time.time()
        dt = t - prev_t
        rx_rate = (rx - prev_rx) / dt / 1024
        tx_rate = (tx - prev_tx) / dt / 1024
        print(f"{time.strftime('%H:%M:%S'):12s} {rx_rate:>12.1f} {tx_rate:>12.1f}")
        prev_rx, prev_tx, prev_t = rx, tx, t
except KeyboardInterrupt:
    print("\nDone.")
PYEOF
  exit 0
fi

# ─── Section 1: Rust Tests ────────────────────────────────────────────────────

if ! $LOAD_ONLY; then
  sep
  echo -e "${BOLD}  § 1. Rust Unit + Integration Tests${NC}"
  sep

  if require_cmd cargo; then
    info "Running cargo test…"
    if cargo test --workspace 2>&1 | tee "${REPORT_DIR}/rust_tests.log" | tail -5; then
      # Extract pass/fail from output
      RUST_RESULT=$(grep "test result:" "${REPORT_DIR}/rust_tests.log" | tail -3)
      echo "$RUST_RESULT" | while read -r line; do
        if echo "$line" | grep -q "FAILED"; then
          fail "Rust: $line"
        else
          ok "Rust: $line"
        fi
      done
    else
      fail "cargo test exited with error"
    fi
  else
    warn "cargo not found — skipping Rust tests"
  fi
fi

# ─── Section 2: Service Availability Check ────────────────────────────────────

sep
echo -e "${BOLD}  § 2. Service Availability${NC}"
sep

ADMIN_HOST="${ADMIN#http://}"; ADMIN_HOST="${ADMIN_HOST%/*}"
PROXY_HOST="${PROXY#http://}"; PROXY_HOST="${PROXY_HOST%/*}"

if check_port "$ADMIN_HOST"; then
  ok "Admin API reachable at ${ADMIN}"
  ADMIN_UP=true
else
  warn "Admin API not reachable at ${ADMIN} — API tests will be skipped"
  ADMIN_UP=false
fi

if check_port "$PROXY_HOST"; then
  ok "Proxy reachable at ${PROXY}"
  PROXY_UP=true
else
  warn "Proxy not reachable at ${PROXY} — proxy smoke tests will be skipped"
  PROXY_UP=false
fi

# ─── Section 3: Python API Tests ─────────────────────────────────────────────

if ! $LOAD_ONLY; then
  sep
  echo -e "${BOLD}  § 3. Python API Tests${NC}"
  sep

  if ! require_cmd python3; then
    warn "python3 not found — skipping Python tests"
  elif ! python3 -c "import requests" 2>/dev/null; then
    warn "requests not installed — run: pip install requests pytest"
  elif ! $ADMIN_UP; then
    warn "Admin not up — skipping Python API tests"
  else
    if require_cmd pytest; then
      info "Running pytest…"
      ADMIN="$ADMIN" PROXY="$PROXY" \
        pytest scripts/test_api.py -v \
          --tb=short \
          --junit-xml="${REPORT_DIR}/pytest_results.xml" \
          2>&1 | tee "${REPORT_DIR}/pytest.log"
      if [ ${PIPESTATUS[0]} -eq 0 ]; then
        ok "Python API tests passed"
      else
        fail "Python API tests had failures"
      fi
    else
      info "pytest not found — running with python3 -m pytest"
      ADMIN="$ADMIN" PROXY="$PROXY" \
        python3 -m pytest scripts/test_api.py -v \
          --tb=short \
          2>&1 | tee "${REPORT_DIR}/pytest.log" || fail "Python API tests failed"
    fi
  fi
fi

# ─── Section 4: WAF Attack Validation ────────────────────────────────────────

sep
echo -e "${BOLD}  § 4. WAF Attack Validation${NC}"
sep

if ! $PROXY_UP; then
  warn "Proxy not reachable — skipping WAF tests"
else
  ATTACKS=(
    "/?q=1' UNION SELECT password FROM users-- :SQLi:403"
    "/?q=<script>alert(1)</script>             :XSS:403"
    "/../../../etc/passwd                       :PathTraversal:400,403,404"
    "/?q=1;cat /etc/passwd                     :CMDi:403"
    "/?q=../../../windows/system32/cmd.exe     :Traversal_Win:400,403,404"
    "/                                          :CleanRequest:200,502,503"
  )

  for entry in "${ATTACKS[@]}"; do
    IFS=: read -r path name expected <<< "$entry"
    path="${path%"${path##*[! ]}"}"  # trim trailing spaces
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             --connect-timeout 3 "${PROXY}${path}" 2>/dev/null || echo "000")
    # Check if status is in expected list
    if echo "$expected" | tr ',' '\n' | grep -qx "$STATUS"; then
      ok "WAF [${name}]: HTTP ${STATUS} (expected ${expected})"
    else
      fail "WAF [${name}]: HTTP ${STATUS} (expected ${expected}) — POSSIBLE WAF MISS"
    fi
  done
fi

# ─── Section 5: Rate Limit Burst Test ────────────────────────────────────────

sep
echo -e "${BOLD}  § 5. Rate Limit Burst Validation${NC}"
sep

if ! $PROXY_UP; then
  warn "Proxy not reachable — skipping rate limit test"
else
  info "Sending 200 rapid requests to proxy…"
  STATUS_COUNTS=$(
    for i in $(seq 1 200); do
      curl -s -o /dev/null -w "%{http_code}\n" \
           --connect-timeout 1 "${PROXY}/?burst=$i" 2>/dev/null || echo "000"
    done | sort | uniq -c | sort -rn
  )
  echo "$STATUS_COUNTS" | while read -r count status; do
    if [ "$status" = "429" ]; then
      ok "Rate limiter fired: ${count}× HTTP 429"
    elif [ "$status" = "200" ]; then
      info "Normal responses: ${count}× HTTP 200"
    elif [ "$status" = "000" ]; then
      warn "Connection errors: ${count}× (proxy may be overloaded)"
    else
      info "Other: ${count}× HTTP ${status}"
    fi
  done
fi

# ─── Section 6: Admin API Curl Smoke Tests ────────────────────────────────────

sep
echo -e "${BOLD}  § 6. Admin API Curl Smoke Tests${NC}"
sep

if ! $ADMIN_UP; then
  warn "Admin not up — skipping curl smoke tests"
else
  ENDPOINTS=(
    "GET    /health                     :200"
    "GET    /metrics                    :200"
    "GET    /api/stats                  :200"
    "GET    /api/bandwidth              :200"
    "GET    /api/alerts                 :200"
    "GET    /api/waf/bans               :200"
    "GET    /api/waf/strikes            :200"
    "GET    /api/waf/attacks            :200"
    "GET    /api/rates/top              :200"
    "GET    /api/cache/stats            :200"
    "GET    /api/cluster/nodes         :200"
    "GET    /api/upstreams/detail       :200"
    "GET    /api/keyval                 :200"
    "POST   /api/alerts/check          :200"
    "POST   /api/reload                :200"
  )

  for entry in "${ENDPOINTS[@]}"; do
    method=$(echo "$entry" | awk '{print $1}')
    path=$(echo "$entry"   | awk '{print $2}')
    expected=$(echo "$entry" | awk -F: '{print $2}')

    if [ "$method" = "GET" ]; then
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
               --connect-timeout 3 "${ADMIN}${path}" 2>/dev/null || echo "000")
    else
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
               -X POST -H "Content-Type: application/json" -d '{}' \
               --connect-timeout 3 "${ADMIN}${path}" 2>/dev/null || echo "000")
    fi

    if [ "$STATUS" = "$expected" ]; then
      ok "${method} ${path} → HTTP ${STATUS}"
    else
      fail "${method} ${path} → HTTP ${STATUS} (expected ${expected})"
    fi
  done
fi

# ─── Section 7: Bandwidth Stats Validation ────────────────────────────────────

sep
echo -e "${BOLD}  § 7. Bandwidth Stats Validation${NC}"
sep

if ! $ADMIN_UP; then
  warn "Admin not up — skipping bandwidth validation"
else
  BW_JSON=$(curl -sf "${ADMIN}/api/bandwidth" 2>/dev/null || echo '{}')
  PROTO_COUNT=$(echo "$BW_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('protocols',[])))" 2>/dev/null || echo "0")
  if [ "$PROTO_COUNT" -ge 8 ]; then
    ok "Bandwidth tracker has ${PROTO_COUNT} protocol buckets"
  else
    fail "Expected ≥8 protocol buckets, got ${PROTO_COUNT}"
  fi

  PROTOCOLS=$(echo "$BW_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('protocols', []):
    print(f\"  {p['protocol']:12s}  in={p['bytes_in']:10d}  out={p['bytes_out']:10d}  conns={p['active_connections']:5d}\")
" 2>/dev/null || echo "  (parse error)")
  echo "$PROTOCOLS"
fi

# ─── Section 8: Load Test ────────────────────────────────────────────────────

if ! $QUICK; then
  sep
  echo -e "${BOLD}  § 8. Load Test (${LOAD_USERS} users × ${LOAD_DURATION}s)${NC}"
  sep

  if ! require_cmd python3; then
    warn "python3 not found — skipping load test"
  else
    info "Starting standalone load test…"
    ADMIN="$ADMIN" PROXY="$PROXY" \
      python3 scripts/load_test.py \
        --users "$LOAD_USERS" \
        --duration "$LOAD_DURATION" \
        2>&1 | tee "${REPORT_DIR}/load_test.log"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
      ok "Load test completed"
    else
      fail "Load test failed"
    fi
  fi

  # Optional locust
  if require_cmd locust && $ADMIN_UP; then
    info "Locust available — running headless for 30s…"
    ADMIN="$ADMIN" PROXY="$PROXY" \
      locust -f scripts/load_test.py \
        --host="${PROXY}" \
        --users="${LOAD_USERS}" \
        --spawn-rate=10 \
        --run-time=30s \
        --headless \
        --csv="${REPORT_DIR}/locust" \
        2>&1 | tee "${REPORT_DIR}/locust.log" || warn "Locust run had errors (non-fatal)"
    ok "Locust run complete — CSV at ${REPORT_DIR}/locust_stats.csv"
  fi
fi

# ─── Section 9: Network Monitoring Summary ────────────────────────────────────

sep
echo -e "${BOLD}  § 9. Network Monitoring Commands${NC}"
sep

echo ""
echo "  Run these while sending load to monitor bandwidth:"
echo ""

if require_cmd nload; then
  IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0")
  echo -e "  ${GREEN}nload${NC} (installed):"
  echo "    nload -u H -U H ${IFACE}"
else
  echo "  nload (not installed — brew install nload  OR  apt install nload):"
  echo "    nload -u H -U H eth0"
fi

if require_cmd iftop; then
  echo ""
  echo -e "  ${GREEN}iftop${NC} (installed):"
  echo "    sudo iftop -i lo -P -f 'port 18080 or port 9099'"
else
  echo ""
  echo "  iftop (not installed — brew install iftop  OR  apt install iftop):"
  echo "    sudo iftop -i eth0 -P -f 'port 18080'"
fi

echo ""
echo "  socket stats (built-in):"
echo "    watch -n1 'ss -tnp sport = :18080 | wc -l'"
echo ""
echo "  curl latency sweep:"
echo "    for i in {1..20}; do curl -s -w '%{time_total}\n' -o /dev/null ${PROXY}/; done"
echo ""

# ─── Section 10: HTML Report ─────────────────────────────────────────────────

sep
echo -e "${BOLD}  § 10. Generating HTML Report${NC}"
sep

cat > "$REPORT_FILE" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Phalanx Test Report — ${TIMESTAMP}</title>
  <style>
    body { font-family: monospace; background: #0f1117; color: #d1d5db; padding: 24px; }
    h1 { color: #f8fafc; }
    .ok  { color: #22c55e; }
    .err { color: #ef4444; }
    .warn{ color: #f59e0b; }
    pre { background: #1e293b; padding: 16px; border-radius: 8px; overflow: auto; }
    .summary { font-size: 1.2rem; font-weight: bold; padding: 12px; border-radius: 8px;
               background: #1e293b; margin: 16px 0; }
  </style>
</head>
<body>
<h1>⚡ Phalanx Test Report</h1>
<p>Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
<p>Admin: ${ADMIN}  |  Proxy: ${PROXY}</p>
<div class="summary">
  Pass: <span class="ok">${pass_count}</span> &nbsp;
  Fail: <span class="err">${fail_count}</span> &nbsp;
  Skipped: <span class="warn">${skip_count}</span>
</div>
<h2>Rust Test Log</h2>
<pre>$(cat "${REPORT_DIR}/rust_tests.log" 2>/dev/null | tail -30 | sed 's/</\&lt;/g;s/>/\&gt;/g')</pre>
<h2>Python API Test Log</h2>
<pre>$(cat "${REPORT_DIR}/pytest.log" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g')</pre>
<h2>Load Test Log</h2>
<pre>$(cat "${REPORT_DIR}/load_test.log" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g')</pre>
</body>
</html>
HTMLEOF

ok "HTML report written to ${REPORT_FILE}"

# ─── Final Summary ────────────────────────────────────────────────────────────

sep
echo -e "${BOLD}  FINAL RESULTS${NC}"
sep
echo -e "  ${GREEN}Passed :${NC} ${pass_count}"
echo -e "  ${RED}Failed :${NC} ${fail_count}"
echo -e "  ${YELLOW}Skipped:${NC} ${skip_count}"
echo ""
echo -e "  Report: ${REPORT_FILE}"
echo ""

if [ "$fail_count" -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}✓ ALL TESTS PASSED${NC}"
  exit 0
else
  echo -e "  ${RED}${BOLD}✗ ${fail_count} TEST(S) FAILED${NC}"
  exit 1
fi
