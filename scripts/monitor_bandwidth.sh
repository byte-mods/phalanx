#!/usr/bin/env bash
# =============================================================================
# Phalanx — Live Bandwidth & Protocol Monitor
# =============================================================================
# Monitors per-protocol bandwidth from the Phalanx admin API alongside
# OS-level network stats. Works with or without nload/iftop installed.
#
# Usage:
#   ./scripts/monitor_bandwidth.sh
#   ./scripts/monitor_bandwidth.sh --interval=2 --iface=eth0
#   ./scripts/monitor_bandwidth.sh --nload      # launch nload if installed
#   ./scripts/monitor_bandwidth.sh --iftop      # launch iftop if installed
#   ./scripts/monitor_bandwidth.sh --watch      # watch admin bandwidth API
# =============================================================================

set -euo pipefail

ADMIN="${ADMIN:-http://127.0.0.1:9099}"
INTERVAL=3
IFACE=""
MODE="watch"

for arg in "$@"; do
  case "$arg" in
    --interval=*) INTERVAL="${arg#--interval=}" ;;
    --iface=*)    IFACE="${arg#--iface=}" ;;
    --nload)      MODE="nload" ;;
    --iftop)      MODE="iftop" ;;
    --nethogs)    MODE="nethogs" ;;
    --watch)      MODE="watch" ;;
  esac
done

# Auto-detect interface if not set
if [ -z "$IFACE" ]; then
  if command -v ip >/dev/null 2>&1; then
    IFACE=$(ip route 2>/dev/null | grep "^default" | awk '{print $5}' | head -1)
  fi
  IFACE="${IFACE:-lo}"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── nload mode ───────────────────────────────────────────────────────────────

if [ "$MODE" = "nload" ]; then
  if command -v nload >/dev/null 2>&1; then
    echo -e "${BOLD}Launching nload on ${IFACE}…${NC}"
    echo "  Controls: arrows to switch interface, d for details, q to quit"
    exec nload -u H -U H "$IFACE"
  else
    echo -e "${RED}nload not installed.${NC}"
    echo "  macOS: brew install nload"
    echo "  Linux: apt install nload  OR  yum install nload"
    exit 1
  fi
fi

# ─── iftop mode ───────────────────────────────────────────────────────────────

if [ "$MODE" = "iftop" ]; then
  if command -v iftop >/dev/null 2>&1; then
    echo -e "${BOLD}Launching iftop on ${IFACE} (proxy + admin ports)…${NC}"
    exec sudo iftop -i "$IFACE" -P -f "port 18080 or port 9099 or port 5555"
  else
    echo -e "${RED}iftop not installed.${NC}"
    echo "  macOS: brew install iftop"
    echo "  Linux: apt install iftop"
    exit 1
  fi
fi

# ─── nethogs mode ─────────────────────────────────────────────────────────────

if [ "$MODE" = "nethogs" ]; then
  if command -v nethogs >/dev/null 2>&1; then
    echo -e "${BOLD}Launching nethogs on ${IFACE}…${NC}"
    exec sudo nethogs "$IFACE"
  else
    echo -e "${RED}nethogs not installed.${NC}"
    echo "  macOS: brew install nethogs"
    echo "  Linux: apt install nethogs"
    exit 1
  fi
fi

# ─── Watch mode (default) ─────────────────────────────────────────────────────
# Polls admin /api/bandwidth + OS network stats and renders a live table.

clear

python3 - "$ADMIN" "$INTERVAL" "$IFACE" <<'PYEOF'
import sys, time, json, os
from urllib.request import urlopen
from urllib.error import URLError

admin    = sys.argv[1]
interval = float(sys.argv[2])
iface    = sys.argv[3]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

def get_os_bytes(iface):
    """Read cumulative bytes from /proc/net/dev (Linux) or netstat (macOS)."""
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    parts = line.split()
                    return int(parts[1]), int(parts[9])
    except FileNotFoundError:
        # macOS fallback
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ["netstat", "-I", iface, "-b", "-n"],
            stderr=subprocess.DEVNULL, text=True
        )
        lines = out.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            # Column order in macOS netstat: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
            return int(parts[6]), int(parts[9])
    except Exception:
        pass
    return 0, 0

def fmt_bytes(n):
    if n is None or n < 0: return '—'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024: return f'{n:.0f} {unit}'
        n /= 1024
    return f'{n:.2f} TB'

def fmt_rate(bps):
    if bps < 0: return '—'
    for unit in ['bps', 'Kbps', 'Mbps', 'Gbps']:
        if bps < 1000: return f'{bps:.1f} {unit}'
        bps /= 1000
    return f'{bps:.2f} Tbps'

def fetch_bw():
    try:
        with urlopen(f'{admin}/api/bandwidth', timeout=2) as r:
            return json.load(r).get('protocols', [])
    except Exception:
        return None

def fetch_alerts():
    try:
        with urlopen(f'{admin}/api/alerts?n=5', timeout=2) as r:
            d = json.load(r)
            return d.get('alerts', []), d.get('total', 0)
    except Exception:
        return [], 0

def level_color(level):
    return {
        'critical': RED + BOLD,
        'warning':  YELLOW,
        'info':     CYAN,
    }.get(level, NC)

prev_os_rx, prev_os_tx = get_os_bytes(iface)
prev_t = time.time()
iteration = 0

try:
    while True:
        # Clear screen
        print('\033[H\033[2J', end='')

        now = time.time()
        dt  = now - prev_t

        # OS-level bytes
        os_rx, os_tx = get_os_bytes(iface)
        os_rx_rate = (os_rx - prev_os_rx) / dt * 8
        os_tx_rate = (os_tx - prev_os_tx) / dt * 8

        # Admin API bandwidth
        protos = fetch_bw()
        alerts, total_alerts = fetch_alerts()

        ts = time.strftime('%H:%M:%S')
        print(f'{BOLD}⚡ Phalanx Live Bandwidth Monitor  [{ts}]  interval={interval}s  iface={iface}{NC}')
        print('─' * 90)

        # OS-level summary
        rx_c = GREEN if os_rx_rate > 0 else DIM
        tx_c = CYAN  if os_tx_rate > 0 else DIM
        print(f'{BOLD}OS Network ({iface}):{NC}')
        print(f'  RX: {rx_c}{fmt_rate(os_rx_rate):>12s}{NC}  total: {fmt_bytes(os_rx)}')
        print(f'  TX: {tx_c}{fmt_rate(os_tx_rate):>12s}{NC}  total: {fmt_bytes(os_tx)}')
        print()

        if protos is None:
            print(f'{YELLOW}⚠  Admin API unreachable at {admin}{NC}')
            print(f'   Start Phalanx and retry, or set ADMIN=http://host:port')
        else:
            # Per-protocol table
            max_total = max((p['bytes_in'] + p['bytes_out'] for p in protos), default=1) or 1

            print(f'{BOLD}{"Protocol":<12} {"Bytes In":>14} {"Bytes Out":>14} {"Total":>14} {"Requests":>10} {"Conns":>7}  Utilization{NC}')
            print('─' * 90)

            for p in protos:
                total  = p['bytes_in'] + p['bytes_out']
                pct    = total / max_total * 100
                bar_w  = int(pct / 5)  # max 20 chars
                bar_c  = RED if pct > 80 else YELLOW if pct > 50 else GREEN
                bar    = bar_c + '█' * bar_w + NC + '░' * (20 - bar_w)
                conn_c = RED if p['active_connections'] > 100 else NC
                print(f'  {p["protocol"]:<10} '
                      f'{fmt_bytes(p["bytes_in"]):>14} '
                      f'{fmt_bytes(p["bytes_out"]):>14} '
                      f'{fmt_bytes(total):>14} '
                      f'{p["requests"]:>10} '
                      f'{conn_c}{p["active_connections"]:>7}{NC}  '
                      f'{bar} {pct:5.1f}%')

            print()

            # Alerts
            alert_color = RED if total_alerts > 0 else GREEN
            print(f'{BOLD}Resource Alerts:{NC} {alert_color}{total_alerts} total{NC}')
            if alerts:
                for a in alerts[:3]:
                    lc = level_color(a['level'])
                    print(f'  {lc}[{a["level"].upper():8s}]{NC} '
                          f'{a["protocol"]:<10} {a["metric"]:<14} {a["message"][:60]}')
            else:
                print(f'  {GREEN}No active alerts — system healthy{NC}')

        print()
        print(f'{DIM}Press Ctrl+C to stop  |  iteration {iteration}{NC}')

        prev_os_rx, prev_os_tx = os_rx, os_tx
        prev_t = now
        iteration += 1

        time.sleep(interval)

except KeyboardInterrupt:
    print(f'\n{NC}Monitor stopped.')
PYEOF
