#!/usr/bin/env bash
# =============================================================================
# Start lightweight HTTP test backends for Phalanx integration testing
# =============================================================================
# Spins up two Node.js or Python HTTP backends on ports 18081 and 18082
# (matching the default phalanx.conf upstream pool).
# Also starts a WebSocket echo backend on 18083.
#
# Usage:
#   ./scripts/start_test_backends.sh [--stop]
#
# Backends:
#   port 18081 — primary backend (echoes request info as JSON)
#   port 18082 — secondary backend (echoes with "backend:2" label)
#   port 18083 — WebSocket echo server (if ws npm package available)
# =============================================================================

set -euo pipefail

PIDS_FILE="/tmp/phalanx_test_backends.pids"

if [ "${1:-}" = "--stop" ]; then
  if [ -f "$PIDS_FILE" ]; then
    echo "Stopping test backends…"
    while read -r pid; do
      kill "$pid" 2>/dev/null && echo "  killed PID $pid" || true
    done < "$PIDS_FILE"
    rm -f "$PIDS_FILE"
    echo "Backends stopped."
  else
    echo "No backends running (no PID file)."
  fi
  exit 0
fi

> "$PIDS_FILE"

start_python_backend() {
  local port=$1
  local label=$2
  python3 - "$port" "$label" &
  echo $! >> "$PIDS_FILE"
  echo "  Backend '$label' started on port $port (PID $!)"
}

# ─── Python HTTP backends ─────────────────────────────────────────────────────

cat > /tmp/phalanx_backend.py << 'PYEOF'
#!/usr/bin/env python3
"""Minimal HTTP backend that echoes request info as JSON."""
import sys, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT  = int(sys.argv[1])
LABEL = sys.argv[2]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silence default access log

    def do_GET(self):
        self._respond()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
        self._respond(body=body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.end_headers()

    def _respond(self, body=''):
        path = self.path
        # Simulate health check
        if path == '/health':
            self._json({'status': 'ok', 'backend': LABEL}, 200)
            return
        # Simulate slow endpoint for latency testing
        if path.startswith('/slow'):
            time.sleep(0.5)
        # Simulate error endpoint
        if path.startswith('/error'):
            self._json({'error': 'intentional error'}, 500)
            return
        # Simulate 404
        if path.startswith('/notfound'):
            self._json({'error': 'not found'}, 404)
            return
        # Echo request info
        resp = {
            'backend': LABEL,
            'port':    PORT,
            'method':  self.command,
            'path':    path,
            'headers': dict(self.headers),
            'body':    body[:500] if body else None,
            'time_ms': round(time.time() * 1000),
        }
        self._json(resp, 200)

    def _json(self, obj, status):
        payload = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('X-Backend', LABEL)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(payload)

HTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
PYEOF

echo ""
echo "Starting Phalanx test backends…"
echo ""

start_python_backend 18081 "backend-1"
start_python_backend 18082 "backend-2"

# ─── WebSocket echo backend ──────────────────────────────────────────────────

cat > /tmp/phalanx_ws_backend.py << 'WSEOF'
#!/usr/bin/env python3
"""
Minimal WebSocket echo server using the websockets library.
Install: pip install websockets
"""
import sys, asyncio

try:
    import websockets

    async def echo(ws, path='/'):
        print(f"WS client connected: {ws.remote_address}")
        try:
            async for msg in ws:
                await ws.send(f"echo: {msg}")
        except websockets.exceptions.ConnectionClosed:
            pass

    async def main():
        print("WebSocket echo server on ws://127.0.0.1:18083")
        async with websockets.serve(echo, "127.0.0.1", 18083):
            await asyncio.Future()

    asyncio.run(main())

except ImportError:
    # Fallback: raw TCP websocket framing (no dependency)
    import socket, hashlib, base64, struct, threading

    def handshake(conn):
        data = conn.recv(4096).decode()
        key = ''
        for line in data.split('\r\n'):
            if 'Sec-WebSocket-Key' in line:
                key = line.split(': ')[1].strip()
        magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
        resp = (
            'HTTP/1.1 101 Switching Protocols\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {accept}\r\n\r\n'
        )
        conn.sendall(resp.encode())

    def recv_frame(conn):
        header = conn.recv(2)
        if len(header) < 2: return None
        fin = (header[0] & 0x80) != 0
        opcode = header[0] & 0x0f
        masked = (header[1] & 0x80) != 0
        length = header[1] & 0x7f
        if length == 126:
            length = struct.unpack('>H', conn.recv(2))[0]
        elif length == 127:
            length = struct.unpack('>Q', conn.recv(8))[0]
        mask = conn.recv(4) if masked else b'\x00\x00\x00\x00'
        data = bytearray(conn.recv(length))
        if masked:
            data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
        return opcode, data.decode('utf-8', errors='replace')

    def send_frame(conn, msg):
        encoded = msg.encode('utf-8')
        header = bytes([0x81, len(encoded)])  # fin + text, no mask, length
        conn.sendall(header + encoded)

    def handle(conn):
        try:
            handshake(conn)
            while True:
                frame = recv_frame(conn)
                if frame is None: break
                opcode, msg = frame
                if opcode == 8: break  # close
                send_frame(conn, f'echo: {msg}')
        except Exception:
            pass
        finally:
            conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 18083))
    srv.listen(50)
    print("WebSocket echo server on ws://127.0.0.1:18083 (raw)")
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
WSEOF

python3 /tmp/phalanx_ws_backend.py &
echo $! >> "$PIDS_FILE"
echo "  WebSocket echo server started on port 18083 (PID $!)"

# ─── Verify all backends are up ───────────────────────────────────────────────

echo ""
echo "Waiting for backends to start…"
sleep 1

for port in 18081 18082; do
  if curl -sf "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
    echo "  ✓ Backend on port ${port} is healthy"
  else
    echo "  ✗ Backend on port ${port} did not start — check /tmp/phalanx_backend.py"
  fi
done

echo ""
echo "Backends running. PIDs stored in ${PIDS_FILE}"
echo "Stop with: ./scripts/start_test_backends.sh --stop"
echo ""
echo "Test URLs:"
echo "  http://127.0.0.1:18081/health    — primary backend"
echo "  http://127.0.0.1:18082/health    — secondary backend"
echo "  http://127.0.0.1:18081/slow      — slow endpoint (500ms)"
echo "  http://127.0.0.1:18081/error     — always 500"
echo "  ws://127.0.0.1:18083             — WebSocket echo"
echo ""
