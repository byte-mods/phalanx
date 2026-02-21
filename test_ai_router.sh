#!/bin/bash
set -e

# Build the proxy
cargo build

echo "Starting 3 simulated backends with delays (10ms, 100ms, 500ms)..."
pkill -f "http.server" || true

# Backend 1: Fast (10ms)
python3 -c "
import http.server
import time
class DelayedHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.010)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Backend 8081 (Fast)')
http.server.HTTPServer(('127.0.0.1', 8081), DelayedHandler).serve_forever()
" &
PID1=$!

# Backend 2: Medium (100ms)
python3 -c "
import http.server
import time
class DelayedHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.100)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Backend 8082 (Medium)')
http.server.HTTPServer(('127.0.0.1', 8082), DelayedHandler).serve_forever()
" &
PID2=$!

# Backend 3: Slow (500ms)
python3 -c "
import http.server
import time
class DelayedHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.500)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Backend 8083 (Slow)')
http.server.HTTPServer(('127.0.0.1', 8083), DelayedHandler).serve_forever()
" &
PID3=$!

# Wait for backends to bind
sleep 2

# Create a test Phalanx config
cat << 'CONF' > phalanx_test.conf
worker_threads 1;

http {
    upstream default {
        algorithm aipredictive;
        server 127.0.0.1:8081 weight=1 max_fails=3 fail_timeout=10s;
        server 127.0.0.1:8082 weight=1 max_fails=3 fail_timeout=10s;
        server 127.0.0.1:8083 weight=1 max_fails=3 fail_timeout=10s;
    }

    server {
        listen 127.0.0.1 8080;
        routes {
            / => default;
        }
    }
}
CONF

echo "Starting Phalanx Proxy..."
export RUST_LOG=info
./target/debug/ai_load_balancer -c phalanx_test.conf &
PROXY_PID=$!

sleep 2

echo "Running 100 requests through the load balancer..."
for i in {1..100}; do
    curl -s http://127.0.0.1:8080/ >> results.txt
    echo "" >> results.txt
done

echo ""
echo "Traffic Distribution:"
echo "Fast Backend (10ms): \$(grep -c 'Backend 8081' results.txt) requests"
echo "Medium Backend (100ms): \$(grep -c 'Backend 8082' results.txt) requests"
echo "Slow Backend (500ms): \$(grep -c 'Backend 8083' results.txt) requests"

# Cleanup
rm results.txt phalanx_test.conf
kill $PID1 $PID2 $PID3 $PROXY_PID
