#!/bin/bash
cargo run --release &
PID=$!
sleep 2

echo "Testing GET /static/index.html"
curl -s -i http://localhost:8080/static/index.html | head -n 10

echo "Testing GET /static/style.css"
curl -s -i http://localhost:8080/static/style.css | head -n 10

echo "Testing default fallback"
curl -s -i http://localhost:8080/ | head -n 10

kill $PID
