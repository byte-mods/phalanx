#!/bin/bash
cargo run --release &
PID=$!
sleep 2

echo "Testing GET /static/index.html on 18080"
curl -s -i http://localhost:18080/static/index.html | head -n 10

echo "Testing GET /static/style.css on 18080"
curl -s -i http://localhost:18080/static/style.css | head -n 10

kill $PID
