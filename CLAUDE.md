# Phalanx

## Graph-First Development
- **Mandatory:** Before starting any task, query `graphify-out/graph.json` to find the relevant community.
- **Token Efficiency:** Never use `grep` or `ls` on the full repo. Use the graph's "God Nodes" and "Community Clusters" to isolate the work.
- **Validation:** If a task touches the WAF, routing, or auth pipeline, check the graph's "Surprising Connections" to confirm no side effects in HTTP/3 / ML fraud / cache layers.

## Auto-Query Rule (STRICT — follow every time)

Before writing, editing, or planning ANY code change, you MUST automatically run the appropriate `/graphify` command FIRST. Do NOT wait for the user to ask. Do NOT skip this step.

### When the user says "build X" / "add X" / "fix X" / "implement X":
1. Run `/graphify query "what is connected to X"` to find the relevant community, files, and dependencies
2. Run `/graphify query "what depends on X"` to check for side effects
3. If the task touches two concepts, also run `/graphify path "A" "B"` to find the shortest path (e.g. `path "handle_h3_request" "WafEngine"`)
4. THEN and ONLY THEN start writing code

### When the user says "how does X work" / "explain X":
1. Run `/graphify explain "X"` or `/graphify query "how does X work"`
2. Answer using graph output + source file references

### When the user says "what's missing" / "what's broken" / "plan next steps":
1. Run `/graphify query "which modules are isolated or disconnected"`
2. Run `/graphify query "what HTTP/3 pipeline steps have parity gaps"`
3. Cross-check with `plan_v2.md` for tracked items
4. Use findings to build the response

### After finishing any code change:
1. Run `/graphify . --update` to keep the graph current
2. This step is non-negotiable — every commit changes the graph and stale graphs produce wrong answers in the next task.

### Quick reference
See `README.md` for the feature catalog, `plan_v2.md` for tracked gaps, and `graphify-out/GRAPH_REPORT.md` for the most recent God Nodes / Community map.

## Tech Stack
- **Core:** Rust 2024, Tokio async runtime, Hyper HTTP/1+2, Quinn + h3 (HTTP/3 / QUIC)
- **TLS:** rustls, rustls-acme (Let's Encrypt)
- **Concurrency:** arc-swap, dashmap, parking_lot, atomics (lock-free hot path)
- **Cache:** Moka L1 (in-memory LFU) + optional disk L2; FxHash for cache keys
- **Rate Limiting:** governor (token bucket) + Redis (cluster sliding-window)
- **WAF:** regex (OWASP signatures), ML fraud via tract-onnx, declarative policy engine
- **Auth:** Basic / JWT (jsonwebtoken) / OAuth introspection / JWKS / OIDC / auth_request
- **Scripting:** Rhai (sandboxed), Proxy-Wasm via wasmtime
- **Cluster:** etcd-client, redis, SWIM gossip
- **Admin:** Actix-web (REST API + dashboard)
- **Observability:** Prometheus, OpenTelemetry OTLP, structured access logs (with W3C trace context)
- **Build:** `cargo build` · **Test:** `cargo test` (955+ tests) · **Run:** `cargo run -- phalanx.conf`
