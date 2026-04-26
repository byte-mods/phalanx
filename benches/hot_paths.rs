//! Microbenchmarks for hot-path code paths shipped during the
//! 9-batch bare-metal pass. Each bench is documented with the
//! plan_v2.md item it backs, so future regressions can be tied to
//! the original change.
//!
//! Run with:
//!
//!   cargo bench --bench hot_paths
//!
//! Save baselines with:
//!
//!   cargo bench --bench hot_paths -- --save-baseline pre-change
//!   # ...refactor...
//!   cargo bench --bench hot_paths -- --baseline pre-change

use ai_load_balancer::config::{
    BackendConfig, LoadBalancingAlgorithm, UpstreamPoolConfig,
};
use ai_load_balancer::routing::UpstreamPool;
use ai_load_balancer::scripting::{HookContext, HookEngine, HookPhase};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::collections::HashMap;
use std::sync::Arc;

// ── P1: get_next_backend allocation ────────────────────────────────────────

fn make_pool(n: usize, algo: LoadBalancingAlgorithm) -> UpstreamPool {
    let backends: Vec<BackendConfig> = (0..n)
        .map(|i| BackendConfig {
            address: format!("10.0.0.{}:8080", i + 1),
            ..Default::default()
        })
        .collect();
    let cfg = UpstreamPoolConfig {
        algorithm: algo,
        backends,
        keepalive: 0,
        srv_discover: None,
        health_check_interval_secs: 5,
        health_check_timeout_secs: 3,
    };
    UpstreamPool::new(&cfg)
}

fn bench_get_next_backend_round_robin(c: &mut Criterion) {
    let pool = make_pool(4, LoadBalancingAlgorithm::RoundRobin);
    c.bench_function("p1_get_next_backend_rr_4_backends", |b| {
        b.iter(|| {
            let _ = black_box(pool.get_next_backend(None, None));
        });
    });
}

fn bench_get_next_backend_round_robin_16(c: &mut Criterion) {
    // SmallVec inline capacity is 8; this test exceeds it so we measure
    // the spill-to-heap path. Should still be ~1 alloc per call vs 3
    // before P1.
    let pool = make_pool(16, LoadBalancingAlgorithm::RoundRobin);
    c.bench_function("p1_get_next_backend_rr_16_backends_spill", |b| {
        b.iter(|| {
            let _ = black_box(pool.get_next_backend(None, None));
        });
    });
}

// ── P4: Random LB no SystemTime syscall ────────────────────────────────────

fn bench_get_next_backend_random(c: &mut Criterion) {
    let pool = make_pool(4, LoadBalancingAlgorithm::Random);
    c.bench_function("p4_random_lb_pick", |b| {
        b.iter(|| {
            let _ = black_box(pool.get_next_backend(None, None));
        });
    });
}

// ── C5: ConsistentHash ring caching ────────────────────────────────────────

fn bench_get_next_backend_consistent_hash_warm_cache(c: &mut Criterion) {
    let pool = make_pool(4, LoadBalancingAlgorithm::ConsistentHash);
    let ip: std::net::IpAddr = "10.10.10.10".parse().unwrap();
    // Prime the ring once so the bench measures the cached-hit path.
    let _ = pool.get_next_backend(Some(&ip), None);
    c.bench_function("c5_consistent_hash_warm_cache", |b| {
        b.iter(|| {
            let _ = black_box(pool.get_next_backend(Some(&ip), None));
        });
    });
}

// ── P6: HookEngine.has_hooks lock-free atomic ─────────────────────────────

fn bench_has_hooks_no_hooks_registered(c: &mut Criterion) {
    let engine = HookEngine::new();
    c.bench_function("p6_has_hooks_empty", |b| {
        b.iter(|| {
            // 4 phases ⇒ 4 atomic loads; previously 4 RwLock reads.
            black_box(engine.has_hooks(HookPhase::PreRoute));
            black_box(engine.has_hooks(HookPhase::PreUpstream));
            black_box(engine.has_hooks(HookPhase::PostUpstream));
            black_box(engine.has_hooks(HookPhase::Log));
        });
    });
}

// ── P2: HookContext Arc<str> sharing ──────────────────────────────────────

fn bench_hookcontext_arc_clone_vs_string_clone(c: &mut Criterion) {
    // Simulate per-phase HookContext construction. With Arc<str> this is
    // 4 atomic increments; with String it would be 4 heap allocations
    // per request when hooks fire.
    let ip_arc: Arc<str> = Arc::from("192.168.1.42");
    let method_arc: Arc<str> = Arc::from("GET");
    let path_arc: Arc<str> = Arc::from("/api/v1/users/12345");

    c.bench_function("p2_hookcontext_arc_clone_per_phase", |b| {
        b.iter(|| {
            // 4 phases × per-request HookContext construction
            for _ in 0..4 {
                let ctx = HookContext {
                    client_ip: Arc::clone(&ip_arc),
                    method: Arc::clone(&method_arc),
                    path: Arc::clone(&path_arc),
                    query: None,
                    headers: HashMap::new(),
                    status: None,
                    response_headers: HashMap::new(),
                };
                black_box(ctx);
            }
        });
    });
}

// ── P7: cache hex_prefix FxHasher vs SipHash ──────────────────────────────
// `hex_prefix` is private; we approximate by hashing the same key shape
// that AdvancedCache uses via the public API to confirm the FxHasher path.

fn bench_cache_key_hash(c: &mut Criterion) {
    use std::hash::{Hash, Hasher};
    let key = "GET:example.com:/api/v1/users/12345?page=2:V:accept-language";
    c.bench_function("p7_cache_key_fxhash_vs_siphash", |bn| {
        bn.iter(|| {
            let mut h = rustc_hash::FxHasher::default();
            black_box(key).hash(&mut h);
            black_box(h.finish());
        });
    });
    c.bench_function("p7_cache_key_siphash_baseline", |bn| {
        bn.iter(|| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            black_box(key).hash(&mut h);
            black_box(h.finish());
        });
    });
}

criterion_group!(
    benches,
    bench_get_next_backend_round_robin,
    bench_get_next_backend_round_robin_16,
    bench_get_next_backend_random,
    bench_get_next_backend_consistent_hash_warm_cache,
    bench_has_hooks_no_hooks_registered,
    bench_hookcontext_arc_clone_vs_string_clone,
    bench_cache_key_hash,
);
criterion_main!(benches);
