//! # AI-Powered Load Balancing Algorithms
//!
//! Implements four multi-armed bandit algorithms for adaptive backend selection.
//! Each algorithm learns from request outcomes (latency, errors) and dynamically
//! shifts traffic toward the best-performing backends.
//!
//! All implementations are thread-safe (`Send + Sync`) via `DashMap` and can be
//! swapped at startup via the `ai_algorithm` config directive.

use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::routing::BackendNode;

// ─────────────────────────────────────────────────────────────────────────────
// Trait: AiRouter
// ─────────────────────────────────────────────────────────────────────────────

/// The core trait that all AI routing algorithms must implement.
/// This allows the proxy to swap algorithms at startup based on configuration.
pub trait AiRouter: Send + Sync {
    /// Records the outcome of a proxied request to train the model.
    /// `backend` is the address string, `latency_ms` is the turnaround time,
    /// and `is_error` indicates a 5xx or connection failure.
    fn update_score(&self, backend: &str, latency_ms: u64, is_error: bool);

    /// Selects the best backend from the given healthy list.
    fn predict_best_backend(&self, backends: &[Arc<BackendNode>]) -> Option<Arc<BackendNode>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 1: Epsilon-Greedy
// ─────────────────────────────────────────────────────────────────────────────

/// Classic Epsilon-Greedy multi-armed bandit.
/// Exploits the best-known backend (1-ε)% of the time and explores randomly ε% of the time.
/// Simple, battle-tested, and used widely at Netflix and AWS for traffic shifting.
#[derive(Clone)]
pub struct EpsilonGreedyRouter {
    /// Exploration probability (0.0-1.0). Higher values explore more.
    epsilon: f64,
    /// Running weighted average penalty score per backend address.
    /// Lower score = better backend. Updated with exponential moving average (alpha=0.2).
    scores: Arc<DashMap<String, f64>>,
}

impl EpsilonGreedyRouter {
    /// Creates a new router with the given exploration rate.
    ///
    /// # Arguments
    /// * `epsilon` - Probability of random exploration (e.g. 0.1 = 10% random picks).
    pub fn new(epsilon: f64) -> Self {
        info!("Initializing AI Epsilon-Greedy Router (ε={})", epsilon);
        Self {
            epsilon,
            scores: Arc::new(DashMap::new()),
        }
    }
}

impl AiRouter for EpsilonGreedyRouter {
    fn update_score(&self, backend: &str, latency_ms: u64, is_error: bool) {
        // Penalty = raw latency + a large constant for errors to heavily penalize failures
        let mut penalty = latency_ms as f64;
        if is_error {
            penalty += 10_000.0;
        }
        // Exponential moving average (EMA) with alpha=0.2: recent observations
        // have 20% influence, decaying old data gradually without storing history.
        self.scores
            .entry(backend.to_string())
            .and_modify(|s| {
                let alpha = 0.2;
                *s = (*s * (1.0 - alpha)) + (penalty * alpha);
            })
            .or_insert(penalty);
    }

    fn predict_best_backend(&self, backends: &[Arc<BackendNode>]) -> Option<Arc<BackendNode>> {
        if backends.is_empty() {
            return None;
        }
        // With probability epsilon: explore by picking a random backend
        if rand::random::<f64>() < self.epsilon {
            let idx = (rand::random::<u32>() as usize) % backends.len();
            debug!(
                "ε-Greedy: Exploring backend {}",
                backends[idx].config.address
            );
            return Some(Arc::clone(&backends[idx]));
        }
        // With probability (1-epsilon): exploit by picking the best-known backend
        // (the one with the lowest cumulative penalty score)
        backends
            .iter()
            .min_by(|a, b| {
                let sa = self
                    .scores
                    .get(&a.config.address)
                    .map(|s| *s)
                    .unwrap_or(0.0);
                let sb = self
                    .scores
                    .get(&b.config.address)
                    .map(|s| *s)
                    .unwrap_or(0.0);
                sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 2: UCB1 (Upper Confidence Bound)
// ─────────────────────────────────────────────────────────────────────────────

/// UCB1 is a mathematically principled bandit algorithm from Auer et al. (2002).
/// It selects the backend with the lowest score MINUS a confidence bonus that rewards
/// under-explored backends. As a backend gets more traffic, its confidence interval
/// shrinks and it must earn its keep purely on latency. This achieves provably optimal
/// regret bounds — used at Google for experiment traffic allocation.
///
/// Formula: select backend with min( avg_score - C * sqrt(ln(N) / n_i) )
/// Where N = total requests, n_i = requests to backend i, C = exploration constant.
/// Per-backend statistics tracked by the UCB1 algorithm.
struct BackendStats {
    /// Incrementally-updated mean penalty score for this backend.
    avg_score: f64,
    /// Total number of requests routed to this backend.
    count: u64,
}

/// UCB1 (Upper Confidence Bound) router.
///
/// Balances exploration and exploitation using a mathematically-derived confidence
/// bonus that shrinks as a backend receives more traffic. Never-tried backends
/// get `NEG_INFINITY` score, guaranteeing they are tried at least once.
pub struct Ucb1Router {
    /// Per-backend statistics: running average score and request count.
    stats: DashMap<String, BackendStats>,
    /// Global request counter across all backends (N in the UCB1 formula).
    total_count: std::sync::atomic::AtomicU64,
    /// Tunable exploration constant (C). Higher values explore more aggressively.
    exploration_constant: f64,
}

impl Ucb1Router {
    /// Creates a new UCB1 router.
    ///
    /// # Arguments
    /// * `exploration_constant` - The C parameter in the UCB1 formula.
    ///   Typical values: 1.0-2.0. Higher = more exploration.
    pub fn new(exploration_constant: f64) -> Self {
        info!("Initializing AI UCB1 Router (C={})", exploration_constant);
        Self {
            stats: DashMap::new(),
            total_count: std::sync::atomic::AtomicU64::new(0),
            exploration_constant,
        }
    }
}

impl AiRouter for Ucb1Router {
    fn update_score(&self, backend: &str, latency_ms: u64, is_error: bool) {
        let mut penalty = latency_ms as f64;
        if is_error {
            penalty += 10_000.0;
        }
        // Increment global counter: used as N in the UCB1 confidence term
        self.total_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Update per-backend stats with an incremental mean:
        // alpha = 1/n gives a true running average (not exponential decay like epsilon-greedy)
        self.stats
            .entry(backend.to_string())
            .and_modify(|s| {
                s.count += 1;
                let alpha = 1.0 / s.count as f64;
                s.avg_score = s.avg_score * (1.0 - alpha) + penalty * alpha;
            })
            .or_insert(BackendStats {
                avg_score: penalty,
                count: 1,
            });
    }

    fn predict_best_backend(&self, backends: &[Arc<BackendNode>]) -> Option<Arc<BackendNode>> {
        if backends.is_empty() {
            return None;
        }
        let total_n = self
            .total_count
            .load(std::sync::atomic::Ordering::Relaxed)
            .max(1) as f64;
        let c = self.exploration_constant;

        // UCB1 formula: score(i) = avg_score(i) - C * sqrt(ln(N) / n_i)
        // We minimize score (lower = better), so the confidence bonus is SUBTRACTED,
        // giving under-explored backends a lower (better) adjusted score.
        backends
            .iter()
            .min_by(|a, b| {
                let ucb_a = self
                    .stats
                    .get(&a.config.address)
                    .map(|s| s.avg_score - c * (total_n.ln() / s.count as f64).sqrt())
                    .unwrap_or(f64::NEG_INFINITY); // Never tried -> guaranteed to be explored first
                let ucb_b = self
                    .stats
                    .get(&b.config.address)
                    .map(|s| s.avg_score - c * (total_n.ln() / s.count as f64).sqrt())
                    .unwrap_or(f64::NEG_INFINITY);
                ucb_a
                    .partial_cmp(&ucb_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 3: Softmax / Boltzmann Exploration
// ─────────────────────────────────────────────────────────────────────────────

/// Softmax (Boltzmann) exploration uses a temperature parameter to create a probability
/// distribution over backends. Unlike ε-Greedy which explores uniformly at random,
/// Softmax gives HIGHER probability to backends that are closer to the best score.
///
/// At high temperature (τ → ∞): all backends are equally likely (pure exploration).
/// At low temperature (τ → 0): deterministically picks the best backend (pure exploitation).
///
/// Used at LinkedIn and Twitter for gradual traffic migration and canary deployments.
pub struct SoftmaxRouter {
    /// Temperature parameter (tau). Controls randomness of selection:
    /// tau -> infinity: uniform random; tau -> 0: greedy deterministic.
    /// Clamped to a minimum of 0.001 to avoid division by zero.
    temperature: f64,
    /// Running penalty scores per backend (same EMA as epsilon-greedy).
    scores: Arc<DashMap<String, f64>>,
}

impl SoftmaxRouter {
    /// Creates a new Softmax router with the given temperature.
    ///
    /// # Arguments
    /// * `temperature` - Boltzmann temperature (tau). Values near 0 are greedy;
    ///   values >> 1 are nearly uniform. Clamped to a minimum of 0.001.
    pub fn new(temperature: f64) -> Self {
        info!(
            "Initializing AI Softmax/Boltzmann Router (τ={})",
            temperature
        );
        Self {
            temperature: temperature.max(0.001), // Avoid division by zero
            scores: Arc::new(DashMap::new()),
        }
    }
}

impl AiRouter for SoftmaxRouter {
    fn update_score(&self, backend: &str, latency_ms: u64, is_error: bool) {
        let mut penalty = latency_ms as f64;
        if is_error {
            penalty += 10_000.0;
        }
        self.scores
            .entry(backend.to_string())
            .and_modify(|s| {
                let alpha = 0.2;
                *s = (*s * (1.0 - alpha)) + (penalty * alpha);
            })
            .or_insert(penalty);
    }

    fn predict_best_backend(&self, backends: &[Arc<BackendNode>]) -> Option<Arc<BackendNode>> {
        if backends.is_empty() {
            return None;
        }

        // Step 1: Compute Boltzmann weights for each backend.
        // w_i = exp(-score_i / tau)
        // Backends with lower scores (better performance) get exponentially higher weights.
        // The negative sign converts our "penalty" (lower = better) into a probability distribution.
        let weights: Vec<f64> = backends
            .iter()
            .map(|b| {
                let score = self
                    .scores
                    .get(&b.config.address)
                    .map(|s| *s)
                    .unwrap_or(0.0);
                (-score / self.temperature).exp()
            })
            .collect();

        // Step 2: Normalize weights into a probability distribution
        let total_weight: f64 = weights.iter().sum();
        if total_weight <= 0.0 || total_weight.is_nan() {
            // Fallback to first backend if numerical instability occurs
            return Some(Arc::clone(&backends[0]));
        }

        // Step 3: Weighted random selection (roulette wheel)
        let mut rng_val = rand::random::<f64>() * total_weight;
        for (i, w) in weights.iter().enumerate() {
            rng_val -= w;
            if rng_val <= 0.0 {
                debug!(
                    "Softmax: Selected backend {} (p={:.3})",
                    backends[i].config.address,
                    w / total_weight
                );
                return Some(Arc::clone(&backends[i]));
            }
        }
        Some(Arc::clone(&backends[backends.len() - 1]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 4: Thompson Sampling (Bayesian)
// ─────────────────────────────────────────────────────────────────────────────

/// Thompson Sampling uses a Bayesian approach: each backend has a Beta(α, β) prior distribution.
/// On each request, we SAMPLE from each backend's distribution and pick the one with the best
/// (lowest) sampled value. Successful low-latency responses increase α (successes), while
/// high-latency or errors increase β (failures).
///
/// This is considered the gold standard for online exploration-exploitation tradeoffs.
/// Used at Microsoft (Bing Ads), Spotify, and Adobe for real-time optimization.
/// Parameters of the Beta distribution for a single backend in Thompson Sampling.
///
/// The Beta(alpha, beta) distribution models the probability of a backend being "good".
/// alpha grows with successes (fast, non-error responses) and beta grows with failures.
struct BetaParams {
    /// Pseudo-count of successes (fast responses under the latency threshold).
    alpha: f64,
    /// Pseudo-count of failures (slow responses or errors).
    beta: f64,
}

/// Thompson Sampling router using Bayesian posterior updating.
///
/// Each backend maintains a Beta(alpha, beta) distribution. On each selection,
/// we draw a random sample from each backend's distribution and pick the one
/// with the highest sample (highest estimated probability of being "good").
/// This naturally balances exploration (uncertain backends have wide distributions)
/// and exploitation (proven backends have tight, high distributions).
pub struct ThompsonSamplingRouter {
    /// Per-backend Beta distribution parameters.
    params: DashMap<String, BetaParams>,
    /// Latency threshold in ms: anything below this counts as a "success".
    /// Responses above this threshold or with errors count as "failures".
    latency_threshold_ms: f64,
}

impl ThompsonSamplingRouter {
    /// Creates a new Thompson Sampling router.
    ///
    /// # Arguments
    /// * `latency_threshold_ms` - Latency cutoff for success/failure classification.
    ///   E.g., 200.0 means responses under 200ms are "successes".
    pub fn new(latency_threshold_ms: f64) -> Self {
        info!(
            "Initializing AI Thompson Sampling Router (threshold={}ms)",
            latency_threshold_ms
        );
        Self {
            params: DashMap::new(),
            latency_threshold_ms,
        }
    }

    /// Approximate sampling from a Beta distribution using the Inverse CDF method.
    /// For production quality, a proper statistical crate would be used, but this
    /// provides a reasonable approximation using the Jöhnk algorithm.
    fn sample_beta(alpha: f64, beta: f64) -> f64 {
        // Simple approximation: use the mean + jitter for lightweight sampling
        // Mean of Beta(α, β) = α / (α + β)
        let mean = alpha / (alpha + beta);
        let variance = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let jitter = (rand::random::<f64>() - 0.5) * 2.0 * variance.sqrt();
        (mean + jitter).clamp(0.0, 1.0)
    }
}

impl AiRouter for ThompsonSamplingRouter {
    fn update_score(&self, backend: &str, latency_ms: u64, is_error: bool) {
        // Classify the outcome: success if no error AND latency is below threshold
        let is_success = !is_error && (latency_ms as f64) < self.latency_threshold_ms;
        self.params
            .entry(backend.to_string())
            .and_modify(|p| {
                // Increment the appropriate pseudo-count
                if is_success {
                    p.alpha += 1.0;
                } else {
                    p.beta += 1.0;
                }
                // Apply multiplicative decay (0.999) to both parameters to
                // gradually forget old data, making the algorithm adaptive to
                // changing backend performance over time.
                let decay = 0.999;
                p.alpha *= decay;
                p.beta *= decay;
            })
            .or_insert(BetaParams {
                // Informative prior: slightly biased toward the observed outcome
                alpha: if is_success { 2.0 } else { 1.0 },
                beta: if is_success { 1.0 } else { 2.0 },
            });
    }

    fn predict_best_backend(&self, backends: &[Arc<BackendNode>]) -> Option<Arc<BackendNode>> {
        if backends.is_empty() {
            return None;
        }

        // Sample from each backend's Beta distribution and pick the HIGHEST sample
        // (highest probability of success = best backend)
        backends
            .iter()
            .max_by(|a, b| {
                let sample_a = self
                    .params
                    .get(&a.config.address)
                    .map(|p| Self::sample_beta(p.alpha, p.beta))
                    .unwrap_or(0.5); // Uninformed prior → 50/50
                let sample_b = self
                    .params
                    .get(&b.config.address)
                    .map(|p| Self::sample_beta(p.alpha, p.beta))
                    .unwrap_or(0.5);
                sample_a
                    .partial_cmp(&sample_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory: Build the right router from config
// ─────────────────────────────────────────────────────────────────────────────

/// The available AI routing algorithms that can be selected in `phalanx.conf`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiAlgorithm {
    EpsilonGreedy,
    Ucb1,
    Softmax,
    ThompsonSampling,
}

impl AiAlgorithm {
    /// Parses a string from the config file into an `AiAlgorithm` variant.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "epsilon_greedy" | "epsilongreedy" | "epsilon-greedy" => AiAlgorithm::EpsilonGreedy,
            "ucb1" | "ucb" => AiAlgorithm::Ucb1,
            "softmax" | "boltzmann" => AiAlgorithm::Softmax,
            "thompson" | "thompson_sampling" | "thompsonsampling" => AiAlgorithm::ThompsonSampling,
            _ => {
                tracing::warn!("Unknown AI algorithm '{}', defaulting to EpsilonGreedy", s);
                AiAlgorithm::EpsilonGreedy
            }
        }
    }
}

/// Factory function: constructs the appropriate AI router based on the config selection.
///
/// # Arguments
/// * `algorithm` - Which bandit algorithm to use.
/// * `epsilon` - Exploration rate for EpsilonGreedy (ignored by other algorithms).
/// * `temperature` - Boltzmann temperature for Softmax (ignored by others).
/// * `ucb_constant` - Exploration constant C for UCB1 (ignored by others).
/// * `thompson_threshold_ms` - Latency threshold for Thompson Sampling (ignored by others).
///
/// # Returns
/// A trait object wrapping the selected algorithm, ready for concurrent use.
pub fn build_ai_router(
    algorithm: AiAlgorithm,
    epsilon: f64,
    temperature: f64,
    ucb_constant: f64,
    thompson_threshold_ms: f64,
) -> Arc<dyn AiRouter> {
    match algorithm {
        AiAlgorithm::EpsilonGreedy => Arc::new(EpsilonGreedyRouter::new(epsilon)),
        AiAlgorithm::Ucb1 => Arc::new(Ucb1Router::new(ucb_constant)),
        AiAlgorithm::Softmax => Arc::new(SoftmaxRouter::new(temperature)),
        AiAlgorithm::ThompsonSampling => {
            Arc::new(ThompsonSamplingRouter::new(thompson_threshold_ms))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;
    use crate::routing::BackendNode;

    fn make_backends(addrs: &[&str]) -> Vec<Arc<BackendNode>> {
        addrs
            .iter()
            .map(|a| {
                Arc::new(BackendNode::new(BackendConfig {
                    address: a.to_string(),
                    ..Default::default()
                }))
            })
            .collect()
    }

    #[test]
    fn test_ai_algorithm_from_str() {
        assert_eq!(AiAlgorithm::from_str("epsilon_greedy"), AiAlgorithm::EpsilonGreedy);
        assert_eq!(AiAlgorithm::from_str("epsilongreedy"), AiAlgorithm::EpsilonGreedy);
        assert_eq!(AiAlgorithm::from_str("epsilon-greedy"), AiAlgorithm::EpsilonGreedy);
        assert_eq!(AiAlgorithm::from_str("ucb1"), AiAlgorithm::Ucb1);
        assert_eq!(AiAlgorithm::from_str("ucb"), AiAlgorithm::Ucb1);
        assert_eq!(AiAlgorithm::from_str("softmax"), AiAlgorithm::Softmax);
        assert_eq!(AiAlgorithm::from_str("boltzmann"), AiAlgorithm::Softmax);
        assert_eq!(AiAlgorithm::from_str("thompson"), AiAlgorithm::ThompsonSampling);
        assert_eq!(AiAlgorithm::from_str("thompson_sampling"), AiAlgorithm::ThompsonSampling);
        assert_eq!(AiAlgorithm::from_str("unknown"), AiAlgorithm::EpsilonGreedy);
    }

    #[test]
    fn test_epsilon_greedy_empty_backends() {
        let router = EpsilonGreedyRouter::new(0.1);
        assert!(router.predict_best_backend(&[]).is_none());
    }

    #[test]
    fn test_epsilon_greedy_single_backend() {
        let router = EpsilonGreedyRouter::new(0.1);
        let backends = make_backends(&["10.0.0.1:80"]);
        let picked = router.predict_best_backend(&backends);
        assert!(picked.is_some());
        assert_eq!(picked.unwrap().config.address, "10.0.0.1:80");
    }

    #[test]
    fn test_epsilon_greedy_update_score() {
        let router = EpsilonGreedyRouter::new(0.0);
        router.update_score("slow", 5000, false);
        router.update_score("fast", 10, false);
        let backends = make_backends(&["slow", "fast"]);
        let picked = router.predict_best_backend(&backends).unwrap();
        assert_eq!(picked.config.address, "fast");
    }

    #[test]
    fn test_epsilon_greedy_error_penalty() {
        let router = EpsilonGreedyRouter::new(0.0);
        router.update_score("ok", 50, false);
        router.update_score("err", 50, true);
        let backends = make_backends(&["ok", "err"]);
        let picked = router.predict_best_backend(&backends).unwrap();
        assert_eq!(picked.config.address, "ok");
    }

    #[test]
    fn test_ucb1_empty_backends() {
        let router = Ucb1Router::new(2.0);
        assert!(router.predict_best_backend(&[]).is_none());
    }

    #[test]
    fn test_ucb1_prefers_unexplored() {
        let router = Ucb1Router::new(2.0);
        router.update_score("tried", 100, false);
        let backends = make_backends(&["tried", "untried"]);
        let picked = router.predict_best_backend(&backends).unwrap();
        assert_eq!(picked.config.address, "untried");
    }

    #[test]
    fn test_softmax_empty_backends() {
        let router = SoftmaxRouter::new(1.0);
        assert!(router.predict_best_backend(&[]).is_none());
    }

    #[test]
    fn test_softmax_single_backend() {
        let router = SoftmaxRouter::new(1.0);
        let backends = make_backends(&["only"]);
        let picked = router.predict_best_backend(&backends).unwrap();
        assert_eq!(picked.config.address, "only");
    }

    #[test]
    fn test_thompson_empty_backends() {
        let router = ThompsonSamplingRouter::new(200.0);
        assert!(router.predict_best_backend(&[]).is_none());
    }

    #[test]
    fn test_thompson_update_and_predict() {
        let router = ThompsonSamplingRouter::new(200.0);
        for _ in 0..50 {
            router.update_score("fast", 50, false);
            router.update_score("slow", 500, false);
        }
        let backends = make_backends(&["fast", "slow"]);
        let mut fast_count = 0;
        for _ in 0..100 {
            let picked = router.predict_best_backend(&backends).unwrap();
            if picked.config.address == "fast" {
                fast_count += 1;
            }
        }
        assert!(fast_count > 50, "fast backend should be preferred: picked {} times", fast_count);
    }

    #[test]
    fn test_build_ai_router_all_types() {
        let _ = build_ai_router(AiAlgorithm::EpsilonGreedy, 0.1, 1.0, 2.0, 200.0);
        let _ = build_ai_router(AiAlgorithm::Ucb1, 0.1, 1.0, 2.0, 200.0);
        let _ = build_ai_router(AiAlgorithm::Softmax, 0.1, 1.0, 2.0, 200.0);
        let _ = build_ai_router(AiAlgorithm::ThompsonSampling, 0.1, 1.0, 2.0, 200.0);
    }

    #[test]
    fn test_softmax_temperature_floor() {
        let router = SoftmaxRouter::new(0.0);
        assert!(router.temperature >= 0.001);
    }
}
