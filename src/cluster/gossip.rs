//! SWIM-style gossip protocol for peer-to-peer cluster state synchronization.
//!
//! Enables Phalanx nodes to share state (sticky sessions, rate counters, bans)
//! without requiring external infrastructure like Redis or etcd.
//!
//! Protocol: Each node periodically picks a random peer and exchanges state digests
//! over UDP. Differences are reconciled using last-write-wins (LWW) semantics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Maximum UDP datagram size for gossip messages.
const MAX_DATAGRAM_SIZE: usize = 65507;

/// Default gossip interval in milliseconds.
const DEFAULT_GOSSIP_INTERVAL_MS: u64 = 1000;

/// Default number of peers to gossip with per round.
const DEFAULT_FANOUT: usize = 3;

/// Node membership state in the SWIM protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    Alive,
    Suspect,
    Dead,
}

/// Metadata about a cluster peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_id: String,
    pub state: NodeState,
    pub incarnation: u64,
    pub last_seen: u64,
}

/// A single key-value entry with LWW timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEntry {
    pub key: String,
    pub value: String,
    pub timestamp: u64,
    pub node_id: String,
    /// TTL in seconds (0 = no expiry)
    pub ttl_secs: u64,
}

/// Gossip protocol message types exchanged over UDP between cluster peers.
///
/// The protocol follows the SWIM paper's Ping/Ack model with Join/Leave extensions.
/// All messages are JSON-serialized for simplicity (production could use bincode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Ping with state digest
    Ping {
        sender_id: String,
        sender_addr: SocketAddr,
        incarnation: u64,
        entries: Vec<GossipEntry>,
        members: Vec<PeerInfo>,
    },
    /// Ack response to a Ping
    Ack {
        sender_id: String,
        sender_addr: SocketAddr,
        incarnation: u64,
        entries: Vec<GossipEntry>,
        members: Vec<PeerInfo>,
    },
    /// Indirect ping request (asked when direct ping fails)
    PingReq {
        sender_id: String,
        target_addr: SocketAddr,
    },
    /// Join request from a new node
    Join {
        node_id: String,
        addr: SocketAddr,
    },
    /// Leave notification
    Leave {
        node_id: String,
    },
}

/// Configuration for the gossip protocol.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// This node's unique ID
    pub node_id: String,
    /// UDP bind address for gossip protocol
    pub bind_addr: SocketAddr,
    /// Known seed peers to join on startup
    pub seed_peers: Vec<SocketAddr>,
    /// Gossip round interval in milliseconds
    pub gossip_interval_ms: u64,
    /// Number of peers to gossip with each round
    pub fanout: usize,
    /// Suspicion timeout before marking a node as Dead (ms)
    pub suspicion_timeout_ms: u64,
    /// Shared HMAC secret for message authentication (disable with None)
    pub hmac_secret: Option<String>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            node_id: "phalanx-node-1".to_string(),
            bind_addr: "0.0.0.0:7946".parse().unwrap(),
            seed_peers: Vec::new(),
            gossip_interval_ms: DEFAULT_GOSSIP_INTERVAL_MS,
            fanout: DEFAULT_FANOUT,
            suspicion_timeout_ms: 5000,
            hmac_secret: None,
        }
    }
}

/// The gossip state engine -- manages membership and shared KV state.
///
/// This is the core data structure for the SWIM-based gossip protocol. It holds:
/// - A replicated KV store (entries) with last-write-wins conflict resolution
/// - A membership table (members) tracking peer health via the SWIM lifecycle
/// - An incarnation counter used to refute false suspicion reports
///
/// All state is protected by `parking_lot::RwLock` for high-throughput concurrent access.
pub struct GossipState {
    /// Protocol configuration (bind address, fanout, intervals, etc.).
    config: GossipConfig,
    /// Shared KV store: key -> GossipEntry (LWW by timestamp).
    entries: Arc<RwLock<HashMap<String, GossipEntry>>>,
    /// Known cluster members indexed by node ID.
    members: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Monotonically increasing incarnation counter. Bumped on each outgoing Ping/Ack
    /// and used to refute suspicion (a node with a higher incarnation overrides Suspect state).
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    /// Per-target rate limit for PingReq indirect probes (prevents task-spawn flood).
    pingreq_last: RwLock<HashMap<SocketAddr, Instant>>,
}

impl GossipState {
    /// Creates a new gossip state engine and registers this node as the first member.
    pub fn new(config: GossipConfig) -> Self {
        let node_id = config.node_id.clone();
        let bind_addr = config.bind_addr;
        let members = Arc::new(RwLock::new(HashMap::new()));

        // Register self as the first member
        {
            let mut m = members.write();
            m.insert(
                node_id.clone(),
                PeerInfo {
                    addr: bind_addr,
                    node_id: node_id.clone(),
                    state: NodeState::Alive,
                    incarnation: 1,
                    last_seen: now_secs(),
                },
            );
        }

        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            members,
            incarnation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            pingreq_last: RwLock::new(HashMap::new()),
        }
    }

    /// Stores a key-value pair in the gossip state.
    pub fn put(&self, key: &str, value: &str, ttl_secs: u64) {
        let entry = GossipEntry {
            key: key.to_string(),
            value: value.to_string(),
            timestamp: now_secs(),
            node_id: self.config.node_id.clone(),
            ttl_secs,
        };
        self.entries.write().insert(key.to_string(), entry);
    }

    /// Retrieves a value from gossip state.
    pub fn get(&self, key: &str) -> Option<String> {
        let entries = self.entries.read();
        entries.get(key).and_then(|e| {
            if e.ttl_secs > 0 {
                let age = now_secs().saturating_sub(e.timestamp);
                if age > e.ttl_secs {
                    return None; // expired
                }
            }
            Some(e.value.clone())
        })
    }

    /// Deletes a key from gossip state.
    pub fn delete(&self, key: &str) {
        self.entries.write().remove(key);
    }

    /// Returns all non-expired entries (for gossip exchange).
    pub fn snapshot_entries(&self) -> Vec<GossipEntry> {
        let now = now_secs();
        self.entries
            .read()
            .values()
            .filter(|e| {
                if e.ttl_secs == 0 {
                    true
                } else {
                    now.saturating_sub(e.timestamp) <= e.ttl_secs
                }
            })
            .cloned()
            .collect()
    }

    /// Returns current member list.
    pub fn snapshot_members(&self) -> Vec<PeerInfo> {
        self.members.read().values().cloned().collect()
    }

    /// Returns the count of alive members.
    pub fn alive_member_count(&self) -> usize {
        self.members
            .read()
            .values()
            .filter(|p| p.state == NodeState::Alive)
            .count()
    }

    /// Merges incoming entries using last-write-wins (LWW) semantics.
    ///
    /// For each incoming entry, if its timestamp is newer than the local copy
    /// (or the key does not exist locally), the local entry is replaced.
    /// This is the core convergence mechanism -- after enough gossip rounds,
    /// all nodes will hold the same set of entries.
    pub fn merge_entries(&self, incoming: &[GossipEntry]) {
        let mut entries = self.entries.write();
        for entry in incoming {
            let dominated = entries
                .get(&entry.key)
                .map(|existing| entry.timestamp > existing.timestamp)
                .unwrap_or(true);
            if dominated {
                entries.insert(entry.key.clone(), entry.clone());
            }
        }
    }

    /// Merges incoming member list using incarnation number and last-seen timestamp.
    ///
    /// A remote peer's state is accepted if its incarnation number is higher
    /// (authoritative) or its last_seen timestamp is more recent. This prevents
    /// stale state from overwriting fresh information.
    pub fn merge_members(&self, incoming: &[PeerInfo]) {
        let mut members = self.members.write();
        for peer in incoming {
            let dominated = members
                .get(&peer.node_id)
                .map(|existing| peer.incarnation > existing.incarnation || peer.last_seen > existing.last_seen)
                .unwrap_or(true);
            if dominated {
                members.insert(peer.node_id.clone(), peer.clone());
            }
        }
    }

    /// Marks a peer as suspect (possible failure detected).
    pub fn suspect_peer(&self, node_id: &str) {
        let mut members = self.members.write();
        if let Some(peer) = members.get_mut(node_id) {
            if peer.state == NodeState::Alive {
                peer.state = NodeState::Suspect;
                debug!("Gossip: peer {} marked as Suspect", node_id);
            }
        }
    }

    /// Marks a peer as dead.
    pub fn mark_dead(&self, node_id: &str) {
        let mut members = self.members.write();
        if let Some(peer) = members.get_mut(node_id) {
            peer.state = NodeState::Dead;
            info!("Gossip: peer {} marked as Dead", node_id);
        }
    }

    /// Handles a join request from a new or re-joining node.
    ///
    /// If the peer already exists with a higher incarnation, the existing state
    /// is preserved — otherwise the peer's suspicion/refutation history would be
    /// erased on every Ping/Ack/Join exchange.
    pub fn handle_join(&self, node_id: &str, addr: SocketAddr) {
        let mut members = self.members.write();
        let now = now_secs();
        let (existing_state, existing_inc) = members
            .get(node_id)
            .map(|e| (e.state, e.incarnation))
            .unwrap_or((NodeState::Alive, 1));
        let inc = existing_inc.max(1);
        members.insert(
            node_id.to_string(),
            PeerInfo {
                addr,
                node_id: node_id.to_string(),
                state: existing_state,
                incarnation: inc,
                last_seen: now,
            },
        );
        info!("Gossip: peer {} joined at {}", node_id, addr);
    }

    /// Handles a leave notification.
    pub fn handle_leave(&self, node_id: &str) {
        self.mark_dead(node_id);
        info!("Gossip: peer {} left the cluster", node_id);
    }

    /// Encodes a gossip message to bytes.
    pub fn encode_message(msg: &GossipMessage) -> Result<Vec<u8>, String> {
        serde_json::to_vec(msg).map_err(|e| format!("encode error: {}", e))
    }

    /// Decodes a gossip message from bytes.
    pub fn decode_message(data: &[u8]) -> Result<GossipMessage, String> {
        serde_json::from_slice(data).map_err(|e| format!("decode error: {}", e))
    }

    /// Processes an incoming gossip message and returns an optional response.
    ///
    /// Message handling:
    /// - **Ping**: Merge the sender's state, then reply with an Ack containing our state.
    ///   This is the core gossip exchange -- both sides converge after each round.
    /// - **Ack**: Merge the sender's state silently (no reply to an Ack).
    /// - **Join**: Register a new peer in the membership table.
    /// - **Leave**: Mark the departing peer as Dead.
    /// - **PingReq**: Handled asynchronously in the gossip loop (indirect probe).
    ///   Returns `None` here; the gossip recv loop spawns an async task for the probe.
    pub fn process_message(&self, msg: GossipMessage) -> Option<GossipMessage> {
        match msg {
            GossipMessage::Ping {
                sender_id,
                sender_addr,
                incarnation: _,
                entries,
                members,
            } => {
                // Update sender's last_seen
                self.handle_join(&sender_id, sender_addr);
                // Merge state
                self.merge_entries(&entries);
                self.merge_members(&members);
                // Reply with our state
                let inc = self.incarnation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(GossipMessage::Ack {
                    sender_id: self.config.node_id.clone(),
                    sender_addr: self.config.bind_addr,
                    incarnation: inc,
                    entries: self.snapshot_entries(),
                    members: self.snapshot_members(),
                })
            }
            GossipMessage::Ack {
                sender_id,
                sender_addr,
                incarnation: _,
                entries,
                members,
            } => {
                self.handle_join(&sender_id, sender_addr);
                self.merge_entries(&entries);
                self.merge_members(&members);
                None // No response to an Ack
            }
            GossipMessage::Join { node_id, addr } => {
                self.handle_join(&node_id, addr);
                None
            }
            GossipMessage::Leave { node_id } => {
                self.handle_leave(&node_id);
                None
            }
            GossipMessage::PingReq { .. } => None,
        }
    }

    /// Returns the gossip config.
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Returns current incarnation value.
    pub fn incarnation(&self) -> u64 {
        self.incarnation.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Evicts expired entries from the KV store based on their TTL.
    /// Entries with `ttl_secs == 0` never expire. Called periodically by the gossip loop.
    pub fn evict_expired(&self) {
        let now = now_secs();
        let mut entries = self.entries.write();
        entries.retain(|_, e| {
            if e.ttl_secs == 0 {
                true
            } else {
                now.saturating_sub(e.timestamp) <= e.ttl_secs
            }
        });
    }

    /// Evicts dead members whose `last_seen` timestamp is older than `max_dead_age_secs`.
    /// This prevents the membership table from growing unboundedly as nodes leave.
    pub fn evict_dead_members(&self, max_dead_age_secs: u64) {
        let now = now_secs();
        let mut members = self.members.write();
        members.retain(|_, p| {
            if p.state == NodeState::Dead {
                now.saturating_sub(p.last_seen) <= max_dead_age_secs
            } else {
                true
            }
        });
    }

    /// Transitions Suspect peers to Dead when `last_seen` exceeds `suspicion_timeout_ms`.
    /// Called each gossip round so suspected nodes don't persist forever (H16).
    pub fn check_suspicion_timeouts(&self) {
        let now = now_secs();
        let timeout_secs = self.config.suspicion_timeout_ms / 1000;
        let mut members = self.members.write();
        for (_, peer) in members.iter_mut() {
            if peer.state == NodeState::Suspect {
                let age_secs = now.saturating_sub(peer.last_seen);
                if age_secs > timeout_secs {
                    peer.state = NodeState::Dead;
                    info!(
                        "Gossip: peer {} Suspect→Dead after {}s (timeout {}s)",
                        peer.node_id, age_secs, timeout_secs,
                    );
                }
            }
        }
    }

    /// Returns true if the target address is not being throttled for PingReq (H18).
    /// Rate-limit: at most one PingReq per target per second.
    fn allow_pingreq(&self, target: SocketAddr) -> bool {
        let now = Instant::now();
        let mut last = self.pingreq_last.write();
        if let Some(prev) = last.get(&target) {
            if now.duration_since(*prev) < Duration::from_secs(1) {
                return false;
            }
        }
        last.insert(target, now);
        true
    }

    /// Builds a Ping whose encoded size fits within `MAX_DATAGRAM_SIZE` (H17).
    /// If the full snapshot is too large, halves the entry/member lists until it fits.
    fn build_size_checked_ping(&self) -> GossipMessage {
        let inc = self.incarnation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut entries = self.snapshot_entries();
        let mut members = self.snapshot_members();

        loop {
            let msg = GossipMessage::Ping {
                sender_id: self.config.node_id.clone(),
                sender_addr: self.config.bind_addr,
                incarnation: inc,
                entries: entries.clone(),
                members: members.clone(),
            };
            match Self::encode_message(&msg) {
                Ok(data) if data.len() <= MAX_DATAGRAM_SIZE => return msg,
                _ => {
                    if entries.len() > members.len() && entries.len() > 1 {
                        entries.truncate(entries.len() / 2);
                    } else if !members.is_empty() {
                        members.truncate((members.len() / 2).max(1));
                    } else {
                        entries.clear();
                        return msg;
                    }
                }
            }
        }
    }

    /// Computes HMAC-SHA256(data, secret) and appends the 32-byte tag to the payload.
    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        let secret = match &self.config.hmac_secret {
            Some(s) => s,
            None => return data.to_vec(),
        };
        let tag = hmac_sha256(secret.as_bytes(), data);
        let mut out = Vec::with_capacity(data.len() + 32);
        out.extend_from_slice(data);
        out.extend_from_slice(&tag);
        out
    }

    /// Verifies and strips the HMAC-SHA256 tag. Returns the plaintext payload or an error.
    fn verify_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let secret = match &self.config.hmac_secret {
            Some(s) => s,
            None => return Ok(data.to_vec()),
        };
        if data.len() < 32 {
            return Err("message too short for HMAC tag".into());
        }
        let (payload, tag) = data.split_at(data.len() - 32);
        let expected = hmac_sha256(secret.as_bytes(), payload);
        if tag != expected.as_slice() {
            return Err("HMAC verification failed".into());
        }
        Ok(payload.to_vec())
    }

    /// Spawns the background gossip protocol loop as a Tokio task.
    ///
    /// The loop performs three activities:
    /// 1. **Bootstrap**: Sends Join messages to all seed peers on startup.
    /// 2. **Listener**: Spawns a UDP recv loop that processes incoming messages
    ///    and sends replies.
    /// 3. **Gossip round**: Every `gossip_interval_ms`, picks up to `fanout` alive
    ///    peers and sends them a Ping containing our full state snapshot.
    pub fn spawn_gossip_loop(self: Arc<Self>) {
        let state = Arc::clone(&self);
        tokio::spawn(async move {
            let socket = match UdpSocket::bind(&state.config.bind_addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    error!("Gossip: failed to bind UDP socket: {}", e);
                    return;
                }
            };
            info!("Gossip protocol listening on {}", state.config.bind_addr);

            // Announce to seed peers (H19: sign if HMAC secret configured)
            for seed in &state.config.seed_peers {
                let join_msg = GossipMessage::Join {
                    node_id: state.config.node_id.clone(),
                    addr: state.config.bind_addr,
                };
                if let Ok(data) = GossipState::encode_message(&join_msg) {
                    let signed = state.sign_data(&data);
                    let _ = socket.send_to(&signed, seed).await;
                }
            }

            // Spawn listener task
            let recv_socket = Arc::clone(&socket);
            let recv_state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
                loop {
                    match recv_socket.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            // H19: verify HMAC before decoding
                            let plain = match recv_state.verify_data(&buf[..len]) {
                                Ok(p) => p,
                                Err(e) => {
                                    debug!("Gossip: dropped message from {}: {}", src, e);
                                    continue;
                                }
                            };
                            match GossipState::decode_message(&plain) {
                                Ok(GossipMessage::PingReq { sender_id: _, target_addr }) => {
                                    // H18: rate-limit PingReq to 1/target/sec
                                    if !recv_state.allow_pingreq(target_addr) {
                                        debug!(
                                            "Gossip: PingReq for {} throttled (rate limit)",
                                            target_addr
                                        );
                                        continue;
                                    }
                                    // Indirect probe: ping the target on behalf of the requester
                                    let target = target_addr;
                                    let sock = Arc::clone(&recv_socket);
                                    let probe_state = Arc::clone(&recv_state);
                                    let requester = src;
                                    tokio::spawn(async move {
                                        // Use ephemeral socket to avoid interfering with main recv loop
                                        let probe_sock = match UdpSocket::bind("0.0.0.0:0").await {
                                            Ok(s) => s,
                                            Err(_) => return,
                                        };
                                        let inc = probe_state.incarnation.fetch_add(
                                            1,
                                            std::sync::atomic::Ordering::SeqCst,
                                        );
                                        let ping = GossipMessage::Ping {
                                            sender_id: probe_state.config.node_id.clone(),
                                            sender_addr: probe_state.config.bind_addr,
                                            incarnation: inc,
                                            entries: vec![],
                                            members: vec![],
                                        };
                                        if let Ok(data) = GossipState::encode_message(&ping) {
                                            let signed = probe_state.sign_data(&data);
                                            if probe_sock.send_to(&signed, target).await.is_err() {
                                                return;
                                            }
                                        } else {
                                            return;
                                        }
                                        // Wait for Ack with 2s timeout
                                        let mut probe_buf = vec![0u8; MAX_DATAGRAM_SIZE];
                                        match tokio::time::timeout(
                                            Duration::from_secs(2),
                                            probe_sock.recv_from(&mut probe_buf),
                                        )
                                        .await
                                        {
                                            Ok(Ok((plen, _))) => {
                                                // H19: verify before decode
                                                let probe_plain = match probe_state
                                                    .verify_data(&probe_buf[..plen])
                                                {
                                                    Ok(p) => p,
                                                    Err(_) => return,
                                                };
                                                if let Ok(GossipMessage::Ack { .. }) =
                                                    GossipState::decode_message(&probe_plain)
                                                {
                                                    // Target is alive — relay Ack to requester
                                                    let ack = GossipMessage::Ack {
                                                        sender_id: probe_state.config.node_id.clone(),
                                                        sender_addr: probe_state.config.bind_addr,
                                                        incarnation: probe_state.incarnation.load(
                                                            std::sync::atomic::Ordering::SeqCst,
                                                        ),
                                                        entries: vec![],
                                                        members: vec![],
                                                    };
                                                    if let Ok(data) =
                                                        GossipState::encode_message(&ack)
                                                    {
                                                        let signed = probe_state.sign_data(&data);
                                                        let _ =
                                                            sock.send_to(&signed, requester).await;
                                                    }
                                                    debug!(
                                                        "PingReq: target {} is alive, relayed Ack to {}",
                                                        target, requester
                                                    );
                                                }
                                            }
                                            _ => {
                                                debug!(
                                                    "PingReq: target {} did not respond within timeout",
                                                    target
                                                );
                                            }
                                        }
                                    });
                                }
                                Ok(msg) => {
                                    if let Some(reply) = recv_state.process_message(msg) {
                                        if let Ok(data) = GossipState::encode_message(&reply) {
                                            let signed = recv_state.sign_data(&data);
                                            let _ = recv_socket.send_to(&signed, src).await;
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Err(e) => {
                            warn!("Gossip recv error: {}", e);
                        }
                    }
                }
            });

            // Gossip round loop
            let interval = Duration::from_millis(state.config.gossip_interval_ms);
            loop {
                tokio::time::sleep(interval).await;

                // Evict expired entries
                state.evict_expired();

                // H16: transition timed-out Suspect peers to Dead
                state.check_suspicion_timeouts();

                // Pick random peers to gossip with
                let peers: Vec<SocketAddr> = {
                    let members = state.members.read();
                    members
                        .values()
                        .filter(|p| p.node_id != state.config.node_id && p.state == NodeState::Alive)
                        .map(|p| p.addr)
                        .collect()
                };

                let fanout = std::cmp::min(state.config.fanout, peers.len());
                if fanout == 0 {
                    continue;
                }

                // H17: build size-checked Ping that fits within MAX_DATAGRAM_SIZE
                let ping = state.build_size_checked_ping();

                if let Ok(data) = GossipState::encode_message(&ping) {
                    // H19: sign if HMAC secret configured
                    let signed = state.sign_data(&data);
                    for &peer_addr in peers.iter().take(fanout) {
                        let _ = socket.send_to(&signed, peer_addr).await;
                    }
                }
            }
        });
    }
}

/// HMAC-SHA256 implementation using the `sha2` crate already in the dependency tree.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha2::Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = sha2::Sha256::digest([&ipad[..], data].concat());
    sha2::Sha256::digest([&opad[..], &inner[..]].concat()).into()
}

/// Returns the current Unix epoch time in seconds. Used for timestamps throughout
/// the gossip protocol (entry timestamps, last_seen, TTL calculations).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(node_id: &str) -> GossipState {
        GossipState::new(GossipConfig {
            node_id: node_id.to_string(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        })
    }

    #[test]
    fn test_gossip_state_creation() {
        let state = make_state("node-1");
        assert_eq!(state.config().node_id, "node-1");
        assert_eq!(state.alive_member_count(), 1); // self
    }

    #[test]
    fn test_gossip_put_get() {
        let state = make_state("node-1");
        state.put("key1", "value1", 0);
        assert_eq!(state.get("key1"), Some("value1".to_string()));
    }

    #[test]
    fn test_gossip_get_missing_key() {
        let state = make_state("node-1");
        assert_eq!(state.get("nonexistent"), None);
    }

    #[test]
    fn test_gossip_delete() {
        let state = make_state("node-1");
        state.put("key1", "value1", 0);
        state.delete("key1");
        assert_eq!(state.get("key1"), None);
    }

    #[test]
    fn test_gossip_ttl_expiry() {
        let state = make_state("node-1");
        // Insert with TTL of 0 (expired immediately via manual timestamp)
        {
            let mut entries = state.entries.write();
            entries.insert("expired".to_string(), GossipEntry {
                key: "expired".to_string(),
                value: "old".to_string(),
                timestamp: 1, // very old timestamp
                node_id: "node-1".to_string(),
                ttl_secs: 1,
            });
        }
        assert_eq!(state.get("expired"), None);
    }

    #[test]
    fn test_gossip_snapshot_entries() {
        let state = make_state("node-1");
        state.put("a", "1", 0);
        state.put("b", "2", 0);
        let snap = state.snapshot_entries();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn test_gossip_merge_entries_lww() {
        let state = make_state("node-1");
        state.put("key1", "old_value", 0);

        let newer_entry = GossipEntry {
            key: "key1".to_string(),
            value: "new_value".to_string(),
            timestamp: now_secs() + 100,
            node_id: "node-2".to_string(),
            ttl_secs: 0,
        };
        state.merge_entries(&[newer_entry]);
        assert_eq!(state.get("key1"), Some("new_value".to_string()));
    }

    #[test]
    fn test_gossip_merge_entries_older_ignored() {
        let state = make_state("node-1");
        state.put("key1", "current", 0);

        let older_entry = GossipEntry {
            key: "key1".to_string(),
            value: "stale".to_string(),
            timestamp: 1, // very old
            node_id: "node-2".to_string(),
            ttl_secs: 0,
        };
        state.merge_entries(&[older_entry]);
        assert_eq!(state.get("key1"), Some("current".to_string()));
    }

    #[test]
    fn test_gossip_handle_join() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        assert_eq!(state.alive_member_count(), 2);
    }

    #[test]
    fn test_gossip_handle_leave() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        state.handle_leave("node-2");
        let members = state.snapshot_members();
        let dead = members.iter().find(|p| p.node_id == "node-2").unwrap();
        assert_eq!(dead.state, NodeState::Dead);
    }

    #[test]
    fn test_gossip_suspect_peer() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        state.suspect_peer("node-2");
        let members = state.snapshot_members();
        let suspect = members.iter().find(|p| p.node_id == "node-2").unwrap();
        assert_eq!(suspect.state, NodeState::Suspect);
    }

    #[test]
    fn test_gossip_mark_dead() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        state.mark_dead("node-2");
        let alive = state.alive_member_count();
        assert_eq!(alive, 1); // only self
    }

    #[test]
    fn test_gossip_merge_members() {
        let state = make_state("node-1");
        let peer = PeerInfo {
            addr: "10.0.0.3:7946".parse().unwrap(),
            node_id: "node-3".to_string(),
            state: NodeState::Alive,
            incarnation: 1,
            last_seen: now_secs(),
        };
        state.merge_members(&[peer]);
        assert_eq!(state.alive_member_count(), 2);
    }

    #[test]
    fn test_gossip_encode_decode_ping() {
        let msg = GossipMessage::Ping {
            sender_id: "node-1".to_string(),
            sender_addr: "10.0.0.1:7946".parse().unwrap(),
            incarnation: 5,
            entries: vec![],
            members: vec![],
        };
        let data = GossipState::encode_message(&msg).unwrap();
        let decoded = GossipState::decode_message(&data).unwrap();
        match decoded {
            GossipMessage::Ping { sender_id, incarnation, .. } => {
                assert_eq!(sender_id, "node-1");
                assert_eq!(incarnation, 5);
            }
            _ => panic!("Expected Ping"),
        }
    }

    #[test]
    fn test_gossip_encode_decode_ack() {
        let msg = GossipMessage::Ack {
            sender_id: "node-2".to_string(),
            sender_addr: "10.0.0.2:7946".parse().unwrap(),
            incarnation: 3,
            entries: vec![],
            members: vec![],
        };
        let data = GossipState::encode_message(&msg).unwrap();
        let decoded = GossipState::decode_message(&data).unwrap();
        match decoded {
            GossipMessage::Ack { sender_id, .. } => assert_eq!(sender_id, "node-2"),
            _ => panic!("Expected Ack"),
        }
    }

    #[test]
    fn test_gossip_encode_decode_join() {
        let msg = GossipMessage::Join {
            node_id: "new-node".to_string(),
            addr: "10.0.0.5:7946".parse().unwrap(),
        };
        let data = GossipState::encode_message(&msg).unwrap();
        let decoded = GossipState::decode_message(&data).unwrap();
        match decoded {
            GossipMessage::Join { node_id, .. } => assert_eq!(node_id, "new-node"),
            _ => panic!("Expected Join"),
        }
    }

    #[test]
    fn test_gossip_encode_decode_leave() {
        let msg = GossipMessage::Leave { node_id: "leaving".to_string() };
        let data = GossipState::encode_message(&msg).unwrap();
        let decoded = GossipState::decode_message(&data).unwrap();
        match decoded {
            GossipMessage::Leave { node_id } => assert_eq!(node_id, "leaving"),
            _ => panic!("Expected Leave"),
        }
    }

    #[test]
    fn test_gossip_process_ping_returns_ack() {
        let state = make_state("node-1");
        let ping = GossipMessage::Ping {
            sender_id: "node-2".to_string(),
            sender_addr: "10.0.0.2:7946".parse().unwrap(),
            incarnation: 1,
            entries: vec![GossipEntry {
                key: "shared-key".to_string(),
                value: "shared-value".to_string(),
                timestamp: now_secs(),
                node_id: "node-2".to_string(),
                ttl_secs: 0,
            }],
            members: vec![],
        };
        let reply = state.process_message(ping);
        assert!(reply.is_some());
        match reply.unwrap() {
            GossipMessage::Ack { sender_id, .. } => assert_eq!(sender_id, "node-1"),
            _ => panic!("Expected Ack"),
        }
        // Verify state was merged
        assert_eq!(state.get("shared-key"), Some("shared-value".to_string()));
    }

    #[test]
    fn test_gossip_process_ack_no_reply() {
        let state = make_state("node-1");
        let ack = GossipMessage::Ack {
            sender_id: "node-2".to_string(),
            sender_addr: "10.0.0.2:7946".parse().unwrap(),
            incarnation: 1,
            entries: vec![],
            members: vec![],
        };
        let reply = state.process_message(ack);
        assert!(reply.is_none());
    }

    #[test]
    fn test_gossip_process_join() {
        let state = make_state("node-1");
        let join = GossipMessage::Join {
            node_id: "node-3".to_string(),
            addr: "10.0.0.3:7946".parse().unwrap(),
        };
        state.process_message(join);
        assert_eq!(state.alive_member_count(), 2);
    }

    #[test]
    fn test_gossip_process_leave() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        let leave = GossipMessage::Leave { node_id: "node-2".to_string() };
        state.process_message(leave);
        assert_eq!(state.alive_member_count(), 1);
    }

    #[test]
    fn test_gossip_evict_expired() {
        let state = make_state("node-1");
        {
            let mut entries = state.entries.write();
            entries.insert("old".to_string(), GossipEntry {
                key: "old".to_string(),
                value: "stale".to_string(),
                timestamp: 1,
                node_id: "node-1".to_string(),
                ttl_secs: 1,
            });
        }
        state.put("fresh", "new", 3600);
        state.evict_expired();
        assert_eq!(state.get("old"), None);
        assert_eq!(state.get("fresh"), Some("new".to_string()));
    }

    #[test]
    fn test_gossip_evict_dead_members() {
        let state = make_state("node-1");
        state.handle_join("node-2", "10.0.0.2:7946".parse().unwrap());
        // Manually set node-2 as dead with old last_seen
        {
            let mut members = state.members.write();
            if let Some(p) = members.get_mut("node-2") {
                p.state = NodeState::Dead;
                p.last_seen = 1; // very old
            }
        }
        state.evict_dead_members(60);
        assert_eq!(state.snapshot_members().len(), 1); // only self
    }

    #[test]
    fn test_gossip_incarnation_increases() {
        let state = make_state("node-1");
        let inc1 = state.incarnation();
        let ping = GossipMessage::Ping {
            sender_id: "node-2".to_string(),
            sender_addr: "10.0.0.2:7946".parse().unwrap(),
            incarnation: 1,
            entries: vec![],
            members: vec![],
        };
        state.process_message(ping);
        let inc2 = state.incarnation();
        assert!(inc2 > inc1);
    }

    #[test]
    fn test_gossip_config_default() {
        let cfg = GossipConfig::default();
        assert_eq!(cfg.gossip_interval_ms, 1000);
        assert_eq!(cfg.fanout, 3);
        assert_eq!(cfg.suspicion_timeout_ms, 5000);
        assert!(cfg.seed_peers.is_empty());
    }

    #[test]
    fn test_node_state_serialization() {
        let json = serde_json::to_string(&NodeState::Alive).unwrap();
        let deserialized: NodeState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, NodeState::Alive);
    }

    #[test]
    fn test_node_state_equality() {
        assert_eq!(NodeState::Alive, NodeState::Alive);
        assert_ne!(NodeState::Alive, NodeState::Dead);
        assert_ne!(NodeState::Suspect, NodeState::Dead);
    }

    #[test]
    fn test_gossip_entry_serialization() {
        let entry = GossipEntry {
            key: "test".to_string(),
            value: "data".to_string(),
            timestamp: 12345,
            node_id: "n1".to_string(),
            ttl_secs: 60,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: GossipEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.key, "test");
        assert_eq!(decoded.ttl_secs, 60);
    }

    #[test]
    fn test_gossip_multiple_puts_overwrite() {
        let state = make_state("node-1");
        state.put("key", "v1", 0);
        state.put("key", "v2", 0);
        state.put("key", "v3", 0);
        assert_eq!(state.get("key"), Some("v3".to_string()));
    }

    #[test]
    fn test_gossip_encode_decode_pingreq() {
        let msg = GossipMessage::PingReq {
            sender_id: "node-1".to_string(),
            target_addr: "10.0.0.5:7946".parse().unwrap(),
        };
        let data = GossipState::encode_message(&msg).unwrap();
        let decoded = GossipState::decode_message(&data).unwrap();
        match decoded {
            GossipMessage::PingReq { sender_id, target_addr } => {
                assert_eq!(sender_id, "node-1");
                assert_eq!(target_addr, "10.0.0.5:7946".parse::<std::net::SocketAddr>().unwrap());
            }
            _ => panic!("Expected PingReq"),
        }
    }

    #[test]
    fn test_gossip_process_pingreq_returns_none() {
        // PingReq is handled async in the gossip loop, so process_message returns None
        let state = make_state("node-1");
        let pingreq = GossipMessage::PingReq {
            sender_id: "node-2".to_string(),
            target_addr: "10.0.0.3:7946".parse().unwrap(),
        };
        let reply = state.process_message(pingreq);
        assert!(reply.is_none());
    }

    #[test]
    fn test_gossip_no_expiry_with_zero_ttl() {
        let state = make_state("node-1");
        state.put("permanent", "value", 0);
        assert_eq!(state.get("permanent"), Some("value".to_string()));
    }

    // ── H16: suspicion timeout ──────────────────────────────────────────────

    #[test]
    fn test_suspicion_timeout_transitions_to_dead() {
        let state = make_state("node-1");
        // Register a peer as Suspect with old last_seen
        let old_peer = PeerInfo {
            addr: "10.0.0.2:7946".parse().unwrap(),
            node_id: "node-2".to_string(),
            state: NodeState::Suspect,
            incarnation: 1,
            last_seen: now_secs() - 10, // 10s ago, timeout is 5s
        };
        state.members.write().insert("node-2".to_string(), old_peer);

        state.check_suspicion_timeouts();

        let members = state.members.read();
        let peer = members.get("node-2").unwrap();
        assert_eq!(peer.state, NodeState::Dead);
    }

    #[test]
    fn test_suspicion_timeout_leaves_recent_suspect() {
        let state = make_state("node-1");
        let recent = PeerInfo {
            addr: "10.0.0.2:7946".parse().unwrap(),
            node_id: "node-2".to_string(),
            state: NodeState::Suspect,
            incarnation: 1,
            last_seen: now_secs(), // just now
        };
        state.members.write().insert("node-2".to_string(), recent);

        state.check_suspicion_timeouts();

        let members = state.members.read();
        let peer = members.get("node-2").unwrap();
        assert_eq!(peer.state, NodeState::Suspect);
    }

    // ── H19: HMAC sign/verify ───────────────────────────────────────────────

    #[test]
    fn test_hmac_sign_verify_roundtrip() {
        let state = GossipState::new(GossipConfig {
            node_id: "node-1".to_string(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            hmac_secret: Some("test-secret".to_string()),
            ..Default::default()
        });

        let msg = GossipMessage::Join {
            node_id: "peer".to_string(),
            addr: "10.0.0.2:7946".parse().unwrap(),
        };
        let encoded = GossipState::encode_message(&msg).unwrap();
        let signed = state.sign_data(&encoded);

        // Verify round-trip
        let verified = state.verify_data(&signed).unwrap();
        let decoded = GossipState::decode_message(&verified).unwrap();
        match decoded {
            GossipMessage::Join { node_id, .. } => assert_eq!(node_id, "peer"),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_hmac_rejects_tampered_data() {
        let state = GossipState::new(GossipConfig {
            node_id: "node-1".to_string(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            hmac_secret: Some("test-secret".to_string()),
            ..Default::default()
        });

        let msg = GossipMessage::Join {
            node_id: "peer".to_string(),
            addr: "10.0.0.2:7946".parse().unwrap(),
        };
        let encoded = GossipState::encode_message(&msg).unwrap();
        let mut signed = state.sign_data(&encoded);
        // Tamper with payload
        signed[5] ^= 0xFF;

        assert!(state.verify_data(&signed).is_err());
    }

    #[test]
    fn test_hmac_disabled_passthrough() {
        let state = make_state("node-1"); // no secret
        let data = b"hello world".to_vec();
        let signed = state.sign_data(&data);
        assert_eq!(signed, data); // identity
        let verified = state.verify_data(&data).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn test_hmac_rejects_short_data() {
        let state = GossipState::new(GossipConfig {
            node_id: "node-1".to_string(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            hmac_secret: Some("secret".to_string()),
            ..Default::default()
        });
        assert!(state.verify_data(b"short").is_err());
    }

    // ── H18: PingReq rate limit ─────────────────────────────────────────────

    #[test]
    fn test_pingreq_rate_limit_allows_first() {
        let state = make_state("node-1");
        let addr: SocketAddr = "10.0.0.2:7946".parse().unwrap();
        assert!(state.allow_pingreq(addr));
    }

    #[test]
    fn test_pingreq_rate_limit_blocks_second() {
        let state = make_state("node-1");
        let addr: SocketAddr = "10.0.0.2:7946".parse().unwrap();
        assert!(state.allow_pingreq(addr));
        // Same target within 1s → blocked
        assert!(!state.allow_pingreq(addr));
    }

    #[test]
    fn test_pingreq_rate_limit_allows_different_targets() {
        let state = make_state("node-1");
        let a: SocketAddr = "10.0.0.2:7946".parse().unwrap();
        let b: SocketAddr = "10.0.0.3:7946".parse().unwrap();
        assert!(state.allow_pingreq(a));
        assert!(state.allow_pingreq(b));
    }

    // ── H17: size-checked ping ──────────────────────────────────────────────

    #[test]
    fn test_build_size_checked_ping_fits() {
        let state = make_state("node-1");
        // Add many entries to test truncation
        for i in 0..2000 {
            state.put(
                &format!("key-{:04}", i),
                &"x".repeat(500),
                0,
            );
        }
        // Register many fake members
        for i in 2..200 {
            let peer = PeerInfo {
                addr: format!("10.0.0.{}:7946", i).parse().unwrap(),
                node_id: format!("node-{}", i),
                state: NodeState::Alive,
                incarnation: 1,
                last_seen: now_secs(),
            };
            state.members.write().insert(format!("node-{}", i), peer);
        }

        let ping = state.build_size_checked_ping();
        let data = GossipState::encode_message(&ping).unwrap();
        assert!(
            data.len() <= MAX_DATAGRAM_SIZE,
            "ping size {} > max {}",
            data.len(),
            MAX_DATAGRAM_SIZE
        );
    }
}
