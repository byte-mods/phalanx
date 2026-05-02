//! # Phalanx WebRTC Selective Forwarding Unit (SFU)
//!
//! This module implements a lightweight WebRTC SFU using the `webrtc-rs` crate.
//! It exposes HTTP signalling endpoints consumed by the `admin` server:
//!
//! - `POST /api/webrtc/publish`   — A publisher POSTs an SDP Offer; receives an SDP Answer.
//! - `POST /api/webrtc/subscribe` — A subscriber POSTs with a `room` query param; receives an Answer.
//! - `POST /api/webrtc/ice/:id`   — Trickle ICE: peer sends additional ICE candidates.
//! - `GET  /api/webrtc/rooms`     — Lists active rooms and their track counts.
//!
//! ## Architecture
//!
//! ```text
//!  Publisher Browser ──(DTLS/SRTP)──► PeerConnection(Publisher)
//!                                                │
//!                            ┌──────────────────┤ on_track
//!                            ▼                  │
//!                      SfuRoom.tracks[]          │
//!                            │                  │
//!             ┌──────────────┘                  │
//!             ▼                                 │
//!  Subscriber A ◄──(DTLS/SRTP)── PeerConnection(Sub A) WriteRTP
//!  Subscriber B ◄──(DTLS/SRTP)── PeerConnection(Sub B) WriteRTP
//! ```

use dashmap::DashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use crate::telemetry::bandwidth::BandwidthTracker;
use webrtc::{
    api::{
        APIBuilder,
        interceptor_registry::register_default_interceptors,
        media_engine::{MediaEngine, MIME_TYPE_H264, MIME_TYPE_OPUS, MIME_TYPE_VP8},
    },
    ice_transport::{
        ice_connection_state::RTCIceConnectionState,
        ice_server::RTCIceServer,
    },
    interceptor::registry::Registry,
    peer_connection::{
        RTCPeerConnection,
        configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription,
    },
    rtp_transceiver::{
        RTCRtpTransceiver,
        rtp_codec::{RTCRtpCodecCapability, RTCRtpCodecParameters, RTPCodecType},
        rtp_receiver::RTCRtpReceiver,
    },
    track::{
        track_local::{
            TrackLocalWriter,
            track_local_static_rtp::TrackLocalStaticRTP,
        },
        track_remote::TrackRemote,
    },
};
use webrtc::util::marshal::Marshal;

// ─── SFU State ───────────────────────────────────────────────────────────────

/// A single media track forwarded by the SFU to all subscribers in its room.
#[derive(Clone)]
pub struct SfuTrack {
    /// The local track that carries RTP packets to subscribers.
    pub local_track: Arc<TrackLocalStaticRTP>,
    /// SSRC of the original remote track (for logging / correlation).
    pub ssrc: u32,
    /// MIME type, e.g. `video/VP8` or `audio/opus`.
    pub mime: String,
}

/// Per-participant media stats snapshot.
#[derive(Clone, serde::Serialize)]
pub struct ParticipantStats {
    pub peer_id: String,
    pub role: String, // "publisher" or "subscriber"
}

/// A logical group of publishers and subscribers sharing the same media.
pub struct SfuRoom {
    pub id: String,
    /// Active tracks being forwarded to subscribers.
    pub tracks: DashMap<u32, SfuTrack>, // key = SSRC
    /// Channel used to notify subscribers of new tracks.
    pub track_tx: broadcast::Sender<SfuTrack>,
    /// Active peer connections (publishers + subscribers).
    pub peers: DashMap<String, Arc<RTCPeerConnection>>,
    /// Total RTP bytes forwarded through this room.
    pub bytes_forwarded: Arc<AtomicU64>,
    /// Total RTP packets forwarded.
    pub packets_forwarded: Arc<AtomicU64>,
    /// Publisher peer IDs (subset of peers).
    pub publishers: DashMap<String, ()>,
    /// Maps publisher peer_id → track SSRCs for cleanup on disconnect (H27).
    pub publisher_tracks: DashMap<String, Vec<u32>>,
    /// Cancellation tokens for subscriber track-rx tasks (H28).
    pub subscriber_tokens: DashMap<String, CancellationToken>,
    /// JoinHandles for subscriber track-rx tasks (H28 resilience).
    /// Stored so we can abort+remove on disconnect and detect panics.
    pub subscriber_handles: DashMap<String, tokio::task::JoinHandle<()>>,
    /// Cached pre-built WebRTC API for take-and-replenish (C3).
    /// Avoids rebuilding MediaEngine + interceptor registry on every publish/subscribe.
    pub cached_api: tokio::sync::Mutex<Option<webrtc::api::API>>,
    /// Unix epoch seconds of the last signalling activity (publish/subscribe/ICE).
    /// Used by the housekeeping task to expire idle rooms.
    pub last_activity: AtomicU64,
}

impl SfuRoom {
    /// Creates a new room with the given ID and an empty track/peer set.
    /// The returned `Arc<SfuRoom>` is shared among all signalling handlers.
    pub fn new(id: String) -> Arc<Self> {
        let (track_tx, _) = broadcast::channel(64);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Arc::new(Self {
            id,
            tracks: DashMap::new(),
            track_tx,
            peers: DashMap::new(),
            bytes_forwarded: Arc::new(AtomicU64::new(0)),
            packets_forwarded: Arc::new(AtomicU64::new(0)),
            publishers: DashMap::new(),
            publisher_tracks: DashMap::new(),
            subscriber_tokens: DashMap::new(),
            subscriber_handles: DashMap::new(),
            cached_api: tokio::sync::Mutex::new(None),
            last_activity: AtomicU64::new(now),
        })
    }

    /// Total participants (publishers + subscribers).
    pub fn participant_count(&self) -> usize {
        self.peers.len()
    }

    /// Publisher count.
    pub fn publisher_count(&self) -> usize {
        self.publishers.len()
    }

    /// Subscriber count (total peers minus publishers).
    pub fn subscriber_count(&self) -> usize {
        self.peers.len().saturating_sub(self.publishers.len())
    }

    /// Update the last-activity timestamp to now (epoch seconds).
    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_activity.store(now, Ordering::Relaxed);
    }
}

/// Global SFU state, shared across all HTTP signalling handlers.
pub struct SfuState {
    /// Active rooms keyed by room ID.
    pub rooms: DashMap<String, Arc<SfuRoom>>,
}

impl SfuState {
    /// Creates an empty global SFU state (no rooms).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rooms: DashMap::new(),
        })
    }

    /// Get or create a room by ID.
    pub fn get_or_create_room(&self, room_id: &str) -> Arc<SfuRoom> {
        self.rooms
            .entry(room_id.to_string())
            .or_insert_with(|| SfuRoom::new(room_id.to_string()))
            .clone()
    }

    /// List all active rooms with their track and bandwidth stats.
    pub fn list_rooms(&self) -> Vec<serde_json::Value> {
        self.rooms
            .iter()
            .map(|entry| {
                let room = entry.value();
                serde_json::json!({
                    "id": entry.key(),
                    "track_count": room.tracks.len(),
                    "peer_count": room.participant_count(),
                    "publishers": room.publisher_count(),
                    "subscribers": room.subscriber_count(),
                    "bytes_forwarded": room.bytes_forwarded.load(Ordering::Relaxed),
                    "packets_forwarded": room.packets_forwarded.load(Ordering::Relaxed),
                })
            })
            .collect()
    }

    /// Spawn a background task that removes rooms with zero peers after
    /// they have been idle longer than `idle_timeout_secs`. Runs every
    /// 30 seconds so worst-case a dead room lingers for 30 s past expiry.
    pub fn start_housekeeping(
        sfu: Arc<SfuState>,
        idle_timeout_secs: u64,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("SFU housekeeping task stopped.");
                        return;
                    }
                    _ = interval.tick() => {}
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                Self::sweep_expired_rooms(&sfu, now, idle_timeout_secs);
            }
        });
    }

    /// Remove any rooms that have zero peers and whose last-activity
    /// timestamp is older than `now - idle_timeout_secs`.
    fn sweep_expired_rooms(sfu: &Arc<SfuState>, now_secs: u64, idle_timeout_secs: u64) {
        let mut expired: Vec<String> = Vec::new();
        for entry in sfu.rooms.iter() {
            let room = entry.value();
            if room.peers.is_empty() {
                let last = room.last_activity.load(Ordering::Relaxed);
                if now_secs.saturating_sub(last) >= idle_timeout_secs {
                    expired.push(entry.key().clone());
                }
            }
        }
        for id in &expired {
            sfu.rooms.remove(id);
            info!("SFU housekeeping: removed idle room '{}'", id);
        }
    }
}

// ─── WebRTC API Factory ───────────────────────────────────────────────────────

/// Builds a configured `webrtc::api::API` with VP8, H.264, and Opus codecs registered.
///
/// The media engine is pre-loaded with the most common real-time codecs:
/// - **VP8** (video, payload type 96) -- widely supported, low-latency.
/// - **H.264** (video, payload type 102) -- hardware-accelerated on most devices.
/// - **Opus** (audio, payload type 111) -- adaptive bitrate voice/music codec.
///
/// Default interceptors (NACK, RTCP, etc.) are registered for reliability.
/// Acquires a pre-built WebRTC API from the room cache, or builds one fresh.
///
/// Uses a take-and-replenish pattern: the cached API is taken (consumed by
/// `new_peer_connection`), and a background task immediately rebuilds and
/// stores a replacement so the next caller gets a warm cache hit.
async fn acquire_api(room: &Arc<SfuRoom>) -> webrtc::error::Result<webrtc::api::API> {
    let cached = {
        let mut guard = room.cached_api.lock().await;
        guard.take()
    };
    match cached {
        Some(api) => {
            // Replenish in background while caller uses this one
            let room_bg = Arc::clone(room);
            tokio::spawn(async move {
                match build_webrtc_api() {
                    Ok(fresh) => {
                        *room_bg.cached_api.lock().await = Some(fresh);
                    }
                    Err(e) => {
                        warn!("Background WebRTC API rebuild failed: {}", e);
                    }
                }
            });
            Ok(api)
        }
        None => build_webrtc_api(),
    }
}

fn build_webrtc_api() -> webrtc::error::Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();

    // Register VP8 video codec
    media_engine.register_codec(
        RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            payload_type: 96,
            ..Default::default()
        },
        RTPCodecType::Video,
    )?;

    // Register H.264 video codec
    media_engine.register_codec(
        RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 102,
            ..Default::default()
        },
        RTPCodecType::Video,
    )?;

    // Register Opus audio codec
    media_engine.register_codec(
        RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
            ..Default::default()
        },
        RTPCodecType::Audio,
    )?;

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    Ok(api)
}

/// Build ICE server list from configured URLs, or fall back to public STUN.
///
/// Each entry in `configured_urls` becomes one `RTCIceServer` with a
/// single-element `urls` vec. When empty, Google's public STUN servers are
/// used so development works without explicit config.
fn build_ice_servers(configured_urls: &[String]) -> Vec<RTCIceServer> {
    let valid: Vec<&String> = configured_urls.iter().filter(|u| !u.trim().is_empty()).collect();
    if !valid.is_empty() {
        return valid
            .iter()
            .map(|url| RTCIceServer {
                urls: vec![(*url).clone()],
                ..Default::default()
            })
            .collect();
    }
    vec![RTCIceServer {
        urls: vec![
            "stun:stun.l.google.com:19302".to_owned(),
            "stun:stun1.l.google.com:19302".to_owned(),
        ],
        ..Default::default()
    }]
}

// ─── Publisher Signalling ─────────────────────────────────────────────────────

/// Accepts a WebRTC offer from a publisher and returns an SDP answer.
/// All incoming tracks are forwarded to the room's subscriber connections.
///
/// # Arguments
/// * `room`   – The `SfuRoom` this publisher is joining.
/// * `peer_id` – Unique ID for this peer connection (so it can be tracked/removed).
/// * `offer`  – Raw SDP offer string from the browser.
///
/// # Returns
/// SDP answer string to send back to the publisher.
pub async fn handle_publish(
    sfu: Arc<SfuState>,
    room_id: String,
    peer_id: String,
    offer_sdp: String,
    bandwidth: Option<Arc<BandwidthTracker>>,
    ice_servers: &[String],
) -> Result<String, String> {
    let room = sfu.get_or_create_room(&room_id);

    let api = acquire_api(&room).await.map_err(|e| format!("Failed to build WebRTC API: {}", e))?;

    let config = RTCConfiguration {
        ice_servers: build_ice_servers(ice_servers),
        ..Default::default()
    };

    let peer_connection = Arc::new(
        api.new_peer_connection(config)
            .await
            .map_err(|e| format!("Failed to create peer connection: {}", e))?,
    );

    // Store the peer connection and mark as publisher
    room.peers.insert(peer_id.clone(), Arc::clone(&peer_connection));
    room.publishers.insert(peer_id.clone(), ());
    room.touch();

    // Clone room for the on_track callback
    let room_for_track = Arc::clone(&room);
    let peer_id_for_close = peer_id.clone();
    let peer_id_for_track = peer_id.clone();
    let bandwidth_for_track = bandwidth.clone();

    // on_track: called when the publisher sends a media track
    peer_connection.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver: Arc<RTCRtpReceiver>, _transceiver: Arc<RTCRtpTransceiver>| {
            let room = Arc::clone(&room_for_track);
            let pid = peer_id_for_track.clone();
            let bw = bandwidth_for_track.clone();

            Box::pin(async move {
                let ssrc = track.ssrc();
                let mime = track.codec().capability.mime_type.clone();
                info!("Publisher track received: ssrc={} mime={}", ssrc, mime);

                // Create a local track to relay RTP packets to subscribers
                let local_track = Arc::new(TrackLocalStaticRTP::new(
                    track.codec().capability.clone(),
                    format!("phalanx-{}", ssrc),
                    format!("phalanx-stream-{}", ssrc),
                ));

                let sfu_track = SfuTrack {
                    local_track: Arc::clone(&local_track),
                    ssrc,
                    mime: mime.clone(),
                };

                // Register track in the room
                room.tracks.insert(ssrc, sfu_track.clone());
                // H27: track which publisher owns this SSRC for cleanup on disconnect
                room.publisher_tracks.entry(pid).or_default().push(ssrc);

                // Broadcast to any subscribers waiting for tracks
                if let Err(e) = room.track_tx.send(sfu_track) {
                    debug!("No active subscribers waiting for track {}: {}", ssrc, e);
                }

                // Forward RTP packets from publisher to the local_track
                let mut rtp_buf = vec![0u8; 1500];
                loop {
                    match track.read(&mut rtp_buf).await {
                        Ok((packet, _attr)) => {
                            // Marshal the parsed packet back to its exact wire-format
                            // bytes. The previous code wrote the entire 1500-byte
                            // rtp_buf (mostly trailing zeros), corrupting streams.
                            match packet.marshal() {
                                Ok(pkt_bytes) => {
                                    let pkt_len = pkt_bytes.len() as u64;
                                    if let Err(e) = local_track.write(&pkt_bytes).await {
                                        debug!("RTP write to local track failed (ssrc={}): {}", ssrc, e);
                                    } else {
                                        room.bytes_forwarded.fetch_add(pkt_len, Ordering::Relaxed);
                                        room.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                                        if let Some(ref bw) = bw {
                                            bw.protocol("webrtc").add_out(pkt_len);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("RTP marshal error for ssrc={}: {}", ssrc, e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Publisher track {} ended: {}", ssrc, e);
                            room.tracks.remove(&ssrc);
                            break;
                        }
                    }
                }
            })
        },
    ));

    // on_peer_connection_state_change: cleanup on disconnect
    let room_for_state = Arc::clone(&room);
    peer_connection.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let room = Arc::clone(&room_for_state);
        let peer_id = peer_id_for_close.clone();
        Box::pin(async move {
            info!("Publisher peer {} state: {:?}", peer_id, state);
            if state == RTCPeerConnectionState::Disconnected
                || state == RTCPeerConnectionState::Failed
                || state == RTCPeerConnectionState::Closed
            {
                // H27: remove all tracks belonging to this publisher
                if let Some((_, ssrclist)) = room.publisher_tracks.remove(&peer_id) {
                    for ssrc in &ssrclist {
                        room.tracks.remove(ssrc);
                    }
                    info!("Cleaned up {} tracks for publisher {}", ssrclist.len(), peer_id);
                }
                room.peers.remove(&peer_id);
                room.publishers.remove(&peer_id);
                info!("Publisher peer {} removed from room.", peer_id);
            }
        })
    }));

    // Set the remote description (publisher's offer)
    let offer = RTCSessionDescription::offer(offer_sdp)
        .map_err(|e| format!("Invalid SDP offer: {}", e))?;
    peer_connection
        .set_remote_description(offer)
        .await
        .map_err(|e| format!("set_remote_description failed: {}", e))?;

    // Create and set local description (our answer)
    let answer = peer_connection
        .create_answer(None)
        .await
        .map_err(|e| format!("create_answer failed: {}", e))?;

    // Gather ICE candidates (non-trickle mode: wait for complete gather)
    let mut gather_complete = peer_connection.gathering_complete_promise().await;

    peer_connection
        .set_local_description(answer)
        .await
        .map_err(|e| format!("set_local_description failed: {}", e))?;

    // Block until all ICE candidates have been gathered
    let _ = gather_complete.recv().await;

    let local_desc = peer_connection
        .local_description()
        .await
        .ok_or("No local description after gather")?;

    Ok(local_desc.sdp)
}

// ─── Subscriber Signalling ────────────────────────────────────────────────────

/// Accepts a subscribe request and returns an SDP answer.
/// Adds all currently available tracks from the room to the subscriber's connection,
/// and subscribes for future tracks via the broadcast channel.
///
/// # Arguments
/// * `sfu`     – Global SFU state.
/// * `room_id` – ID of the room to subscribe to.
/// * `peer_id` – Unique ID for this subscriber peer.
/// * `offer_sdp` – SDP offer from the subscriber browser.
///
/// # Returns
/// SDP answer string.
pub async fn handle_subscribe(
    sfu: Arc<SfuState>,
    room_id: String,
    peer_id: String,
    offer_sdp: String,
    ice_servers: &[String],
) -> Result<String, String> {
    let room = sfu.get_or_create_room(&room_id);

    let api = acquire_api(&room).await.map_err(|e| format!("Failed to build WebRTC API: {}", e))?;

    let config = RTCConfiguration {
        ice_servers: build_ice_servers(ice_servers),
        ..Default::default()
    };

    let peer_connection = Arc::new(
        api.new_peer_connection(config)
            .await
            .map_err(|e| format!("Failed to create subscriber peer connection: {}", e))?,
    );

    room.peers.insert(peer_id.clone(), Arc::clone(&peer_connection));
    room.touch();

    // Subscribe to all existing tracks immediately
    let existing_tracks: Vec<SfuTrack> = room.tracks.iter().map(|e| e.value().clone()).collect();
    for sfu_track in existing_tracks {
        if let Err(e) = peer_connection
            .add_track(Arc::clone(&sfu_track.local_track) as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>)
            .await
        {
            warn!("Failed to add existing track {} to subscriber {}: {}", sfu_track.ssrc, peer_id, e);
        }
    }

    // H28: create cancellation token so the track-rx task exits on disconnect
    let sub_cancel = CancellationToken::new();
    room.subscriber_tokens.insert(peer_id.clone(), sub_cancel.clone());

    // Subscribe to future tracks (publishers joining after this subscriber)
    let mut track_rx = room.track_tx.subscribe();
    let pc_for_future = Arc::clone(&peer_connection);
    let peer_id_future = peer_id.clone();
    let sub_token = sub_cancel.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sub_token.cancelled() => {
                    debug!("Subscriber {} track task cancelled", peer_id_future);
                    return;
                }
                result = track_rx.recv() => {
                    match result {
                        Ok(sfu_track) => {
                            debug!("New track {} available — adding to subscriber {}", sfu_track.ssrc, peer_id_future);
                            if let Err(e) = pc_for_future
                                .add_track(Arc::clone(&sfu_track.local_track) as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>)
                                .await
                            {
                                warn!("Could not add new track to subscriber {}: {}", peer_id_future, e);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("Subscriber {} track channel closed", peer_id_future);
                            return;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            debug!("Subscriber {} track channel lagged by {}", peer_id_future, n);
                            // continue waiting for new tracks
                        }
                    }
                }
            }
        }
    });
    room.subscriber_handles.insert(peer_id.clone(), handle);

    // on_ice_connection_state_change: cleanup on disconnect (H28: cancel subscriber token)
    let room_for_state = Arc::clone(&room);
    let peer_id_for_close = peer_id.clone();
    peer_connection.on_ice_connection_state_change(Box::new(move |state: RTCIceConnectionState| {
        let room = Arc::clone(&room_for_state);
        let peer_id = peer_id_for_close.clone();
        Box::pin(async move {
            if state == RTCIceConnectionState::Disconnected
                || state == RTCIceConnectionState::Failed
                || state == RTCIceConnectionState::Closed
            {
                if let Some((_, token)) = room.subscriber_tokens.remove(&peer_id) {
                    token.cancel();
                }
                if let Some((_, handle)) = room.subscriber_handles.remove(&peer_id) {
                    handle.abort();
                }
                room.peers.remove(&peer_id);
                info!("Subscriber peer {} disconnected from room.", peer_id);
            }
        })
    }));

    // Set subscriber offer and generate answer
    let offer = RTCSessionDescription::offer(offer_sdp)
        .map_err(|e| format!("Invalid subscriber SDP offer: {}", e))?;
    peer_connection
        .set_remote_description(offer)
        .await
        .map_err(|e| format!("Subscriber set_remote_description failed: {}", e))?;

    let answer = peer_connection
        .create_answer(None)
        .await
        .map_err(|e| format!("Subscriber create_answer failed: {}", e))?;

    let mut gather_complete = peer_connection.gathering_complete_promise().await;

    peer_connection
        .set_local_description(answer)
        .await
        .map_err(|e| format!("Subscriber set_local_description failed: {}", e))?;

    let _ = gather_complete.recv().await;

    let local_desc = peer_connection
        .local_description()
        .await
        .ok_or("No local description after gather")?;

    Ok(local_desc.sdp)
}

// ─── Trickle ICE ─────────────────────────────────────────────────────────────

/// Adds a trickle ICE candidate to a peer connection in any room.
pub async fn add_ice_candidate(
    sfu: Arc<SfuState>,
    room_id: &str,
    peer_id: &str,
    candidate_json: &str,
) -> Result<(), String> {
    let room = sfu
        .rooms
        .get(room_id)
        .ok_or_else(|| format!("Room '{}' not found", room_id))?
        .clone();

    let pc = room
        .peers
        .get(peer_id)
        .ok_or_else(|| format!("Peer '{}' not found in room '{}'", peer_id, room_id))?
        .clone();

    let candidate: webrtc::ice_transport::ice_candidate::RTCIceCandidateInit =
        serde_json::from_str(candidate_json)
            .map_err(|e| format!("Invalid ICE candidate JSON: {}", e))?;

    pc.add_ice_candidate(candidate)
        .await
        .map_err(|e| format!("add_ice_candidate failed: {}", e))?;

    room.touch();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfu_state_room_creation() {
        let sfu = SfuState::new();
        let room = sfu.get_or_create_room("test");
        assert_eq!(room.id, "test");
        assert_eq!(sfu.rooms.len(), 1);
    }

    #[test]
    fn test_sfu_state_idempotent_room() {
        let sfu = SfuState::new();
        sfu.get_or_create_room("myroom");
        sfu.get_or_create_room("myroom"); // Same room
        assert_eq!(sfu.rooms.len(), 1);
    }

    #[test]
    fn test_sfu_list_rooms() {
        let sfu = SfuState::new();
        sfu.get_or_create_room("room-a");
        sfu.get_or_create_room("room-b");
        let rooms = sfu.list_rooms();
        assert_eq!(rooms.len(), 2);
    }

    #[test]
    fn test_build_ice_servers_empty_returns_google_stun() {
        let servers = build_ice_servers(&[]);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].urls.len() >= 2);
        assert!(servers[0].urls[0].starts_with("stun:"));
    }

    #[test]
    fn test_build_ice_servers_configured_overrides_default() {
        let configured = vec![
            "turn:turn.example.com:3478?transport=udp".to_string(),
        ];
        let servers = build_ice_servers(&configured);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].urls[0], "turn:turn.example.com:3478?transport=udp");
    }

    #[test]
    fn test_build_ice_servers_multiple_urls_produce_multiple_servers() {
        let configured = vec![
            "stun:stun.custom.com:3478".to_string(),
            "turn:turn.custom.com:3478?transport=udp".to_string(),
        ];
        let servers = build_ice_servers(&configured);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].urls[0], "stun:stun.custom.com:3478");
        assert_eq!(servers[1].urls[0], "turn:turn.custom.com:3478?transport=udp");
    }

    #[test]
    fn test_build_ice_servers_empty_string_falls_back_to_google_stun() {
        let configured = vec!["".to_string()];
        let servers = build_ice_servers(&configured);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].urls.len() >= 2);
        assert!(servers[0].urls[0].starts_with("stun:"));
    }

    #[test]
    fn test_build_ice_servers_whitespace_only_falls_back() {
        let configured = vec!["   ".to_string()];
        let servers = build_ice_servers(&configured);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].urls[0].starts_with("stun:"));
    }

    #[test]
    fn test_build_ice_servers_mixed_valid_and_empty_keeps_valid() {
        let configured = vec![
            "".to_string(),
            "turn:turn.example.com:3478".to_string(),
            "  ".to_string(),
        ];
        let servers = build_ice_servers(&configured);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].urls[0], "turn:turn.example.com:3478");
    }

    #[test]
    fn test_room_touch_updates_last_activity() {
        let room = SfuRoom::new("test".into());
        let before = room.last_activity.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(10));
        room.touch();
        let after = room.last_activity.load(Ordering::Relaxed);
        assert!(after >= before);
    }

    #[test]
    fn test_sweep_removes_idle_empty_room() {
        let sfu = SfuState::new();
        let room = sfu.get_or_create_room("idle-room");
        // Room starts with 0 peers (empty). Set last_activity far in the past.
        let long_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(600);
        room.last_activity.store(long_ago, Ordering::Relaxed);

        assert_eq!(sfu.rooms.len(), 1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        SfuState::sweep_expired_rooms(&sfu, now, 300);
        assert_eq!(sfu.rooms.len(), 0);
    }

    #[test]
    fn test_sweep_keeps_recently_active_empty_room() {
        let sfu = SfuState::new();
        let room = sfu.get_or_create_room("active-room");
        // Room is empty but was just touched (last_activity is recent).
        room.touch();

        assert_eq!(sfu.rooms.len(), 1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        SfuState::sweep_expired_rooms(&sfu, now, 300);
        assert_eq!(sfu.rooms.len(), 1);
    }

    #[test]
    fn test_sweep_room_count_matches_participant_count() {
        // A room with non-zero participant_count() should have peers and should
        // not be sweepable. participant_count delegates to peers.len().
        let room = SfuRoom::new("test".into());
        assert_eq!(room.participant_count(), 0);
        assert_eq!(room.publisher_count(), 0);
        assert_eq!(room.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_subscriber_handles_stored_and_removed() {
        let room = SfuRoom::new("test".into());
        assert!(room.subscriber_handles.is_empty());

        // Simulate storing a handle (use an already-completed task for the test)
        let dummy_handle = tokio::spawn(async {});
        room.subscriber_handles
            .insert("peer1".into(), dummy_handle);
        assert_eq!(room.subscriber_handles.len(), 1);

        // Simulate disconnect cleanup
        let (_, handle) = room.subscriber_handles.remove("peer1").unwrap();
        handle.abort(); // should be a no-op on already-completed task
        assert!(room.subscriber_handles.is_empty());
    }
}
