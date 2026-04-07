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
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
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
}

impl SfuRoom {
    /// Creates a new room with the given ID and an empty track/peer set.
    /// The returned `Arc<SfuRoom>` is shared among all signalling handlers.
    pub fn new(id: String) -> Arc<Self> {
        let (track_tx, _) = broadcast::channel(64);
        Arc::new(Self {
            id,
            tracks: DashMap::new(),
            track_tx,
            peers: DashMap::new(),
            bytes_forwarded: Arc::new(AtomicU64::new(0)),
            packets_forwarded: Arc::new(AtomicU64::new(0)),
            publishers: DashMap::new(),
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

/// Default ICE server list (STUN only — add TURN as needed)
fn default_ice_servers() -> Vec<RTCIceServer> {
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
) -> Result<String, String> {
    let room = sfu.get_or_create_room(&room_id);

    let api = build_webrtc_api().map_err(|e| format!("Failed to build WebRTC API: {}", e))?;

    let config = RTCConfiguration {
        ice_servers: default_ice_servers(),
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

    // Clone room for the on_track callback
    let room_for_track = Arc::clone(&room);
    let peer_id_for_close = peer_id.clone();

    // on_track: called when the publisher sends a media track
    peer_connection.on_track(Box::new(
        move |track: Arc<TrackRemote>, _receiver: Arc<RTCRtpReceiver>, _transceiver: Arc<RTCRtpTransceiver>| {
            let room = Arc::clone(&room_for_track);

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

                // Broadcast to any subscribers waiting for tracks
                if let Err(e) = room.track_tx.send(sfu_track) {
                    debug!("No active subscribers waiting for track {}: {}", ssrc, e);
                }

                // Forward RTP packets from publisher to the local_track
                let mut rtp_buf = vec![0u8; 1500];
                loop {
                    match track.read(&mut rtp_buf).await {
                        Ok((packet, _attr)) => {
                            // Estimate size: 12-byte fixed RTP header + payload
                            let pkt_len = (packet.payload.len() as u64) + 12;
                            // Write the buffer content - the packet's payload is stored in rtp_buf
                            if let Err(e) = local_track.write(&rtp_buf).await {
                                debug!("RTP write to local track failed (ssrc={}): {}", ssrc, e);
                            } else {
                                room.bytes_forwarded.fetch_add(pkt_len, Ordering::Relaxed);
                                room.packets_forwarded.fetch_add(1, Ordering::Relaxed);
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
) -> Result<String, String> {
    let room = sfu.get_or_create_room(&room_id);

    let api = build_webrtc_api().map_err(|e| format!("Failed to build WebRTC API: {}", e))?;

    let config = RTCConfiguration {
        ice_servers: default_ice_servers(),
        ..Default::default()
    };

    let peer_connection = Arc::new(
        api.new_peer_connection(config)
            .await
            .map_err(|e| format!("Failed to create subscriber peer connection: {}", e))?,
    );

    room.peers.insert(peer_id.clone(), Arc::clone(&peer_connection));

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

    // Subscribe to future tracks (publishers joining after this subscriber)
    let mut track_rx = room.track_tx.subscribe();
    let pc_for_future = Arc::clone(&peer_connection);
    let peer_id_future = peer_id.clone();
    tokio::spawn(async move {
        while let Ok(sfu_track) = track_rx.recv().await {
            debug!("New track {} available — adding to subscriber {}", sfu_track.ssrc, peer_id_future);
            if let Err(e) = pc_for_future
                .add_track(Arc::clone(&sfu_track.local_track) as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>)
                .await
            {
                warn!("Could not add new track to subscriber {}: {}", peer_id_future, e);
            }
        }
    });

    // on_ice_connection_state_change: cleanup on disconnect
    let room_for_state = Arc::clone(&room);
    let peer_id_for_close = peer_id.clone();
    peer_connection.on_ice_connection_state_change(Box::new(move |state: RTCIceConnectionState| {
        let room = Arc::clone(&room_for_state);
        let peer_id = peer_id_for_close.clone();
        Box::pin(async move {
            if state == RTCIceConnectionState::Disconnected || state == RTCIceConnectionState::Failed {
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
}
