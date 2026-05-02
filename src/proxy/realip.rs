//! Real client IP resolution and forwarding header injection.
//!
//! When Phalanx sits behind one or more reverse proxies (e.g. a CDN or cloud
//! load balancer), the TCP peer address is that of the proxy, not the real
//! client. This module extracts the true client IP from `X-Real-IP` or
//! `X-Forwarded-For` headers, but only when the direct connection originates
//! from a trusted proxy CIDR.
//!
//! Additionally provides:
//! - `inject_forwarding_headers` to set standard `X-Forwarded-For`,
//!   `X-Forwarded-Proto`, and `X-Real-IP` on outbound backend requests.
//! - `parse_proxy_protocol_v1` for HAProxy PROXY protocol v1 header parsing.

use std::net::{IpAddr, SocketAddr};
use tracing::debug;

/// Trusted proxy CIDR ranges.
/// Connections from these CIDRs are allowed to set the real client IP via
/// `X-Forwarded-For`, `X-Real-IP`, or the PROXY protocol.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    cidrs: Vec<CidrRange>,
}

/// A single CIDR range (e.g. `10.0.0.0/8` or `::1/128`).
#[derive(Debug, Clone)]
struct CidrRange {
    /// Base network address.
    network: IpAddr,
    /// Number of significant bits in the network mask (0..=32 for IPv4, 0..=128 for IPv6).
    prefix_len: u8,
}

impl TrustedProxies {
    /// Parses a list of CIDR strings (e.g. `["10.0.0.0/8", "172.16.0.0/12"]`).
    /// Falls back to treating a bare IP as a /32 or /128.
    pub fn from_cidrs(cidrs: &[String]) -> Self {
        let mut parsed = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            if let Some(cr) = CidrRange::parse(cidr) {
                parsed.push(cr);
            } else {
                tracing::warn!("Invalid trusted proxy CIDR: {}", cidr);
            }
        }
        Self { cidrs: parsed }
    }

    /// Returns `true` if `ip` falls within any of the configured trusted CIDR ranges.
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    /// Returns `true` if no trusted CIDRs were configured (forwarding headers are never trusted).
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }
}

impl CidrRange {
    /// Parses a CIDR string like `"10.0.0.0/8"` or a bare IP like `"192.168.1.1"`.
    /// A bare IP is treated as a `/32` (IPv4) or `/128` (IPv6) single-host range.
    fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = if let Some(pos) = s.find('/') {
            (&s[..pos], &s[pos + 1..])
        } else {
            return s.parse::<IpAddr>().ok().map(|ip| CidrRange {
                network: ip,
                prefix_len: if ip.is_ipv4() { 32 } else { 128 },
            });
        };
        let network: IpAddr = addr_str.parse().ok()?;
        let prefix_len: u8 = prefix_str.parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return None;
        }
        Some(CidrRange {
            network,
            prefix_len,
        })
    }

    /// Tests whether `ip` falls within this CIDR range using bitwise masking.
    /// Returns `false` if the address families (v4 vs v6) don't match.
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_bits = u32::from(net);
                let target_bits = u32::from(*target);
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (net_bits & mask) == (target_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let net_bits = u128::from(net);
                let target_bits = u128::from(*target);
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix_len);
                (net_bits & mask) == (target_bits & mask)
            }
            _ => false,
        }
    }
}

/// Returns `true` if the IP is unsuitable as a real client address.
/// Rejects loopback, multicast, unspecified (0.0.0.0 / ::), and broadcast
/// (255.255.255.255) addresses that a misconfigured or malicious proxy
/// might inject into forwarding headers.
fn is_bogus_ip(ip: &IpAddr) -> bool {
    ip.is_loopback() || ip.is_multicast() || ip.is_unspecified()
        || *ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

/// Determines the real client IP from request headers, respecting trusted proxies.
///
/// Priority: `X-Real-IP` > `X-Forwarded-For` (rightmost untrusted) > socket address.
/// Bogus IPs (loopback, multicast, unspecified, broadcast) are silently skipped
/// when encountered in forwarding headers.
pub fn resolve_client_ip(
    peer: &SocketAddr,
    headers: &hyper::HeaderMap,
    trusted: &TrustedProxies,
) -> IpAddr {
    let socket_ip = peer.ip();

    // Only inspect forwarding headers if the direct connection is from a trusted proxy
    if !trusted.is_trusted(&socket_ip) {
        return socket_ip;
    }

    // 1. X-Real-IP (single value, highest priority)
    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        if !is_bogus_ip(&real_ip) {
            debug!("Real IP from X-Real-IP: {}", real_ip);
            return real_ip;
        }
        debug!("Ignoring bogus X-Real-IP: {}", real_ip);
    }

    // 2. X-Forwarded-For — walk from right to find the first non-trusted IP.
    // Cap the number of parsed hops to prevent resource exhaustion from
    // maliciously long XFF chains.
    const MAX_XFF_HOPS: usize = 20;
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let addrs: Vec<&str> = xff.split(',').map(str::trim).take(MAX_XFF_HOPS).collect();
        // Walk from the right (closest to us) and skip trusted proxies
        for addr_str in addrs.iter().rev() {
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                if !is_bogus_ip(&ip) && !trusted.is_trusted(&ip) {
                    debug!("Real IP from X-Forwarded-For: {}", ip);
                    return ip;
                }
            }
        }
        // All addresses in XFF are trusted — use leftmost
        if let Some(first) = addrs.first().and_then(|s| s.parse::<IpAddr>().ok()) {
            return first;
        }
    }

    socket_ip
}

/// Injects standard proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`)
/// into the outgoing request to the backend.
pub fn inject_forwarding_headers(
    headers: &mut hyper::HeaderMap,
    client_ip: &IpAddr,
    is_tls: bool,
) {
    let ip_str = client_ip.to_string();

    // X-Forwarded-For: append to existing or create new
    let existing_xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let new_xff = match existing_xff {
        Some(existing) => format!("{}, {}", existing, ip_str),
        None => ip_str.clone(),
    };

    if let Ok(val) = new_xff.parse() {
        headers.insert(
            hyper::header::HeaderName::from_static("x-forwarded-for"),
            val,
        );
    }

    // X-Real-IP
    if let Ok(val) = ip_str.parse() {
        headers.insert(
            hyper::header::HeaderName::from_static("x-real-ip"),
            val,
        );
    }

    // X-Forwarded-Proto
    let proto = if is_tls { "https" } else { "http" };
    if let Ok(val) = proto.parse() {
        headers.insert(
            hyper::header::HeaderName::from_static("x-forwarded-proto"),
            val,
        );
    }
}

/// Parses the HAProxy PROXY protocol v1 header from a byte buffer.
/// Returns `(client_addr, remaining_bytes_offset)` if successful.
pub fn parse_proxy_protocol_v1(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let header_end = buf.windows(2).position(|w| w == b"\r\n")?;
    let header_str = std::str::from_utf8(&buf[..header_end]).ok()?;

    if !header_str.starts_with("PROXY ") {
        return None;
    }

    let parts: Vec<&str> = header_str.split_whitespace().collect();
    // PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>
    if parts.len() < 6 {
        return None;
    }

    let src_ip: IpAddr = parts[2].parse().ok()?;
    let src_port: u16 = parts[4].parse().ok()?;

    Some((SocketAddr::new(src_ip, src_port), header_end + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_contains_ipv4() {
        let tp = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        assert!(tp.is_trusted(&"10.1.2.3".parse().unwrap()));
        assert!(!tp.is_trusted(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_single_ip() {
        let tp = TrustedProxies::from_cidrs(&["192.168.1.1".to_string()]);
        assert!(tp.is_trusted(&"192.168.1.1".parse().unwrap()));
        assert!(!tp.is_trusted(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_trusted_xff() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.2".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_client_ip_untrusted_peer() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "203.0.113.1:12345".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_proxy_protocol_v1() {
        let header = b"PROXY TCP4 203.0.113.50 10.0.0.1 56789 80\r\nGET / HTTP/1.1\r\n";
        let (addr, offset) = parse_proxy_protocol_v1(header).unwrap();
        assert_eq!(addr.ip(), "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 56789);
        assert!(offset > 0);
    }

    #[test]
    fn test_inject_forwarding_headers_no_panics() {
        let mut headers = hyper::HeaderMap::new();
        let client_ip: IpAddr = "203.0.113.50".parse().unwrap();
        // Should not panic — proto.parse() is fallible but values are hardcoded
        inject_forwarding_headers(&mut headers, &client_ip, true);
        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "https"
        );
        inject_forwarding_headers(&mut headers, &client_ip, false);
        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "http"
        );
    }

    #[test]
    fn test_resolve_client_ip_rejects_loopback() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        // X-Real-IP set to 127.0.0.1 — should be skipped
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        // Falls back to socket addr since 127.0.0.1 is bogus
        assert_eq!(resolved, peer.ip());
    }

    #[test]
    fn test_resolve_client_ip_rejects_multicast() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "224.0.0.1".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, peer.ip());
    }

    #[test]
    fn test_resolve_client_ip_rejects_unspecified() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "0.0.0.0".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, peer.ip());
    }

    #[test]
    fn test_resolve_client_ip_rejects_broadcast() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "255.255.255.255".parse().unwrap());
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, peer.ip());
    }

    #[test]
    fn test_resolve_client_ip_xff_skips_bogus() {
        let trusted = TrustedProxies::from_cidrs(&["10.0.0.0/8".to_string()]);
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        // XFF chain: real client, loopback proxy, trusted proxy
        // The loopback should be skipped, returning the real client
        headers.insert(
            "x-forwarded-for",
            "203.0.113.50, 127.0.0.1, 10.0.0.2".parse().unwrap(),
        );
        let resolved = resolve_client_ip(&peer, &headers, &trusted);
        assert_eq!(resolved, "203.0.113.50".parse::<IpAddr>().unwrap());
    }
}
