use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::debug;

/// Trusted proxy CIDR ranges.
/// Connections from these CIDRs are allowed to set the real client IP via
/// `X-Forwarded-For`, `X-Real-IP`, or the PROXY protocol.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    cidrs: Vec<CidrRange>,
}

#[derive(Debug, Clone)]
struct CidrRange {
    network: IpAddr,
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

    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }
}

impl CidrRange {
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

/// Determines the real client IP from request headers, respecting trusted proxies.
///
/// Priority: `X-Real-IP` > `X-Forwarded-For` (rightmost untrusted) > socket address.
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
        debug!("Real IP from X-Real-IP: {}", real_ip);
        return real_ip;
    }

    // 2. X-Forwarded-For — walk from right to find the first non-trusted IP
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let addrs: Vec<&str> = xff.split(',').map(str::trim).collect();
        // Walk from the right (closest to us) and skip trusted proxies
        for addr_str in addrs.iter().rev() {
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                if !trusted.is_trusted(&ip) {
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
    headers.insert(
        hyper::header::HeaderName::from_static("x-forwarded-proto"),
        proto.parse().unwrap(),
    );
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
}
