//! # PROXY Protocol v2 Parser
//!
//! Implements binary parsing of the PROXY Protocol v2 header as defined by
//! HAProxy's specification: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!
//! The v2 header is recognised by the 12-byte magic signature followed by a
//! fixed 4-byte control block and a variable-length address section.
//!
//! ## Integration
//! Call `parse_v2_header` on the first bytes of an accepted TCP connection.
//! If the magic is present, the parsed `ProxyProtoV2` struct carries the real
//! client address which should be used in lieu of `peer_addr`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ─── Constants ────────────────────────────────────────────────────────────────

/// The 12-byte magic that identifies a PROXY Protocol v2 header.
const PP2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// Minimum header length (signature + 4 fixed bytes).
const PP2_HEADER_LEN: usize = 16;

// ─── Types ────────────────────────────────────────────────────────────────────

/// Address family of the proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec,
    Ipv4,
    Ipv6,
    Unix,
}

/// Transport protocol of the proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Unspec,
    Stream, // TCP
    Dgram,  // UDP
}

/// The parsed PROXY Protocol v2 header.
#[derive(Debug, Clone)]
pub struct ProxyProtoV2 {
    pub address_family: AddressFamily,
    pub transport: TransportProtocol,
    /// Real source address. `None` for `UNSPEC` or `UNIX` family.
    pub src_addr: Option<SocketAddr>,
    /// Real destination address. `None` for `UNSPEC` or `UNIX` family.
    pub dst_addr: Option<SocketAddr>,
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The buffer is too short to contain a complete header.
    TooShort,
    /// The 12-byte magic does not match — this is not a PP v2 header.
    NotProxyProtocol,
    /// The version nibble is not 2.
    UnsupportedVersion(u8),
    /// The address-family or transport-protocol nibbles are unknown/reserved.
    UnknownAddressFamily(u8),
    /// The address block is shorter than required for the declared family.
    AddressDataTooShort,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::NotProxyProtocol => write!(f, "magic mismatch — not PROXY protocol v2"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {}", v),
            Self::UnknownAddressFamily(b) => write!(f, "unknown address family byte 0x{:02x}", b),
            Self::AddressDataTooShort => write!(f, "address data too short for declared family"),
        }
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse a PROXY Protocol v2 header from `buf`.
///
/// Returns the parsed header **and** the number of bytes consumed from `buf`
/// so the caller can advance the read cursor past the header.
///
/// # Errors
/// Returns `ParseError::NotProxyProtocol` if the first 12 bytes don't match
/// the magic — the caller should treat the data as regular traffic in that case.
pub fn parse_v2_header(buf: &[u8]) -> Result<(ProxyProtoV2, usize), ParseError> {
    if buf.len() < PP2_HEADER_LEN {
        return Err(ParseError::TooShort);
    }

    // 1. Magic check
    if &buf[..12] != PP2_SIGNATURE {
        return Err(ParseError::NotProxyProtocol);
    }

    // 2. Version + Command byte  (byte 12)
    let ver_cmd = buf[12];
    let version = (ver_cmd >> 4) & 0x0F;
    if version != 2 {
        return Err(ParseError::UnsupportedVersion(version));
    }
    // command: 0x0 = LOCAL, 0x1 = PROXY  (we accept both but only extract addrs for PROXY)
    let command = ver_cmd & 0x0F;

    // 3. Address family + transport byte (byte 13)
    let fam_byte = buf[13];
    let af_nibble = (fam_byte >> 4) & 0x0F;
    let tp_nibble = fam_byte & 0x0F;

    let address_family = match af_nibble {
        0x0 => AddressFamily::Unspec,
        0x1 => AddressFamily::Ipv4,
        0x2 => AddressFamily::Ipv6,
        0x3 => AddressFamily::Unix,
        other => return Err(ParseError::UnknownAddressFamily(other)),
    };

    let transport = match tp_nibble {
        0x0 => TransportProtocol::Unspec,
        0x1 => TransportProtocol::Stream,
        0x2 => TransportProtocol::Dgram,
        // Treat unknown transport as Unspec rather than hard-error
        _ => TransportProtocol::Unspec,
    };

    // 4. Remaining length (bytes 14-15, big-endian)
    let remaining_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total_len = PP2_HEADER_LEN + remaining_len;
    if buf.len() < total_len {
        return Err(ParseError::TooShort);
    }

    let addr_data = &buf[PP2_HEADER_LEN..total_len];

    // 5. Decode addresses (only for PROXY command = 0x1 and known families)
    let (src_addr, dst_addr) = if command == 0x1 {
        decode_addresses(address_family, addr_data)?
    } else {
        (None, None)
    };

    Ok((
        ProxyProtoV2 {
            address_family,
            transport,
            src_addr,
            dst_addr,
        },
        total_len,
    ))
}

/// Decode source and destination addresses from the address data block.
fn decode_addresses(
    family: AddressFamily,
    data: &[u8],
) -> Result<(Option<SocketAddr>, Option<SocketAddr>), ParseError> {
    match family {
        // AF_UNSPEC — no address information
        AddressFamily::Unspec => Ok((None, None)),

        // AF_INET — 4+4+2+2 = 12 bytes (src_ip, dst_ip, src_port, dst_port)
        AddressFamily::Ipv4 => {
            if data.len() < 12 {
                return Err(ParseError::AddressDataTooShort);
            }
            let src_ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let dst_ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let src_port = u16::from_be_bytes([data[8], data[9]]);
            let dst_port = u16::from_be_bytes([data[10], data[11]]);
            Ok((
                Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)),
                Some(SocketAddr::new(IpAddr::V4(dst_ip), dst_port)),
            ))
        }

        // AF_INET6 — 16+16+2+2 = 36 bytes
        AddressFamily::Ipv6 => {
            if data.len() < 36 {
                return Err(ParseError::AddressDataTooShort);
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[0..16]).unwrap());
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[16..32]).unwrap());
            let src_port = u16::from_be_bytes([data[32], data[33]]);
            let dst_port = u16::from_be_bytes([data[34], data[35]]);
            Ok((
                Some(SocketAddr::new(IpAddr::V6(src_ip), src_port)),
                Some(SocketAddr::new(IpAddr::V6(dst_ip), dst_port)),
            ))
        }

        // AF_UNIX — 108+108 bytes of path; no port — we return None (no SocketAddr)
        AddressFamily::Unix => Ok((None, None)),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PP v2 packet for IPv4 PROXY command.
    fn ipv4_packet(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x21); // version=2 (0x2), command=PROXY (0x1)
        buf.push(0x11); // AF_INET (0x1), STREAM (0x1)
        buf.extend_from_slice(&12u16.to_be_bytes()); // remaining_len = 12
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf
    }

    fn ipv6_packet(
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x21); // version=2, PROXY
        buf.push(0x21); // AF_INET6 (0x2), STREAM (0x1)
        buf.extend_from_slice(&36u16.to_be_bytes()); // remaining_len = 36
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf
    }

    #[test]
    fn test_bad_magic() {
        let buf = b"GET / HTTP/1.1\r\n";
        assert_eq!(
            parse_v2_header(buf).unwrap_err(),
            ParseError::NotProxyProtocol
        );
    }

    #[test]
    fn test_too_short() {
        assert_eq!(
            parse_v2_header(b"\r\n\r\n\x00").unwrap_err(),
            ParseError::TooShort
        );
    }

    #[test]
    fn test_ipv4_proxy_command() {
        let pkt = ipv4_packet([1, 2, 3, 4], [5, 6, 7, 8], 1234, 80);
        let (hdr, consumed) = parse_v2_header(&pkt).unwrap();
        assert_eq!(consumed, pkt.len());
        assert_eq!(hdr.address_family, AddressFamily::Ipv4);
        assert_eq!(hdr.transport, TransportProtocol::Stream);
        let src = hdr.src_addr.unwrap();
        assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(src.port(), 1234);
        let dst = hdr.dst_addr.unwrap();
        assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(dst.port(), 80);
    }

    #[test]
    fn test_ipv6_proxy_command() {
        let src6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        let dst6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2u8];
        let pkt = ipv6_packet(src6, dst6, 4321, 443);
        let (hdr, consumed) = parse_v2_header(&pkt).unwrap();
        assert_eq!(consumed, pkt.len());
        assert_eq!(hdr.address_family, AddressFamily::Ipv6);
        let src = hdr.src_addr.unwrap();
        assert_eq!(src.port(), 4321);
        let dst = hdr.dst_addr.unwrap();
        assert_eq!(dst.port(), 443);
    }

    #[test]
    fn test_local_command_no_addresses() {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x20); // version=2, LOCAL (0x0)
        buf.push(0x00); // AF_UNSPEC, UNSPEC
        buf.extend_from_slice(&0u16.to_be_bytes()); // no address data
        let (hdr, _) = parse_v2_header(&buf).unwrap();
        assert!(hdr.src_addr.is_none());
        assert!(hdr.dst_addr.is_none());
    }

    #[test]
    fn test_unspec_family() {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x21); // version=2, PROXY
        buf.push(0x00); // AF_UNSPEC, UNSPEC
        buf.extend_from_slice(&0u16.to_be_bytes());
        let (hdr, _) = parse_v2_header(&buf).unwrap();
        assert_eq!(hdr.address_family, AddressFamily::Unspec);
        assert!(hdr.src_addr.is_none());
    }

    #[test]
    fn test_ipv4_data_too_short() {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x21); // version=2, PROXY
        buf.push(0x11); // AF_INET, STREAM
        buf.extend_from_slice(&4u16.to_be_bytes()); // only 4 bytes (need 12)
        buf.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            parse_v2_header(&buf).unwrap_err(),
            ParseError::AddressDataTooShort
        );
    }

    #[test]
    fn test_unsupported_version() {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x11); // version=1 (unsupported), command=PROXY
        buf.push(0x11);
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            parse_v2_header(&buf).unwrap_err(),
            ParseError::UnsupportedVersion(1)
        );
    }

    #[test]
    fn test_unix_family_returns_no_socketaddr() {
        let mut buf = PP2_SIGNATURE.to_vec();
        buf.push(0x21); // version=2, PROXY
        buf.push(0x31); // AF_UNIX (0x3), STREAM
        buf.extend_from_slice(&216u16.to_be_bytes()); // 108+108
        buf.extend(std::iter::repeat(0u8).take(216));
        let (hdr, _) = parse_v2_header(&buf).unwrap();
        assert_eq!(hdr.address_family, AddressFamily::Unix);
        assert!(hdr.src_addr.is_none());
        assert!(hdr.dst_addr.is_none());
    }
}
