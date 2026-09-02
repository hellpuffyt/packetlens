//! Protocol decoding: Ethernet II -> IPv4/IPv6 -> TCP/UDP/ICMP.

use crate::checksum;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug)]
pub enum DecodeError {
    TooShort {
        layer: &'static str,
        needed: usize,
        available: usize,
    },
    UnsupportedEthertype(u16),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort {
                layer,
                needed,
                available,
            } => {
                write!(
                    f,
                    "{layer} header truncated: needed {needed} bytes, had {available}"
                )
            }
            DecodeError::UnsupportedEthertype(et) => write!(f, "unsupported ethertype 0x{et:04x}"),
        }
    }
}
impl std::error::Error for DecodeError {}

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    /// 802.1Q VLAN tag, if one was present between the addresses and the
    /// real ethertype.
    pub vlan_tag: Option<u16>,
}

pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub checksum_valid: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

#[derive(Debug, Clone)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    pub fn src(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.src),
            IpHeader::V6(h) => IpAddr::V6(h.src),
        }
    }
    pub fn dst(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.dst),
            IpHeader::V6(h) => IpAddr::V6(h.dst),
        }
    }
    pub fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.protocol,
            IpHeader::V6(h) => h.next_header,
        }
    }
}

/// Small hand-rolled bitflags so the crate stays dependency-free for the
/// core decode path.
macro_rules! bitflags_lite {
    (
        pub struct $name:ident: $repr:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub $repr);
        impl $name {
            $(pub const $flag: $name = $name($value);)*
            pub fn contains(&self, other: $name) -> bool {
                (self.0 & other.0) == other.0
            }
            pub fn bits(&self) -> $repr {
                self.0
            }
        }
        impl std::ops::BitOr for $name {
            type Output = $name;
            fn bitor(self, rhs: $name) -> $name {
                $name(self.0 | rhs.0)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let names: [(&str, $repr); 8] = [
                    ("FIN", 0b0000_0001), ("SYN", 0b0000_0010), ("RST", 0b0000_0100),
                    ("PSH", 0b0000_1000), ("ACK", 0b0001_0000), ("URG", 0b0010_0000),
                    ("ECE", 0b0100_0000), ("CWR", 0b1000_0000),
                ];
                let set: Vec<&str> = names.iter().filter(|(_, bit)| self.0 & bit == *bit).map(|(n, _)| *n).collect();
                if set.is_empty() { write!(f, "-") } else { write!(f, "{}", set.join(",")) }
            }
        }
    };
}
bitflags_lite! {
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
        const ECE = 0b0100_0000;
        const CWR = 0b1000_0000;
    }
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub checksum_valid: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub checksum_valid: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Other(u8),
    None,
}

#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub timestamp_micros: u64,
    pub captured_len: u32,
    pub original_len: u32,
    pub ethernet: EthernetHeader,
    pub ip: Option<IpHeader>,
    pub transport: Transport,
    pub payload: Vec<u8>,
}

pub fn decode_ethernet(data: &[u8]) -> Result<(EthernetHeader, &[u8]), DecodeError> {
    if data.len() < 14 {
        return Err(DecodeError::TooShort {
            layer: "ethernet",
            needed: 14,
            available: data.len(),
        });
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    let mut vlan_tag = None;
    if ethertype == ETHERTYPE_VLAN {
        if data.len() < 18 {
            return Err(DecodeError::TooShort {
                layer: "802.1q vlan tag",
                needed: 18,
                available: data.len(),
            });
        }
        vlan_tag = Some(u16::from_be_bytes([data[14], data[15]]));
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        offset = 18;
    }
    Ok((
        EthernetHeader {
            dst_mac,
            src_mac,
            ethertype,
            vlan_tag,
        },
        &data[offset..],
    ))
}

pub fn decode_ipv4(data: &[u8]) -> Result<(Ipv4Header, &[u8]), DecodeError> {
    if data.len() < 20 {
        return Err(DecodeError::TooShort {
            layer: "ipv4",
            needed: 20,
            available: data.len(),
        });
    }
    let version = data[0] >> 4;
    let ihl = data[0] & 0x0F;
    let header_len = (ihl as usize) * 4;
    if data.len() < header_len || header_len < 20 {
        return Err(DecodeError::TooShort {
            layer: "ipv4 (ihl)",
            needed: header_len,
            available: data.len(),
        });
    }
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_frag >> 13) as u8;
    let fragment_offset = flags_frag & 0x1FFF;
    let ttl = data[8];
    let protocol = data[9];
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let checksum_valid = checksum::internet_checksum(&data[..header_len]) == 0;

    let header = Ipv4Header {
        version,
        ihl,
        dscp: data[1] >> 2,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src,
        dst,
        checksum_valid,
    };
    Ok((header, &data[header_len..]))
}

pub fn decode_ipv6(data: &[u8]) -> Result<(Ipv6Header, &[u8]), DecodeError> {
    if data.len() < 40 {
        return Err(DecodeError::TooShort {
            layer: "ipv6",
            needed: 40,
            available: data.len(),
        });
    }
    let word0 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let traffic_class = ((word0 >> 20) & 0xFF) as u8;
    let flow_label = word0 & 0x000F_FFFF;
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let header = Ipv6Header {
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        src: Ipv6Addr::from(src_bytes),
        dst: Ipv6Addr::from(dst_bytes),
    };
    Ok((header, &data[40..]))
}

pub fn decode_tcp(
    data: &[u8],
    v4_pseudo: Option<(Ipv4Addr, Ipv4Addr)>,
) -> Result<(TcpHeader, &[u8]), DecodeError> {
    if data.len() < 20 {
        return Err(DecodeError::TooShort {
            layer: "tcp",
            needed: 20,
            available: data.len(),
        });
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = data[12] >> 4;
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len || header_len < 20 {
        return Err(DecodeError::TooShort {
            layer: "tcp (data offset)",
            needed: header_len,
            available: data.len(),
        });
    }
    let flags = TcpFlags(data[13]);
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

    let checksum_valid = v4_pseudo.map(|(src, dst)| {
        checksum::transport_checksum_v4(src.octets(), dst.octets(), IPPROTO_TCP, data) == 0
    });

    let header = TcpHeader {
        src_port,
        dst_port,
        sequence,
        ack_number,
        data_offset,
        flags,
        window,
        checksum,
        urgent_pointer,
        checksum_valid,
    };
    Ok((header, &data[header_len..]))
}

pub fn decode_udp(
    data: &[u8],
    v4_pseudo: Option<(Ipv4Addr, Ipv4Addr)>,
) -> Result<(UdpHeader, &[u8]), DecodeError> {
    if data.len() < 8 {
        return Err(DecodeError::TooShort {
            layer: "udp",
            needed: 8,
            available: data.len(),
        });
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);
    let payload_end = (length as usize).min(data.len()).max(8);
    let checksum_valid = if checksum == 0 {
        None // checksum optional/disabled for UDP over IPv4
    } else {
        v4_pseudo.map(|(src, dst)| {
            checksum::transport_checksum_v4(
                src.octets(),
                dst.octets(),
                IPPROTO_UDP,
                &data[..payload_end],
            ) == 0
        })
    };
    let header = UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
        checksum_valid,
    };
    Ok((header, &data[8..]))
}

pub fn decode_icmp(data: &[u8]) -> Result<(IcmpHeader, &[u8]), DecodeError> {
    if data.len() < 4 {
        return Err(DecodeError::TooShort {
            layer: "icmp",
            needed: 4,
            available: data.len(),
        });
    }
    let header = IcmpHeader {
        icmp_type: data[0],
        code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
    };
    Ok((header, &data[4..]))
}

/// Decodes a full Ethernet frame captured from a pcap file into all
/// supported layers. Best-effort: an undecodable transport layer still
/// yields the IP layer with `Transport::None`/`Other` rather than failing
/// the whole packet, since malformed or unsupported payloads are common
/// and should not stop analysis of the rest of the capture.
pub fn decode_packet(
    timestamp_micros: u64,
    captured_len: u32,
    original_len: u32,
    data: &[u8],
) -> Result<DecodedPacket, DecodeError> {
    let (ethernet, rest) = decode_ethernet(data)?;
    let mut ip = None;
    let mut transport = Transport::None;
    let mut payload: Vec<u8> = rest.to_vec();

    match ethernet.ethertype {
        ETHERTYPE_IPV4 => {
            if let Ok((hdr, ip_rest)) = decode_ipv4(rest) {
                let pseudo = Some((hdr.src, hdr.dst));
                let proto = hdr.protocol;
                transport = decode_transport(proto, ip_rest, pseudo, &mut payload);
                ip = Some(IpHeader::V4(hdr));
            }
        }
        ETHERTYPE_IPV6 => {
            if let Ok((hdr, ip_rest)) = decode_ipv6(rest) {
                let proto = hdr.next_header;
                transport = decode_transport(proto, ip_rest, None, &mut payload);
                ip = Some(IpHeader::V6(hdr));
            }
        }
        _ => {}
    }

    Ok(DecodedPacket {
        timestamp_micros,
        captured_len,
        original_len,
        ethernet,
        ip,
        transport,
        payload,
    })
}

fn decode_transport(
    proto: u8,
    data: &[u8],
    v4_pseudo: Option<(Ipv4Addr, Ipv4Addr)>,
    payload_out: &mut Vec<u8>,
) -> Transport {
    match proto {
        IPPROTO_TCP => match decode_tcp(data, v4_pseudo) {
            Ok((hdr, rest)) => {
                *payload_out = rest.to_vec();
                Transport::Tcp(hdr)
            }
            Err(_) => Transport::Other(proto),
        },
        IPPROTO_UDP => match decode_udp(data, v4_pseudo) {
            Ok((hdr, rest)) => {
                *payload_out = rest.to_vec();
                Transport::Udp(hdr)
            }
            Err(_) => Transport::Other(proto),
        },
        IPPROTO_ICMP | IPPROTO_ICMPV6 => match decode_icmp(data) {
            Ok((hdr, rest)) => {
                *payload_out = rest.to_vec();
                Transport::Icmp(hdr)
            }
            Err(_) => Transport::Other(proto),
        },
        other => {
            *payload_out = data.to_vec();
            Transport::Other(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_syn() -> Vec<u8> {
        // Ethernet header
        let mut f = Vec::new();
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // TCP header (no options, no payload) computed first for length.
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        tcp.extend_from_slice(&80u16.to_be_bytes()); // dst port
        tcp.extend_from_slice(&1000u32.to_be_bytes()); // seq
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset = 5 (20 bytes), reserved bits 0
        tcp.push(0b0000_0010); // SYN
        tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr

        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let cksum = checksum::transport_checksum_v4(src.octets(), dst.octets(), IPPROTO_TCP, &tcp);
        tcp[16] = (cksum >> 8) as u8;
        tcp[17] = (cksum & 0xFF) as u8;

        // IPv4 header
        let total_len = 20 + tcp.len();
        let mut ip = Vec::new();
        ip.push((4 << 4) | 5); // version 4, ihl 5
        ip.push(0); // dscp/ecn
        ip.extend_from_slice(&(total_len as u16).to_be_bytes());
        ip.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        ip.push(64); // ttl
        ip.push(IPPROTO_TCP);
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&dst.octets());
        let ip_cksum = checksum::internet_checksum(&ip);
        ip[10] = (ip_cksum >> 8) as u8;
        ip[11] = (ip_cksum & 0xFF) as u8;

        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        f
    }

    #[test]
    fn decodes_ethernet_ipv4_tcp_syn_with_valid_checksums() {
        let frame = build_ipv4_tcp_syn();
        let pkt = decode_packet(0, frame.len() as u32, frame.len() as u32, &frame).unwrap();
        assert_eq!(pkt.ethernet.ethertype, ETHERTYPE_IPV4);
        assert_eq!(format_mac(pkt.ethernet.src_mac), "aa:bb:cc:dd:ee:ff");
        let ip = match pkt.ip.unwrap() {
            IpHeader::V4(h) => h,
            _ => panic!("expected ipv4"),
        };
        assert!(ip.checksum_valid);
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 0, 2));
        match pkt.transport {
            Transport::Tcp(tcp) => {
                assert_eq!(tcp.src_port, 12345);
                assert_eq!(tcp.dst_port, 80);
                assert!(tcp.flags.contains(TcpFlags::SYN));
                assert!(!tcp.flags.contains(TcpFlags::ACK));
                assert_eq!(tcp.checksum_valid, Some(true));
            }
            _ => panic!("expected tcp"),
        }
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn detects_corrupted_ip_checksum() {
        let mut frame = build_ipv4_tcp_syn();
        // Flip a byte inside the IPv4 header (TTL field) without fixing the
        // checksum, simulating bit-level corruption in transit.
        frame[22] ^= 0xFF; // ttl byte within the ipv4 header
        let pkt = decode_packet(0, frame.len() as u32, frame.len() as u32, &frame).unwrap();
        let ip = match pkt.ip.unwrap() {
            IpHeader::V4(h) => h,
            _ => panic!("expected ipv4"),
        };
        assert!(!ip.checksum_valid);
    }

    #[test]
    fn tcp_flags_display() {
        let f = TcpFlags::SYN | TcpFlags::ACK;
        assert_eq!(f.to_string(), "SYN,ACK");
        assert_eq!(TcpFlags(0).to_string(), "-");
    }

    #[test]
    fn vlan_tag_is_skipped_to_reach_real_ethertype() {
        let mut f = Vec::new();
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&100u16.to_be_bytes()); // vlan tag
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let (hdr, rest) = decode_ethernet(&f).unwrap();
        assert_eq!(hdr.vlan_tag, Some(100));
        assert_eq!(hdr.ethertype, ETHERTYPE_IPV4);
        assert!(rest.is_empty());
    }

    #[test]
    fn truncated_ethernet_frame_errors() {
        let f = vec![0u8; 10];
        assert!(matches!(
            decode_ethernet(&f),
            Err(DecodeError::TooShort { .. })
        ));
    }

    #[test]
    fn udp_zero_checksum_is_not_flagged_invalid() {
        let mut udp = Vec::new();
        udp.extend_from_slice(&1u16.to_be_bytes());
        udp.extend_from_slice(&2u16.to_be_bytes());
        udp.extend_from_slice(&8u16.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 0 = disabled
        let (hdr, _) = decode_udp(
            &udp,
            Some((Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2))),
        )
        .unwrap();
        assert_eq!(hdr.checksum_valid, None);
    }
}
