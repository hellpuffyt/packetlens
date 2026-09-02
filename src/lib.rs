//! packetlens: a live, readable packet inspector built on raw sockets and a
//! from-scratch protocol decoder — no bundled Wireshark, no libpcap binding.
//!
//! The library is split into small, independently-testable layers:
//!
//! - [`pcap`] reads the classic libpcap capture file format.
//! - [`checksum`] implements the RFC 1071 internet checksum shared by
//!   IPv4/TCP/UDP.
//! - [`decode`] turns raw bytes into typed Ethernet/IPv4/IPv6/TCP/UDP/ICMP
//!   headers.
//! - [`dns`] and [`tls`] pull the useful bits out of DNS messages and TLS
//!   ClientHellos (query names, SNI, ALPN) without a general-purpose library.
//! - [`flow`] groups decoded packets into bidirectional connections and
//!   produces plain-English descriptions of what each one looks like it was
//!   doing.
//!
//! Live capture from a real network interface is available on Linux behind
//! the `live-capture` cargo feature (see [`live`]); it needs `CAP_NET_RAW`
//! or root and is not part of the default, always-testable build. A
//! `ratatui`-based interactive viewer is available behind the `tui` feature
//! (see [`tui`]).

pub mod checksum;
pub mod decode;
pub mod dns;
pub mod flow;
pub mod pcap;
pub mod tls;

#[cfg(all(feature = "live-capture", target_os = "linux"))]
pub mod live;

#[cfg(feature = "tui")]
pub mod tui;

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct AnalysisError(pub String);
impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for AnalysisError {}

/// Result of running the full analysis pipeline (parse pcap -> decode every
/// packet -> track flows) over a capture file's bytes.
#[derive(Debug)]
pub struct Analysis {
    pub pcap_header: pcap::GlobalHeader,
    pub packets: Vec<decode::DecodedPacket>,
    pub decode_failures: usize,
    pub tracker: flow::FlowTracker,
}

/// Runs the complete pipeline over the raw bytes of a pcap file.
pub fn analyze(bytes: &[u8]) -> Result<Analysis, Box<dyn Error>> {
    let file = pcap::parse(bytes)?;
    if file.header.linktype != pcap::LINKTYPE_ETHERNET {
        return Err(Box::new(AnalysisError(format!(
            "unsupported link-layer type {} (only Ethernet/DLT_EN10MB is decoded)",
            file.header.linktype
        ))));
    }

    let mut packets = Vec::with_capacity(file.packets.len());
    let mut decode_failures = 0;
    for raw in &file.packets {
        let ts = raw.timestamp_micros(file.header.resolution);
        match decode::decode_packet(ts, raw.captured_len, raw.original_len, &raw.data) {
            Ok(pkt) => packets.push(pkt),
            Err(_) => decode_failures += 1,
        }
    }

    let mut tracker = flow::FlowTracker::new();
    tracker.ingest_all(&packets);

    Ok(Analysis {
        pcap_header: file.header,
        packets,
        decode_failures,
        tracker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_rejects_non_ethernet_linktype() {
        // linktype 0 = DLT_NULL, which we don't decode.
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1];
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // linktype 0
        let err = analyze(&bytes).unwrap_err();
        assert!(err.to_string().contains("unsupported link-layer type"));
    }

    #[test]
    fn analyze_reports_decode_failures_without_aborting() {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1];
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // linktype 1 = ethernet
                                                      // One record with only 4 bytes of payload: too short to be a valid
                                                      // ethernet frame (needs 14), so it should count as a decode failure
                                                      // rather than aborting the whole analysis.
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let analysis = analyze(&bytes).unwrap();
        assert_eq!(analysis.decode_failures, 1);
        assert!(analysis.packets.is_empty());
    }
}
