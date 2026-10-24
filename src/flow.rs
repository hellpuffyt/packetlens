//! Connection tracking and plain-English flow summaries.

use crate::decode::{DecodedPacket, Transport};
use crate::{dns, tls};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Other(p) => write!(f, "proto-{p}"),
        }
    }
}

/// Direction-independent flow key: two endpoints, ordered by natural
/// `Ord` so the same conversation hashes identically regardless of which
/// side sent the first packet we happened to see.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: Protocol,
    pub endpoint_a: (IpAddr, u16),
    pub endpoint_b: (IpAddr, u16),
}

impl FlowKey {
    fn new(protocol: Protocol, ep1: (IpAddr, u16), ep2: (IpAddr, u16)) -> Self {
        if ep1 <= ep2 {
            FlowKey {
                protocol,
                endpoint_a: ep1,
                endpoint_b: ep2,
            }
        } else {
            FlowKey {
                protocol,
                endpoint_a: ep2,
                endpoint_b: ep1,
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirectionalStats {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub key: FlowKey,
    /// The endpoint that sent the first packet observed for this flow.
    pub initiator: (IpAddr, u16),
    pub responder: (IpAddr, u16),
    pub first_ts_micros: u64,
    pub last_ts_micros: u64,
    pub initiator_stats: DirectionalStats,
    pub responder_stats: DirectionalStats,
    pub tcp_flags_seen: u8,
    pub syn_seen: bool,
    pub synack_seen: bool,
    pub handshake_ack_seen: bool,
    pub fin_seen: bool,
    pub rst_seen: bool,
    pub total_packets: u64,
    /// TLS SNI (server name) pulled from a ClientHello seen in this flow, if
    /// any application payload matched port 443 and parsed as one.
    pub tls_sni: Option<String>,
    /// Distinct hostnames asked about in DNS queries seen on this flow.
    pub dns_queries: Vec<String>,
}

impl FlowState {
    pub fn duration_micros(&self) -> u64 {
        self.last_ts_micros.saturating_sub(self.first_ts_micros)
    }

    pub fn total_bytes(&self) -> u64 {
        self.initiator_stats.bytes + self.responder_stats.bytes
    }

    /// True for a TCP flow that never got past the initial SYN — the
    /// classic footprint of a scan probe or a filtered/closed port.
    pub fn is_unanswered_tcp_syn(&self) -> bool {
        self.key.protocol == Protocol::Tcp
            && self.syn_seen
            && !self.synack_seen
            && self.responder_stats.packets == 0
    }

    pub fn handshake_completed(&self) -> bool {
        self.syn_seen && self.synack_seen && self.handshake_ack_seen
    }
}

#[derive(Debug, Default)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    /// Insertion order, so reports read in capture order rather than hash order.
    order: Vec<FlowKey>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one packet and returns the flow it was accounted to (`None` for
    /// traffic that is not flow-tracked, such as ARP).
    pub fn ingest(&mut self, pkt: &DecodedPacket) -> Option<&FlowState> {
        // Non-IP traffic (ARP etc.) is not flow-tracked.
        let ip = pkt.ip.as_ref()?;
        let (protocol, src_port, dst_port) = match &pkt.transport {
            Transport::Tcp(t) => (Protocol::Tcp, t.src_port, t.dst_port),
            Transport::Udp(u) => (Protocol::Udp, u.src_port, u.dst_port),
            Transport::Icmp(_) => (Protocol::Icmp, 0, 0),
            Transport::Other(p) => (Protocol::Other(*p), 0, 0),
            Transport::None => return None,
        };
        let src = (ip.src(), src_port);
        let dst = (ip.dst(), dst_port);
        let key = FlowKey::new(protocol, src, dst);

        let is_new = !self.flows.contains_key(&key);
        let state = self.flows.entry(key.clone()).or_insert_with(|| FlowState {
            key: key.clone(),
            initiator: src,
            responder: dst,
            first_ts_micros: pkt.timestamp_micros,
            last_ts_micros: pkt.timestamp_micros,
            initiator_stats: DirectionalStats::default(),
            responder_stats: DirectionalStats::default(),
            tcp_flags_seen: 0,
            syn_seen: false,
            synack_seen: false,
            handshake_ack_seen: false,
            fin_seen: false,
            rst_seen: false,
            total_packets: 0,
            tls_sni: None,
            dns_queries: Vec::new(),
        });
        if is_new {
            self.order.push(key);
        }

        state.last_ts_micros = state.last_ts_micros.max(pkt.timestamp_micros);
        state.total_packets += 1;
        let wire_len = pkt.original_len as u64;
        if src == state.initiator {
            state.initiator_stats.packets += 1;
            state.initiator_stats.bytes += wire_len;
        } else {
            state.responder_stats.packets += 1;
            state.responder_stats.bytes += wire_len;
        }

        if let Transport::Tcp(tcp) = &pkt.transport {
            state.tcp_flags_seen |= tcp.flags.bits();
            let is_syn = tcp.flags.contains(crate::decode::TcpFlags::SYN);
            let is_ack = tcp.flags.contains(crate::decode::TcpFlags::ACK);
            if is_syn && !is_ack && src == state.initiator {
                state.syn_seen = true;
            }
            if is_syn && is_ack && src == state.responder {
                state.synack_seen = true;
            }
            if !is_syn
                && is_ack
                && src == state.initiator
                && state.synack_seen
                && !state.handshake_ack_seen
            {
                state.handshake_ack_seen = true;
            }
            if tcp.flags.contains(crate::decode::TcpFlags::FIN) {
                state.fin_seen = true;
            }
            if tcp.flags.contains(crate::decode::TcpFlags::RST) {
                state.rst_seen = true;
            }
        }

        // Best-effort application-layer peek: only attempted on the ports
        // where these protocols conventionally live, and never fatal if the
        // payload doesn't parse (mid-stream capture, unrelated traffic on a
        // well-known port, etc).
        if state.tls_sni.is_none()
            && (src_port == 443 || dst_port == 443)
            && !pkt.payload.is_empty()
        {
            if let Ok(hello) = tls::parse_client_hello(&pkt.payload) {
                state.tls_sni = hello.server_name;
            }
        }
        if (src_port == dns::DNS_PORT || dst_port == dns::DNS_PORT) && !pkt.payload.is_empty() {
            if let Ok(msg) = dns::parse(&pkt.payload) {
                if !msg.is_response {
                    for q in &msg.questions {
                        if !state.dns_queries.contains(&q.name) {
                            state.dns_queries.push(q.name.clone());
                        }
                    }
                }
            }
        }
        Some(state)
    }

    pub fn ingest_all<'a>(&mut self, packets: impl IntoIterator<Item = &'a DecodedPacket>) {
        for pkt in packets {
            let _ = self.ingest(pkt);
        }
    }

    /// Flows in the order their first packet was observed.
    pub fn flows(&self) -> Vec<&FlowState> {
        self.order
            .iter()
            .filter_map(|k| self.flows.get(k))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Heuristic scan detector: groups unanswered TCP SYN flows by source
    /// IP and reports sources that probed at least `threshold` distinct
    /// destination ports without a single reply — the standard signature
    /// of a TCP SYN (half-open) port scan.
    pub fn possible_scans(&self, threshold: usize) -> Vec<ScanReport> {
        let mut by_source: HashMap<IpAddr, Vec<(IpAddr, u16)>> = HashMap::new();
        for key in &self.order {
            if let Some(flow) = self.flows.get(key) {
                if flow.is_unanswered_tcp_syn() {
                    by_source
                        .entry(flow.initiator.0)
                        .or_default()
                        .push(flow.responder);
                }
            }
        }
        let mut reports: Vec<ScanReport> = by_source
            .into_iter()
            .filter(|(_, targets)| {
                let mut ports: Vec<u16> = targets.iter().map(|(_, p)| *p).collect();
                ports.sort_unstable();
                ports.dedup();
                ports.len() >= threshold
            })
            .map(|(source, mut targets)| {
                targets.sort();
                ScanReport { source, targets }
            })
            .collect();
        reports.sort_by_key(|r| r.source.to_string());
        reports
    }
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub source: IpAddr,
    pub targets: Vec<(IpAddr, u16)>,
}

/// Produces a one-paragraph plain-English explanation of what a flow looks
/// like it was doing, based only on observable transport-layer behavior
/// (handshake shape, byte balance, well-known ports) — not payload
/// inspection or magic signatures.
/// Makes attacker-controlled text (SNI, DNS names — straight off the wire)
/// safe to print: control characters (terminal escape sequences, newlines)
/// and invisible/bidirectional formatting characters are shown as `\u{..}`
/// escapes instead of being interpreted by the terminal or reordering text.
pub fn display_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let invisible = matches!(
            c,
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
        );
        if c.is_control() || invisible {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn explain_flow(flow: &FlowState) -> String {
    let a = format_endpoint(flow.initiator);
    let b = format_endpoint(flow.responder);
    match flow.key.protocol {
        Protocol::Tcp => {
            if flow.is_unanswered_tcp_syn() {
                format!(
                    "{a} -> {b}: a single SYN with no reply at all ({pkts} packet, {bytes} B). \
                     Consistent with a port scan probe, or a closed/filtered port that silently \
                     dropped the connection attempt.",
                    pkts = flow.initiator_stats.packets,
                    bytes = flow.total_bytes()
                )
            } else if flow.rst_seen && !flow.handshake_completed() {
                format!(
                    "{a} -> {b}: connection attempt was reset before completing (SYN then RST). \
                     The destination is reachable but actively refused this port."
                )
            } else if flow.handshake_completed() {
                let closed = if flow.fin_seen {
                    "closed cleanly with FIN"
                } else if flow.rst_seen {
                    "ended with a RST after data was exchanged"
                } else {
                    "left open at the end of the capture"
                };
                let hint_str = if let Some(sni) = &flow.tls_sni {
                    format!(" TLS ClientHello asked for '{}' (SNI).", display_safe(sni))
                } else if let Some(s) = well_known_service(flow.initiator, flow.responder) {
                    format!(" Looks like {s}.")
                } else {
                    String::new()
                };
                format!(
                    "{a} -> {b}: completed TCP handshake, {out_p} packet(s)/{out_b} B sent, \
                     {in_p} packet(s)/{in_b} B received, {closed}.{hint}",
                    out_p = flow.initiator_stats.packets,
                    out_b = flow.initiator_stats.bytes,
                    in_p = flow.responder_stats.packets,
                    in_b = flow.responder_stats.bytes,
                    closed = closed,
                    hint = hint_str
                )
            } else {
                format!(
                    "{a} -> {b}: partial TCP exchange ({pkts} packets, {bytes} B total), handshake \
                     never fully completed within the capture window.",
                    pkts = flow.total_packets,
                    bytes = flow.total_bytes()
                )
            }
        }
        Protocol::Udp => {
            let is_dns = flow.initiator.1 == 53 || flow.responder.1 == 53;
            let both_sides_spoke =
                flow.initiator_stats.packets > 0 && flow.responder_stats.packets > 0;
            if is_dns && both_sides_spoke {
                let names = if flow.dns_queries.is_empty() {
                    String::new()
                } else {
                    let names: Vec<String> =
                        flow.dns_queries.iter().map(|n| display_safe(n)).collect();
                    format!(" Asked about: {}.", names.join(", "))
                };
                format!(
                    "{a} -> {b}: one UDP request answered by one reply on port 53. Looks like a \
                     DNS query and response ({out_b} B out / {in_b} B back).{names}",
                    out_b = flow.initiator_stats.bytes,
                    in_b = flow.responder_stats.bytes,
                    names = names
                )
            } else if both_sides_spoke {
                format!(
                    "{a} -> {b}: UDP exchange, {out_p} packet(s)/{out_b} B out, {in_p} packet(s)/{in_b} B back.",
                    out_p = flow.initiator_stats.packets,
                    out_b = flow.initiator_stats.bytes,
                    in_p = flow.responder_stats.packets,
                    in_b = flow.responder_stats.bytes
                )
            } else {
                format!(
                    "{a} -> {b}: {pkts} UDP packet(s) sent with no reply seen ({bytes} B). Since UDP \
                     has no handshake this may simply be one-way traffic, or a probe against a \
                     closed/filtered port.",
                    pkts = flow.initiator_stats.packets,
                    bytes = flow.total_bytes()
                )
            }
        }
        Protocol::Icmp => {
            format!(
                "{a} <-> {b}: ICMP exchange, {pkts} packet(s), {bytes} B total. Typically a ping \
                 (echo request/reply) or a network-layer control message such as \
                 destination-unreachable.",
                pkts = flow.total_packets,
                bytes = flow.total_bytes()
            )
        }
        Protocol::Other(p) => {
            format!(
                "{a} <-> {b}: {pkts} packet(s) of IP protocol {p} (not decoded further).",
                pkts = flow.total_packets
            )
        }
    }
}

fn format_endpoint((ip, port): (IpAddr, u16)) -> String {
    if port == 0 {
        ip.to_string()
    } else {
        format!("{ip}:{port}")
    }
}

fn well_known_service(a: (IpAddr, u16), b: (IpAddr, u16)) -> Option<&'static str> {
    let port = if is_well_known(a.1) { a.1 } else { b.1 };
    match port {
        80 => Some("a plain HTTP request/response"),
        443 => Some("a TLS/HTTPS session"),
        22 => Some("an SSH session"),
        21 => Some("an FTP control session"),
        25 => Some("an SMTP mail transfer"),
        3389 => Some("an RDP session"),
        _ => None,
    }
}

fn is_well_known(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 80 | 443 | 3389)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{
        DecodedPacket, EthernetHeader, IpHeader, Ipv4Header, TcpFlags, TcpHeader, Transport,
    };
    use std::net::Ipv4Addr;

    fn eth() -> EthernetHeader {
        EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ethertype: 0x0800,
            vlan_tag: None,
        }
    }

    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr) -> IpHeader {
        IpHeader::V4(Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            total_length: 40,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            header_checksum: 0,
            src,
            dst,
            checksum_valid: true,
        })
    }

    fn tcp_pkt(
        ts: u64,
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        flags: u8,
        len: u32,
    ) -> DecodedPacket {
        DecodedPacket {
            timestamp_micros: ts,
            captured_len: len,
            original_len: len,
            ethernet: eth(),
            ip: Some(ipv4(src, dst)),
            transport: Transport::Tcp(TcpHeader {
                src_port: sport,
                dst_port: dport,
                sequence: 0,
                ack_number: 0,
                data_offset: 5,
                flags: TcpFlags(flags),
                window: 0,
                checksum: 0,
                urgent_pointer: 0,
                checksum_valid: Some(true),
            }),
            payload: vec![],
        }
    }

    /// Regression: SNI and DNS names come straight off the wire and were
    /// interpolated raw into the summary printed to the terminal, so a
    /// crafted ClientHello could inject terminal escape sequences (or
    /// bidi-override characters) into the analyst's screen.
    #[test]
    fn hostile_names_are_escaped_in_summaries() {
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        let _ = tracker.ingest(&tcp_pkt(0, client, 5555, server, 443, TcpFlags::SYN.0, 60));
        let _ = tracker.ingest(&tcp_pkt(
            1,
            server,
            443,
            client,
            5555,
            TcpFlags::SYN.0 | TcpFlags::ACK.0,
            60,
        ));
        let _ = tracker.ingest(&tcp_pkt(2, client, 5555, server, 443, TcpFlags::ACK.0, 54));
        let mut flow = tracker.flows()[0].clone();
        flow.tls_sni = Some("evil\x1b]0;pwned\x07\x1b[2J\u{202E}moc.knab\n".into());
        let text = explain_flow(&flow);
        for bad in ['\x1b', '\x07', '\n', '\u{202E}'] {
            assert!(!text.contains(bad), "{bad:?} leaked into {text:?}");
        }
        assert!(text.contains("\\u{1b}]0;pwned"), "{text}");
        assert_eq!(display_safe("example.com"), "example.com");
        assert_eq!(display_safe("bücher.example"), "bücher.example");
    }

    /// Regression: live capture printed the first flow that merely involved
    /// the packet's source IP, so with two connections from one host the
    /// summary shown was usually for the wrong connection. `ingest` now
    /// returns the flow the packet was actually accounted to.
    #[test]
    fn ingest_returns_the_packets_own_flow() {
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        let _ = tracker.ingest(&tcp_pkt(0, client, 5555, server, 80, TcpFlags::SYN.0, 60));
        let second = tracker
            .ingest(&tcp_pkt(1, client, 6666, server, 443, TcpFlags::SYN.0, 60))
            .expect("tcp packet is tracked");
        assert_eq!(second.initiator, (IpAddr::V4(client), 6666));
        assert_eq!(second.responder, (IpAddr::V4(server), 443));
        // A reply is accounted to the same flow, seen from the server side.
        let reply = tracker
            .ingest(&tcp_pkt(
                2,
                server,
                443,
                client,
                6666,
                TcpFlags::SYN.0 | TcpFlags::ACK.0,
                60,
            ))
            .expect("tcp packet is tracked");
        assert_eq!(reply.initiator, (IpAddr::V4(client), 6666));
        assert!(reply.synack_seen);
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn tracks_completed_handshake_as_one_flow_both_directions() {
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        tracker.ingest(&tcp_pkt(0, client, 5555, server, 80, TcpFlags::SYN.0, 60));
        tracker.ingest(&tcp_pkt(
            1,
            server,
            80,
            client,
            5555,
            (TcpFlags::SYN | TcpFlags::ACK).0,
            60,
        ));
        tracker.ingest(&tcp_pkt(2, client, 5555, server, 80, TcpFlags::ACK.0, 54));
        tracker.ingest(&tcp_pkt(
            3,
            client,
            5555,
            server,
            80,
            (TcpFlags::PSH | TcpFlags::ACK).0,
            200,
        ));
        tracker.ingest(&tcp_pkt(
            4,
            server,
            80,
            client,
            5555,
            (TcpFlags::FIN | TcpFlags::ACK).0,
            54,
        ));

        assert_eq!(tracker.len(), 1);
        let flow = &tracker.flows()[0];
        assert!(flow.handshake_completed());
        assert!(flow.fin_seen);
        assert_eq!(flow.initiator, (IpAddr::V4(client), 5555));
        assert_eq!(flow.initiator_stats.packets, 3);
        assert_eq!(flow.responder_stats.packets, 2);
        let explanation = explain_flow(flow);
        assert!(explanation.contains("completed TCP handshake"));
        assert!(explanation.contains("HTTP"));
    }

    #[test]
    fn unanswered_syn_is_flagged() {
        let attacker = Ipv4Addr::new(198, 51, 100, 9);
        let victim = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        tracker.ingest(&tcp_pkt(
            0,
            attacker,
            40000,
            victim,
            22,
            TcpFlags::SYN.0,
            60,
        ));
        let flow = &tracker.flows()[0];
        assert!(flow.is_unanswered_tcp_syn());
        let text = explain_flow(flow);
        assert!(text.contains("port scan"));
    }

    #[test]
    fn detects_scan_across_many_flows() {
        let attacker = Ipv4Addr::new(198, 51, 100, 9);
        let victim = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        for port in [22u16, 23, 25, 3389] {
            tracker.ingest(&tcp_pkt(
                0,
                attacker,
                40000 + port,
                victim,
                port,
                TcpFlags::SYN.0,
                60,
            ));
        }
        let scans = tracker.possible_scans(4);
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].source, IpAddr::V4(attacker));
        assert_eq!(scans[0].targets.len(), 4);
    }

    #[test]
    fn scan_not_reported_below_threshold() {
        let attacker = Ipv4Addr::new(198, 51, 100, 9);
        let victim = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        tracker.ingest(&tcp_pkt(
            0,
            attacker,
            40001,
            victim,
            22,
            TcpFlags::SYN.0,
            60,
        ));
        tracker.ingest(&tcp_pkt(
            1,
            attacker,
            40002,
            victim,
            23,
            TcpFlags::SYN.0,
            60,
        ));
        assert!(tracker.possible_scans(4).is_empty());
    }

    #[test]
    fn reset_before_handshake_is_explained_as_refused() {
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mut tracker = FlowTracker::new();
        tracker.ingest(&tcp_pkt(0, client, 5555, server, 8080, TcpFlags::SYN.0, 60));
        tracker.ingest(&tcp_pkt(
            1,
            server,
            8080,
            client,
            5555,
            (TcpFlags::RST | TcpFlags::ACK).0,
            54,
        ));
        let flow = &tracker.flows()[0];
        assert!(flow.rst_seen);
        assert!(!flow.handshake_completed());
        let text = explain_flow(flow);
        assert!(text.contains("reset"));
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let a = (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 100);
        let b = (IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 200);
        let k1 = FlowKey::new(Protocol::Tcp, a, b);
        let k2 = FlowKey::new(Protocol::Tcp, b, a);
        assert_eq!(k1, k2);
    }

    #[test]
    fn non_ip_packets_are_ignored_by_tracker() {
        let mut tracker = FlowTracker::new();
        let pkt = DecodedPacket {
            timestamp_micros: 0,
            captured_len: 14,
            original_len: 14,
            ethernet: EthernetHeader {
                dst_mac: [0; 6],
                src_mac: [0; 6],
                ethertype: 0x0806,
                vlan_tag: None,
            },
            ip: None,
            transport: Transport::None,
            payload: vec![],
        };
        tracker.ingest(&pkt);
        assert!(tracker.is_empty());
    }
}
