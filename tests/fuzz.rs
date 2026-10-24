//! Deterministic robustness tests: a packet inspector reads hostile input
//! by definition, so no byte sequence may panic any layer.

use packetlens::{analyze, dns, flow, tls};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn full_pipeline(bytes: &[u8]) {
    if let Ok(a) = analyze(bytes) {
        for f in a.tracker.flows() {
            let _ = flow::explain_flow(f);
        }
        let _ = a.tracker.possible_scans(1);
    }
}

const FIXTURES: [&[u8]; 5] = [
    include_bytes!("../fixtures/web_browsing.pcap"),
    include_bytes!("../fixtures/port_scan.pcap"),
    include_bytes!("../fixtures/dns_lookup.pcap"),
    include_bytes!("../fixtures/icmp_ping.pcap"),
    include_bytes!("../fixtures/tls_clienthello.pcap"),
];

#[test]
fn mutated_fixtures_never_panic() {
    let mut rng = Rng(0x5eed);
    for fixture in FIXTURES {
        for _ in 0..3_000 {
            let mut b = fixture.to_vec();
            // Keep the 24-byte global header intact so mutations reach the
            // packet decoders, not just the magic check.
            for _ in 0..1 + rng.below(8) {
                let i = 24 + rng.below(b.len() - 24);
                b[i] = rng.next() as u8;
            }
            if rng.below(4) == 0 {
                let keep = 24 + rng.below(b.len() - 24);
                b.resize(keep, 0);
            }
            full_pipeline(&b);
        }
    }
}

#[test]
fn random_bytes_never_panic_any_parser() {
    let mut rng = Rng(42);
    for _ in 0..20_000 {
        let n = rng.below(300);
        let b: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        full_pipeline(&b);
        let _ = dns::parse(&b);
        let _ = tls::parse_client_hello(&b);
    }
}

#[test]
fn structured_dns_and_tls_payloads_never_panic() {
    let mut rng = Rng(7);
    for _ in 0..20_000 {
        let mut b = vec![0u8; 12 + rng.below(120)];
        for x in b.iter_mut() {
            *x = rng.next() as u8;
        }
        // DNS: small counts so the parser walks into names and answers.
        b[4] = 0;
        b[5] = rng.below(4) as u8;
        b[6] = 0;
        b[7] = rng.below(4) as u8;
        let _ = dns::parse(&b);
        // TLS: handshake record header followed by a ClientHello type byte.
        let mut t = vec![22, 3, 1];
        t.extend_from_slice(&(b.len() as u16 + 1).to_be_bytes());
        t.push(1);
        t.extend_from_slice(&b);
        let _ = tls::parse_client_hello(&t);
    }
}
