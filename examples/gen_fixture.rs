//! Writes real-shaped classic-format pcap fixtures into `fixtures/` for the
//! integration test suite (`tests/fixtures.rs`) to exercise against.
//!
//! Run with `cargo run --example gen_fixture` whenever a fixture needs to be
//! regenerated (e.g. after changing what scenarios the suite should cover).
//! Every fixture is built by hand at the byte level here — deliberately not
//! through `packetlens::pcap` (which only reads) or a system capture tool —
//! so the test suite's fixtures are traceable to exactly the bytes that
//! produced them, and require no network access, root, or Npcap to
//! regenerate.

use packetlens::checksum::{internet_checksum, transport_checksum_v4};
use std::net::Ipv4Addr;

const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

fn main() -> std::io::Result<()> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::create_dir_all(&dir)?;

    write_pcap(&dir.join("web_browsing.pcap"), &web_browsing_frames())?;
    write_pcap(&dir.join("port_scan.pcap"), &port_scan_frames())?;
    write_pcap(&dir.join("dns_lookup.pcap"), &dns_lookup_frames())?;
    write_pcap(&dir.join("icmp_ping.pcap"), &icmp_ping_frames())?;
    write_pcap(&dir.join("tls_clienthello.pcap"), &tls_handshake_frames())?;

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        println!("wrote {}", entry.path().display());
    }
    Ok(())
}

struct Frame {
    ts_secs: u32,
    ts_micros: u32,
    bytes: Vec<u8>,
}

fn write_pcap(path: &std::path::Path, frames: &[Frame]) -> std::io::Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic: little-endian, microsecond resolution
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // linktype = DLT_EN10MB

    for f in frames {
        out.extend_from_slice(&f.ts_secs.to_le_bytes());
        out.extend_from_slice(&f.ts_micros.to_le_bytes());
        out.extend_from_slice(&(f.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.bytes);
    }
    std::fs::write(path, out)
}

fn mac(seed: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, seed]
}

#[allow(clippy::too_many_arguments)]
fn eth_ipv4_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(payload);
    let cksum = transport_checksum_v4(src_ip.octets(), dst_ip.octets(), IPPROTO_TCP, &tcp);
    tcp[16] = (cksum >> 8) as u8;
    tcp[17] = (cksum & 0xFF) as u8;

    build_frame(src_mac, dst_mac, src_ip, dst_ip, IPPROTO_TCP, &tcp)
}

fn eth_ipv4_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    let length = (8 + payload.len()) as u16;
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    udp.extend_from_slice(payload);
    let cksum = transport_checksum_v4(src_ip.octets(), dst_ip.octets(), IPPROTO_UDP, &udp);
    udp[6] = (cksum >> 8) as u8;
    udp[7] = (cksum & 0xFF) as u8;

    build_frame(src_mac, dst_mac, src_ip, dst_ip, IPPROTO_UDP, &udp)
}

fn eth_ipv4_icmp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = Vec::new();
    icmp.push(icmp_type);
    icmp.push(code);
    icmp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp.extend_from_slice(payload);
    let cksum = internet_checksum(&icmp);
    icmp[2] = (cksum >> 8) as u8;
    icmp[3] = (cksum & 0xFF) as u8;

    build_frame(src_mac, dst_mac, src_ip, dst_ip, IPPROTO_ICMP, &icmp)
}

fn build_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    transport: &[u8],
) -> Vec<u8> {
    let total_len = 20 + transport.len();
    let mut ip = Vec::new();
    ip.push((4 << 4) | 5);
    ip.push(0);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0x1000u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't-fragment flag set
    ip.push(64);
    ip.push(protocol);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let cksum = internet_checksum(&ip);
    ip[10] = (cksum >> 8) as u8;
    ip[11] = (cksum & 0xFF) as u8;

    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(transport);
    frame
}

const SYN: u8 = 0b0000_0010;
const ACK: u8 = 0b0001_0000;
const FIN: u8 = 0b0000_0001;
const PSH: u8 = 0b0000_1000;

fn web_browsing_frames() -> Vec<Frame> {
    let client_mac = mac(1);
    let server_mac = mac(2);
    let client_ip = Ipv4Addr::new(10, 0, 0, 5);
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    let cport = 51000;

    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";

    let mut frames = Vec::new();
    let mut t = 0u32;
    let mut push = |bytes: Vec<u8>| {
        frames.push(Frame {
            ts_secs: 1_700_000_000,
            ts_micros: t,
            bytes,
        });
        t += 1000;
    };

    push(eth_ipv4_tcp(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        cport,
        80,
        1000,
        0,
        SYN,
        &[],
    ));
    push(eth_ipv4_tcp(
        server_mac,
        client_mac,
        server_ip,
        client_ip,
        80,
        cport,
        5000,
        1001,
        SYN | ACK,
        &[],
    ));
    push(eth_ipv4_tcp(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        cport,
        80,
        1001,
        5001,
        ACK,
        &[],
    ));
    push(eth_ipv4_tcp(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        cport,
        80,
        1001,
        5001,
        PSH | ACK,
        request,
    ));
    push(eth_ipv4_tcp(
        server_mac,
        client_mac,
        server_ip,
        client_ip,
        80,
        cport,
        5001,
        1001 + request.len() as u32,
        PSH | ACK,
        response,
    ));
    push(eth_ipv4_tcp(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        cport,
        80,
        1001 + request.len() as u32,
        5001 + response.len() as u32,
        FIN | ACK,
        &[],
    ));
    push(eth_ipv4_tcp(
        server_mac,
        client_mac,
        server_ip,
        client_ip,
        80,
        cport,
        5001 + response.len() as u32,
        2001 + request.len() as u32,
        FIN | ACK,
        &[],
    ));
    frames
}

fn port_scan_frames() -> Vec<Frame> {
    let attacker_mac = mac(3);
    let victim_mac = mac(4);
    let attacker_ip = Ipv4Addr::new(198, 51, 100, 23);
    let victim_ip = Ipv4Addr::new(93, 184, 216, 34);
    let mut frames = Vec::new();
    let mut t = 0u32;
    for (i, port) in [21u16, 22, 23, 25, 80, 443, 3389, 8080].iter().enumerate() {
        frames.push(Frame {
            ts_secs: 1_700_000_100,
            ts_micros: t,
            bytes: eth_ipv4_tcp(
                attacker_mac,
                victim_mac,
                attacker_ip,
                victim_ip,
                40000 + i as u16,
                *port,
                9000 + i as u32,
                0,
                SYN,
                &[],
            ),
        });
        t += 100;
    }
    frames
}

/// Builds a minimal, syntactically valid DNS message by hand (no
/// `packetlens::dns` writer exists — only a reader — so this mirrors RFC
/// 1035 section 4.1 directly).
fn dns_message(txid: u16, is_response: bool, qname: &str, answer_ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&txid.to_be_bytes());
    let flags: u16 = if is_response { 0x8180 } else { 0x0100 };
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&(if answer_ip.is_some() { 1u16 } else { 0 }).to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    if let Some(ip) = answer_ip {
        m.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to qname
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes()); // ttl
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&ip.octets());
    }
    m
}

fn dns_lookup_frames() -> Vec<Frame> {
    let client_mac = mac(5);
    let resolver_mac = mac(6);
    let client_ip = Ipv4Addr::new(10, 0, 0, 5);
    let resolver_ip = Ipv4Addr::new(8, 8, 8, 8);

    let query = dns_message(0xBEEF, false, "example.com", None);
    let response = dns_message(
        0xBEEF,
        true,
        "example.com",
        Some(Ipv4Addr::new(93, 184, 216, 34)),
    );

    vec![
        Frame {
            ts_secs: 1_700_000_200,
            ts_micros: 0,
            bytes: eth_ipv4_udp(
                client_mac,
                resolver_mac,
                client_ip,
                resolver_ip,
                52000,
                53,
                &query,
            ),
        },
        Frame {
            ts_secs: 1_700_000_200,
            ts_micros: 5000,
            bytes: eth_ipv4_udp(
                resolver_mac,
                client_mac,
                resolver_ip,
                client_ip,
                53,
                52000,
                &response,
            ),
        },
    ]
}

fn icmp_ping_frames() -> Vec<Frame> {
    let a_mac = mac(7);
    let b_mac = mac(8);
    let a_ip = Ipv4Addr::new(10, 0, 0, 5);
    let b_ip = Ipv4Addr::new(10, 0, 0, 1);
    vec![
        Frame {
            ts_secs: 1_700_000_300,
            ts_micros: 0,
            bytes: eth_ipv4_icmp(a_mac, b_mac, a_ip, b_ip, 8, 0, b"pingdata"), // echo request
        },
        Frame {
            ts_secs: 1_700_000_300,
            ts_micros: 2000,
            bytes: eth_ipv4_icmp(b_mac, a_mac, b_ip, a_ip, 0, 0, b"pingdata"), // echo reply
        },
    ]
}

fn tls_client_hello_record(sni: &str) -> Vec<u8> {
    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&0x0303u16.to_be_bytes());
    hs_body.extend_from_slice(&[0x42u8; 32]);
    hs_body.push(0); // session id len
    let ciphers: &[u16] = &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
    hs_body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        hs_body.extend_from_slice(&c.to_be_bytes());
    }
    hs_body.push(1);
    hs_body.push(0);

    let mut sni_list = vec![0u8];
    sni_list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sni.as_bytes());
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_list);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_ext);

    hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&ext);

    let mut handshake = vec![1u8];
    handshake.extend_from_slice(&(hs_body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hs_body);

    let mut record = vec![22u8];
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn tls_handshake_frames() -> Vec<Frame> {
    let client_mac = mac(9);
    let server_mac = mac(10);
    let client_ip = Ipv4Addr::new(10, 0, 0, 9);
    let server_ip = Ipv4Addr::new(203, 0, 113, 50);
    let cport = 52123;
    let hello = tls_client_hello_record("secure.example.net");

    vec![
        Frame {
            ts_secs: 1_700_000_400,
            ts_micros: 0,
            bytes: eth_ipv4_tcp(
                client_mac,
                server_mac,
                client_ip,
                server_ip,
                cport,
                443,
                1,
                0,
                SYN,
                &[],
            ),
        },
        Frame {
            ts_secs: 1_700_000_400,
            ts_micros: 1000,
            bytes: eth_ipv4_tcp(
                server_mac,
                client_mac,
                server_ip,
                client_ip,
                443,
                cport,
                1,
                2,
                SYN | ACK,
                &[],
            ),
        },
        Frame {
            ts_secs: 1_700_000_400,
            ts_micros: 2000,
            bytes: eth_ipv4_tcp(
                client_mac,
                server_mac,
                client_ip,
                server_ip,
                cport,
                443,
                2,
                2,
                ACK,
                &[],
            ),
        },
        Frame {
            ts_secs: 1_700_000_400,
            ts_micros: 3000,
            bytes: eth_ipv4_tcp(
                client_mac,
                server_mac,
                client_ip,
                server_ip,
                cport,
                443,
                2,
                2,
                PSH | ACK,
                &hello,
            ),
        },
    ]
}
