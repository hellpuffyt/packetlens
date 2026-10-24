# packetlens

**A live, readable packet inspector.** Decode Ethernet/IPv4/IPv6/TCP/UDP/DNS/TLS,
track connections, and get a plain-English sentence explaining what a flow is
actually doing — built on raw sockets, not a bundled Wireshark.

```
packetlens: 4 packets decoded (0 failed to decode), 1 flow(s)

protocol breakdown: TCP=4 UDP=0 ICMP=0 other=0

flows:
  [TCP] 10.0.0.9:52123 -> 203.0.113.50:443: completed TCP handshake, 3 packet(s)/249 B sent,
  1 packet(s)/54 B received, left open at the end of the capture. TLS ClientHello asked for
  'secure.example.net' (SNI).
```

## Why

Wireshark shows you every field of every header. Most of the time what you
actually want to know is *"what is this flow doing, in a sentence"* — is
this a completed HTTP request, a half-open port scan, a DNS lookup, a TLS
handshake to some particular hostname? packetlens decodes the same wire
formats but reports at that level: one line per connection, in English,
with the raw fields available underneath if you need them (`--json`).

It also has an unusual constraint baked into its architecture: the entire
decode → connection-tracking → explanation pipeline is **pure and
file-driven**. It never touches a socket unless you explicitly ask it to.
That means the whole test suite — protocol decoding, TCP/UDP/DNS/TLS
parsing, scan detection, flow explanations — runs on Linux, macOS, and
Windows CI runners with zero capture privileges, against hand-written pcap
fixtures that ship in the repo. Live capture is a separate, honestly
scoped, feature-gated layer on top.

## Quickstart

```sh
git clone https://github.com/hellpuffyt/packetlens.git
cd packetlens
cargo run -- fixtures/port_scan.pcap
```

(Output abbreviated: long lines wrapped, remaining flows and ports elided.)

```
packetlens: 8 packets decoded (0 failed to decode), 8 flow(s)

protocol breakdown: TCP=8 UDP=0 ICMP=0 other=0

flows:
  [TCP] 198.51.100.23:40000 -> 93.184.216.34:21: a single SYN with no reply at all (1 packet, 54 B).
  Consistent with a port scan probe, or a closed/filtered port that silently dropped the connection
  attempt.
  ... (7 more)

possible port scans (>= 4 unanswered ports from one source):
  198.51.100.23 probed 8 ports with no reply: 93.184.216.34:21, 93.184.216.34:22, ...
```

Machine-readable output:

```sh
cargo run -- fixtures/web_browsing.pcap --json
```

Interactive viewer (needs the `tui` feature):

```sh
cargo run --features tui -- fixtures/port_scan.pcap --tui
```

```
 packetlens — 8 flow(s), scan threshold 4 — q to quit
┌Flows──────────────────────────────────────┐┌Explanation──────────────────────────────────────────┐
│[TCP] 198.51.100.23 <-> 93.184.216.34  (1 p││198.51.100.23:40000 -> 93.184.216.34:21: a single SYN│
│[TCP] 198.51.100.23 <-> 93.184.216.34  (1 p││with no reply at all (1 packet, 54 B). Consistent    │
│[TCP] 198.51.100.23 <-> 93.184.216.34  (1 p││with a port scan probe, or a closed/filtered port    │
│[TCP] 198.51.100.23 <-> 93.184.216.34  (1 p││that silently dropped the connection attempt.        │
│  ...                                      ││                                                     │
└───────────────────────────────────────────┘└─────────────────────────────────────────────────────┘
```
*(actual frame, rendered via ratatui's `TestBackend` against
`fixtures/port_scan.pcap` — see `examples/render_tui_snapshot.rs`.)*

`j`/`k` or arrow keys move the selection, `q`/Esc quits.

Live capture from a real interface (needs elevated privileges — see below):

```sh
cargo build --release --features live-capture   # Linux only
sudo ./target/release/packetlens live --iface eth0
```

## Architecture

```
                    ┌──────────────────────────────────────────┐
   .pcap file  ───▶ │  pcap::parse   →  global header + frames │
                    └──────────────────┬───────────────────────┘
                                       │ raw Ethernet frames
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  decode::decode_packet                    │
                    │  Ethernet(+VLAN) → IPv4/IPv6 → TCP/UDP/   │
                    │  ICMP, with IPv4/TCP/UDP checksum verify  │
                    └──────────────────┬───────────────────────┘
                                       │ DecodedPacket
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  flow::FlowTracker::ingest                │
                    │  bidirectional conntrack, TCP handshake/  │
                    │  close state, byte/packet counters,      │
                    │  best-effort DNS/TLS payload peek         │
                    │  (dns::parse / tls::parse_client_hello)   │
                    └──────────────────┬───────────────────────┘
                                       │ FlowState
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  flow::explain_flow                       │
                    │  → one plain-English sentence per flow    │
                    │  flow::possible_scans                     │
                    │  → heuristic half-open-SYN scan detector  │
                    └──────────────────┬───────────────────────┘
                                       │
                          ┌────────────┴────────────┐
                          ▼                          ▼
                 CLI text/--json report      tui::AppState (ratatui)
```

Everything above the dashed line in the crate (`pcap`, `checksum`, `decode`,
`dns`, `tls`, `flow`) is pure: bytes in, typed data out, no I/O. That's what
makes it exhaustively unit- and fixture-tested without a capture backend.

```
src/
├── pcap.rs      classic libpcap file reader (read-only; the fixture writer lives in examples/)
├── checksum.rs  RFC 1071 internet checksum (IPv4/TCP/UDP)
├── decode.rs    Ethernet/IPv4/IPv6/TCP/UDP/ICMP decoding
├── dns.rs       DNS message parser (questions, A-record answers)
├── tls.rs       TLS ClientHello parser (SNI, ALPN)
├── flow.rs      connection tracking + plain-English explanations + scan heuristic
├── tui.rs       ratatui viewer (feature "tui")
├── live.rs      Linux AF_PACKET raw-socket capture (feature "live-capture")
└── main.rs      CLI: text/--json report, --tui, live capture subcommand
```

### Portability of live capture — read this before relying on it

Live capture is real, but it is not portable, and this project does not
pretend otherwise:

- **Linux**: implemented (`src/live.rs`), via an `AF_PACKET`/`SOCK_RAW`
  socket. Needs `CAP_NET_RAW` (or root): either run as root, or
  `sudo setcap cap_net_raw+ep target/release/packetlens`.
- **Windows**: not implemented. Raw packet capture on Windows requires
  [Npcap](https://npcap.com/) (WinPcap's actively maintained successor) or an
  equivalent driver — packetlens does not bundle or link one. `packetlens live`
  on Windows returns a clear "not supported" error rather than silently
  failing.
- **macOS**: not implemented. BSD raw capture goes through `BPF`
  (`/dev/bpf*`) with its own permission model. Same honest error, no
  pretense of support.

Every one of those backends would feed the exact same `decode::decode_packet`
and `flow::FlowTracker` used by the pcap-file path — there is only one
decoder in this codebase — so adding a platform means writing a capture
loop, not a second parser.

## Testing strategy

```sh
cargo test                    # 49 tests: 38 lib + 1 CLI unit, 7 fixture, 3 fuzz
cargo test --features tui     # 52: + 3 tui::AppState unit tests (Rust >= 1.88)
cargo test --test fixtures    # 7 integration tests against fixtures/*.pcap
cargo test --test fuzz        # 3 deterministic robustness tests (mutated fixtures, random bytes)
```

`fixtures/*.pcap` are real-shaped classic-format pcap files — not truncated
or synthetic-looking — generated by `examples/gen_fixture.rs` (which builds
each Ethernet/IP/TCP/UDP/ICMP frame byte-for-byte, including correct
checksums, using the same `checksum` module the decoder verifies against).
They cover:

| Fixture | Scenario |
|---|---|
| `web_browsing.pcap` | Full TCP handshake, HTTP request/response, clean FIN close |
| `port_scan.pcap` | 8 unanswered SYNs from one source across distinct ports — the scan heuristic |
| `dns_lookup.pcap` | UDP/53 A-record query and answer |
| `icmp_ping.pcap` | ICMP echo request/reply |
| `tls_clienthello.pcap` | TCP handshake + a real TLS 1.2-record ClientHello carrying an SNI extension |

CI regenerates the fixtures on every run and fails if the committed copies
are stale, so the fixtures can never silently drift from the generator that
produced them. No fixture requires network access, root, or Npcap to
(re)generate — `cargo run --example gen_fixture` is enough.

## What this is not

- Not a Wireshark replacement — no dissector plugins, no deep-inspection of
  arbitrary application protocols, no packet editing/replay.
- Not a decryption tool — the TLS parser reads the plaintext ClientHello
  only; it does not, and structurally cannot, decrypt TLS traffic.
- Not a long-running monitor yet — live capture keeps every flow it has
  seen in memory for the whole run.
- **Defensive/diagnostic use only.** This is a tool for understanding
  traffic you already have permission to observe (your own interface, a
  capture you were given), not for intercepting anyone else's.

## Security

Captures are untrusted input. Every parser is bounds-checked and fuzzed
(`tests/fuzz.rs`), and names taken from packets (TLS SNI, DNS queries) are
escaped before they reach your terminal or the JSON output. See
[SECURITY.md](SECURITY.md) for the threat model and how to report issues.

## License

MIT — see [LICENSE](LICENSE).
