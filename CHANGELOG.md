# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-09-02

### Added
- Classic-format pcap file reader (`pcap`), independent of any decoding.
- RFC 1071 internet checksum implementation shared by IPv4/TCP/UDP (`checksum`).
- Protocol decoder (`decode`) for Ethernet II (+ 802.1Q), IPv4, IPv6, TCP, UDP, and ICMP.
- Minimal DNS message parser (`dns`): questions, A-record answers, compression-pointer following with a loop guard.
- Minimal TLS ClientHello parser (`tls`): SNI and ALPN extraction without a TLS library.
- Bidirectional connection tracker (`flow`) with TCP handshake/close-state tracking, byte/packet counters, and a heuristic half-open-SYN port-scan detector.
- Plain-English flow explanations (`explain_flow`) that fold in TLS SNI and DNS query names when observed.
- `packetlens` CLI: text and `--json` report modes, `--scan-threshold`, and a pcap-file-only default build.
- Interactive `ratatui` TUI (`--features tui`, `--tui` flag) with a flow list and per-flow explanation pane.
- `live-capture` feature (Linux only, `AF_PACKET` raw socket) that feeds the same decode/flow pipeline from a real interface — needs `CAP_NET_RAW`/root, not exercised in CI.
- Hand-written pcap fixture generator (`examples/gen_fixture.rs`) producing real-shaped web-browsing, port-scan, DNS-lookup, ICMP-ping, and TLS-ClientHello captures for the test suite.
- 46+ unit and integration tests covering every decode/conntrack/explanation path from fixture bytes, runnable on any platform with no capture privileges.
- CI matrix (Linux/macOS/Windows) running tests, clippy, and rustfmt, plus a coverage job.
