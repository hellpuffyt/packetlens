# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Text output, the TUI and `--json` summaries interpolated TLS SNI and DNS
  names from packets verbatim, so a crafted capture or live packet could
  inject terminal escape sequences or bidi-override characters; they are now
  escaped (`flow::display_safe`). The JSON writer also escaped only `"`,
  `\` and `\n`, producing invalid JSON for other control characters; all of
  U+0000–U+001F are now escaped.
- `tui` feature: upgraded `ratatui` 0.29 → 0.30 (default features off,
  `crossterm` backend) and `crossterm` 0.28 → 0.29, removing `lru` 0.12
  (RUSTSEC-2026-0002, RUSTSEC-2026-0253: unsound) and `paste`
  (RUSTSEC-2024-0436: unmaintained) from the dependency tree. The `tui`
  feature now needs Rust 1.88.
- CI workflow now declares least-privilege `permissions: contents: read`.

### Fixed
- `fixtures/web_browsing.pcap`: the server's closing FIN acknowledged
  sequence number 2038 instead of 1039 (the request bytes plus the client's
  FIN), a typo in `examples/gen_fixture.rs`. A fixture test now checks
  every ACK in that capture against the peer's sequence space.
- Live capture printed the summary of the first flow sharing the packet's
  source IP, usually the wrong connection; `FlowTracker::ingest` now returns
  the flow the packet was accounted to and the live loop prints that one.
- `unsafe` blocks in `live.rs` now carry `SAFETY:` justifications.

### Added
- Deterministic fuzz tests (`tests/fuzz.rs`), `SECURITY.md`, `.editorconfig`.

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
