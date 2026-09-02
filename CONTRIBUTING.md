# Contributing to packetlens

Thanks for considering a contribution. This is a small, focused project —
here's how to work in it.

## Setup

```sh
git clone https://github.com/hellpuffyt/packetlens.git
cd packetlens
cargo test
```

No system dependencies are needed for the default build or test suite —
everything runs against the pcap fixtures in `fixtures/`.

## Project layout

- `src/pcap.rs` — classic libpcap file format reader.
- `src/checksum.rs` — RFC 1071 internet checksum.
- `src/decode.rs` — Ethernet/IPv4/IPv6/TCP/UDP/ICMP decoding.
- `src/dns.rs`, `src/tls.rs` — best-effort application-layer parsers (DNS questions/answers, TLS ClientHello/SNI).
- `src/flow.rs` — connection tracking and plain-English explanations.
- `src/tui.rs` — ratatui viewer (`--features tui`).
- `src/live.rs` — Linux raw-socket live capture (`--features live-capture`), not part of the default build.
- `examples/gen_fixture.rs` — regenerates every file under `fixtures/`.
- `tests/fixtures.rs` — integration tests over those fixtures.

## Adding a new fixture scenario

1. Add a frame-building function to `examples/gen_fixture.rs`.
2. Run `cargo run --example gen_fixture` to regenerate `fixtures/*.pcap`.
3. Write an integration test in `tests/fixtures.rs` asserting on the decoded/tracked/explained result.
4. Commit the regenerated fixture bytes alongside your test — CI fails if `fixtures/` is stale (see `.github/workflows/ci.yml`).

## Before opening a PR

```sh
cargo fmt
cargo clippy --all-targets --features tui -- -D warnings
cargo test --features tui
```

All three must be clean. Please keep the core decode/conntrack/explanation
path (everything outside `src/live.rs` and `src/tui.rs`'s render module)
free of any dependency that can't run in CI without capture privileges —
that portability guarantee is the whole point of this project's test
strategy.

## Reporting issues

Open a GitHub issue with the pcap fixture (or a byte sequence) that
reproduces the problem where possible; that turns directly into a
regression test.
