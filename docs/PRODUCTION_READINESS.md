# Production readiness — packetlens

Audit date: 2026-10-22. Tested commit: `5ba45ef` on branch
`audit/production-readiness` (this file was added in the next commit; no
code changed after the tested commit).

## Scope

packetlens reads classic pcap files (and, on Linux with the `live-capture`
feature, an `AF_PACKET` socket), decodes Ethernet/VLAN/IPv4/IPv6/TCP/UDP/
ICMP with checksum verification, peeks at DNS and TLS ClientHello payloads,
tracks bidirectional flows and explains each in one English sentence, with
text, `--json` and an optional ratatui TUI. Architecture: README
"Architecture". Maturity: 0.1.0.

## Platforms and prerequisites

| Path | Status here (macOS 27, Apple silicon, rustc 1.98.0) |
|---|---|
| pcap-file pipeline, text/JSON | built, tested, run |
| `--features tui` | built and tested (Rust ≥ 1.88; verified with `cargo +1.88 test --features tui --locked`); frame rendering verified via `examples/render_tui_snapshot.rs`; interactive use not driven (no TTY in this audit) |
| `--features live-capture` | Linux only; type-checked here with `cargo clippy --target x86_64-unknown-linux-gnu --features live-capture` (exit 0); **never executed** (needs Linux + `CAP_NET_RAW`) |
| Windows | `cargo clippy --target x86_64-pc-windows-msvc --all-targets --features tui` exit 0; tests run only in CI |

## Clean-clone verification (this audit)

```
git clone -b audit/production-readiness <repo> cc && cd cc
cargo run -- fixtures/port_scan.pcap                     # exit 0, "8 packets decoded … 8 flow(s)"
cargo run -- fixtures/web_browsing.pcap --json           # exit 0, valid JSON (python -m json.tool)
cargo run --features tui -- fixtures/port_scan.pcap --tui   # no TTY here: exits 1 "tui failed: Device not configured"
cargo run --features tui --example render_tui_snapshot   # exit 0, frame identical to README
cargo test                                               # exit 0: 49 passed, 0 failed, 0 ignored
cargo test --features tui                                # exit 0: 52 passed, 0 failed, 0 ignored
cargo test --test fixtures                               # exit 0: 7 passed
cargo run --example gen_fixture && git status --short    # fixtures regenerate byte-identical
```

## Commands executed (exit codes)

| Command | Before (main `d9f71dc`) | After (`5ba45ef`) |
|---|---|---|
| `cargo run --example gen_fixture` + `git diff --exit-code fixtures` | 0 / 0 | 0 / 0 |
| `cargo fmt -- --check` | 0 | 0 |
| `cargo clippy --all-targets -- -D warnings` (default / tui / live-capture) | 0 / 0 / 0 | 0 / 0 / 0 |
| same, `--target x86_64-unknown-linux-gnu --features live-capture` | — | 0 |
| `RUSTDOCFLAGS=-D warnings cargo doc --no-deps` (default / tui) | 101 (broken intra-doc link) | 0 / 0 |
| `cargo test` | 0: 43 passed (36 lib + 7 fixtures) | 0: 49 passed (38 lib + 1 bin + 7 fixtures + 3 fuzz), 0 ignored |
| `cargo test --features tui` | 0: 46 passed | 0: 52 passed, 0 ignored |
| `cargo audit --db <advisory-db 2026-10-22> --no-fetch` | 0 with 3 warnings: `lru` 0.12.5 RUSTSEC-2026-0002 + RUSTSEC-2026-0253 (unsound), `paste` RUSTSEC-2024-0436 (unmaintained), all via `ratatui` 0.29 | 0, no warnings (90 crates) |
| `gitleaks git` / `gitleaks dir` | — | no leaks found |

## CI status

Default branch (`main`, `d9f71dc`): **success** (run 33591301050). Audit
branch: pending until pushed. CI never ran `cargo doc` or `cargo audit`.

## Bugs found and fixed

| # | Severity | Defect | Fix | Regression test |
|---|---|---|---|---|
| 1 | Medium (security) | TLS SNI / DNS names from packets were printed raw: a crafted packet could inject terminal escape sequences (title/clear-screen/OSC) or bidi overrides into the analyst's terminal (text, TUI, live) | `flow::display_safe` escapes control + invisible/bidi chars in summaries | `flow::tests::hostile_names_are_escaped_in_summaries` (fails if the escaping is disabled) |
| 2 | Low | `--json` escaped only `"`, `\`, `\n`; other control chars produced invalid JSON | escape all U+0000–U+001F | `tests::json_escape_handles_every_control_character` (bin) |
| 3 | Medium (dependency) | `tui` pulled `lru` 0.12.5 (two unsoundness advisories) and unmaintained `paste` via `ratatui` 0.29 | `ratatui` 0.30 (default features off, crossterm backend), `crossterm` 0.29; one trait-bound change in `tui.rs` | cargo audit clean; TUI unit tests + snapshot example |
| 4 | Medium (wrong behaviour, live mode) | live loop printed the first flow sharing the packet's *source IP*, i.e. usually the wrong connection, and scanned all flows per packet | `FlowTracker::ingest` returns the packet's flow; loop prints it | `flow::tests::ingest_returns_the_packets_own_flow` (platform-independent; the live loop itself is untested) |
| 5 | Low (hygiene) | `unsafe` blocks without `SAFETY:` notes; CI workflow without `permissions:`; broken rustdoc link; README test counts wrong ("39 unit tests" for default build: was 36) | added notes, `permissions: contents: read`, fixed link and counts | — |

## Security review

- Untrusted input everywhere; parsers fuzzed (3 deterministic suites:
  15,000 mutated fixtures, 20,000 random buffers through the whole pipeline
  and DNS/TLS parsers, 20,000 structured DNS/TLS payloads) — no panics
  found in debug builds (overflow checks on).
- `unsafe` is confined to `live.rs` (libc socket/bind/recv/if_nametoindex).
- History: 3 pre-existing commits, no secret hits (pattern scan +
  gitleaks). No rotation needed. Note: commit author and `Cargo.toml`
  `authors` carry a personal name ("Prabesh Sharma") — pre-existing, left
  unchanged, flagged for the owner.

## Known limitations / unresolved risks

- Live capture never executed in this audit or in CI; unbounded flow-table
  growth in long live runs (documented in README/SECURITY).
- A truncated final pcap record makes the whole file fail to parse (no
  partial analysis).
- `tui::run`: if entering the alternate screen fails after raw mode was
  enabled, raw mode is not restored (not reproduced; code reading).
- Interactive TUI keys (`j`/`k`/`q`) not driven in a terminal here.
- No `LICENSE` change (MIT, kept). No `rust-version` in `Cargo.toml`; the
  `tui` feature now needs Rust 1.88 (documented).

## Acceptance checklist

| Item | Expected | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Decode all fixture protocols | correct headers/checksums | `cargo test --test fixtures`, lib unit tests | pass | 7 + 38 | `src/decode.rs`, `src/pcap.rs` |
| Flow tracking + explanations | one sentence per flow, as README | quickstart run | pass | matches README | `src/flow.rs` |
| Scan heuristic | 8 unanswered ports flagged | port_scan run | pass | "probed 8 ports" | `src/flow.rs` |
| JSON output valid | parses | `--json \| python -m json.tool` | pass | valid | `src/main.rs` |
| TUI renders | README frame | `render_tui_snapshot` | pass | identical | `src/tui.rs` |
| Hostile input never panics | no panic | `cargo test --test fuzz` | pass | 3/3 | `tests/fuzz.rs` |
| Packet text cannot drive the terminal | escaped | `hostile_names_are_escaped_in_summaries` | pass | ok | `src/flow.rs` |
| Fixtures reproducible | byte-identical | `gen_fixture` + git diff | pass | clean | `examples/gen_fixture.rs` |
| Live capture on Linux | summaries per flow | — | not run | needs Linux + CAP_NET_RAW | `src/live.rs` |
| Dependency/secret audit | clean | `cargo audit`, gitleaks | pass | clean | `Cargo.lock` |

## Classification proposal

**Partially Verified** — the pcap-file pipeline, JSON and TUI rendering are
verified from a clean clone with new security regression tests; the
Linux live-capture path is type-checked only and has never been executed,
and the interactive TUI was not driven in a real terminal.
