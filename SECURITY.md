# Security

## Threat model

packetlens reads packet captures and, with the Linux-only `live-capture`
feature, live traffic. Both are **untrusted input**: anyone who can put a
packet on the wire (or hand you a `.pcap`) controls the bytes the decoders
see.

| Threat | Defence | Evidence |
|---|---|---|
| Malformed or hostile capture crashes the tool | Every parser (`pcap`, `decode`, `dns`, `tls`) is bounds-checked and returns errors; DNS compression pointers have a loop guard | `tests/fuzz.rs` (mutated fixtures, random bytes, structured DNS/TLS payloads), unit tests |
| Terminal escape / bidi injection via names from packets | TLS SNI and DNS names are escaped before printing (`flow::display_safe`) | `flow::tests::hostile_names_are_escaped_in_summaries` |
| Invalid JSON from packet-derived text | `--json` escapes `"`, `\` and all control characters | `main` unit test `json_escape_handles_every_control_character` |

## Non-guarantees

- **Live capture runs with `CAP_NET_RAW`/root.** Grant it to the binary only
  on machines where you are allowed to observe traffic. The capture loop uses
  `unsafe` libc calls (`socket`, `bind`, `recv`), each with a `SAFETY:` note.
- **Memory grows with flows.** The tracker keeps every flow for the whole
  run; a long live capture on a busy or hostile network grows without bound.
- **Large captures are read fully into memory.**
- Live capture is not exercised in CI (no `CAP_NET_RAW` on runners).

## Reporting a vulnerability

Please report privately via
https://github.com/hellpuffyt/packetlens/security/advisories/new with a
capture (or generator) that reproduces the problem.
