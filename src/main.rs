use packetlens::{analyze, decode::Transport, flow::explain_flow};
use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
packetlens - a live, readable packet inspector

USAGE:
    packetlens <capture.pcap> [OPTIONS]
    packetlens live --iface <name>   (needs --features live-capture, Linux, root/CAP_NET_RAW)

OPTIONS:
    --json                 emit machine-readable JSON instead of text
    --tui                  open the interactive ratatui viewer (needs --features tui)
    --scan-threshold <N>   distinct unanswered ports before flagging a scan (default 4)
    -h, --help             print this help and exit
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") || args.is_empty() {
        print!("{USAGE}");
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }

    if args[0] == "live" {
        return run_live(&args[1..]);
    }

    let path = &args[0];
    let mut json = false;
    let mut tui = false;
    let mut scan_threshold: usize = 4;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--tui" => tui = true,
            "--scan-threshold" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(n) => scan_threshold = n,
                    None => {
                        eprintln!("error: --scan-threshold requires a number");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("error: unrecognized option '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: could not read '{path}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let analysis = match analyze(&bytes) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if tui {
        return run_tui(&analysis, scan_threshold);
    }

    if json {
        print!("{}", render_json(&analysis, scan_threshold));
    } else {
        print!("{}", render_text(&analysis, scan_threshold));
    }
    ExitCode::SUCCESS
}

#[cfg(feature = "tui")]
fn run_tui(analysis: &packetlens::Analysis, scan_threshold: usize) -> ExitCode {
    match packetlens::tui::run(analysis, scan_threshold) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: tui failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "tui"))]
fn run_tui(_analysis: &packetlens::Analysis, _scan_threshold: usize) -> ExitCode {
    eprintln!("error: this build was compiled without the interactive viewer.\nRebuild with `cargo build --features tui`.");
    ExitCode::FAILURE
}

fn render_text(analysis: &packetlens::Analysis, scan_threshold: usize) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(
        out,
        "packetlens: {} packets decoded ({} failed to decode), {} flow(s)",
        analysis.packets.len(),
        analysis.decode_failures,
        analysis.tracker.len()
    )
    .unwrap();
    writeln!(out).unwrap();

    let mut tcp = 0usize;
    let mut udp = 0usize;
    let mut icmp = 0usize;
    let mut other = 0usize;
    for pkt in &analysis.packets {
        match pkt.transport {
            Transport::Tcp(_) => tcp += 1,
            Transport::Udp(_) => udp += 1,
            Transport::Icmp(_) => icmp += 1,
            _ => other += 1,
        }
    }
    writeln!(
        out,
        "protocol breakdown: TCP={tcp} UDP={udp} ICMP={icmp} other={other}"
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "flows:").unwrap();
    for flow in analysis.tracker.flows() {
        writeln!(out, "  [{}] {}", flow.key.protocol, explain_flow(flow)).unwrap();
    }

    let scans = analysis.tracker.possible_scans(scan_threshold);
    if !scans.is_empty() {
        writeln!(out).unwrap();
        writeln!(
            out,
            "possible port scans (>= {scan_threshold} unanswered ports from one source):"
        )
        .unwrap();
        for scan in &scans {
            let ports: Vec<String> = scan
                .targets
                .iter()
                .map(|(ip, p)| format!("{ip}:{p}"))
                .collect();
            writeln!(
                out,
                "  {} probed {} ports with no reply: {}",
                scan.source,
                scan.targets.len(),
                ports.join(", ")
            )
            .unwrap();
        }
    }

    out
}

/// Hand-rolled minimal JSON string escaper (no serde dependency). Summaries
/// can contain text taken from packets (SNI, DNS names), so every character
/// JSON requires to be escaped (quote, backslash, U+0000–U+001F) is handled.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn render_json(analysis: &packetlens::Analysis, scan_threshold: usize) -> String {
    let mut flows_json = Vec::new();
    for flow in analysis.tracker.flows() {
        let init = format!("{}:{}", flow.initiator.0, flow.initiator.1);
        let resp = format!("{}:{}", flow.responder.0, flow.responder.1);
        flows_json.push(format!(
            "{{\"protocol\":\"{proto}\",\"initiator\":\"{init}\",\"responder\":\"{resp}\",\"packets\":{pkts},\"bytes\":{bytes},\"summary\":\"{summary}\"}}",
            proto = flow.key.protocol,
            pkts = flow.total_packets,
            bytes = flow.total_bytes(),
            summary = json_escape(&explain_flow(flow)),
        ));
    }
    let scans = analysis.tracker.possible_scans(scan_threshold);
    let scans_json: Vec<String> = scans
        .iter()
        .map(|s| {
            let ports: Vec<String> = s
                .targets
                .iter()
                .map(|(ip, p)| format!("\"{ip}:{p}\""))
                .collect();
            format!(
                "{{\"source\":\"{}\",\"targets\":[{}]}}",
                s.source,
                ports.join(",")
            )
        })
        .collect();

    format!(
        "{{\"packets_decoded\":{pkts},\"decode_failures\":{fail},\"flow_count\":{flows},\"flows\":[{flow_list}],\"possible_scans\":[{scan_list}]}}\n",
        pkts = analysis.packets.len(),
        fail = analysis.decode_failures,
        flows = analysis.tracker.len(),
        flow_list = flows_json.join(","),
        scan_list = scans_json.join(","),
    )
}

#[cfg(all(feature = "live-capture", target_os = "linux"))]
fn run_live(args: &[String]) -> ExitCode {
    let mut iface = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--iface" {
            iface = args.get(i + 1).cloned();
            i += 1;
        }
        i += 1;
    }
    let iface = match iface {
        Some(i) => i,
        None => {
            eprintln!("error: live capture requires --iface <name>");
            return ExitCode::from(2);
        }
    };
    match packetlens::live::capture_loop(&iface) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("hint: live capture needs CAP_NET_RAW (usually: run as root, or `sudo setcap cap_net_raw+ep`)");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(feature = "live-capture", target_os = "linux")))]
fn run_live(_args: &[String]) -> ExitCode {
    eprintln!(
        "error: this build was compiled without live capture support.\n\
         Live capture is a Linux-only, elevated-privilege feature: rebuild with\n\
         `cargo build --features live-capture` on Linux and run with CAP_NET_RAW or root."
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::json_escape;

    /// Regression: control characters other than `\n` were emitted raw,
    /// producing invalid JSON for summaries containing packet-derived text.
    #[test]
    fn json_escape_handles_every_control_character() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("\r\t\n"), "\\r\\t\\n");
        assert_eq!(json_escape("\u{1b}[2J\u{0}"), "\\u001b[2J\\u0000");
        for c in (0u8..0x20).map(char::from) {
            let e = json_escape(&c.to_string());
            assert!(e.starts_with('\\'), "{c:?} not escaped: {e:?}");
        }
    }
}
