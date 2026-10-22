//! Live capture from a real network interface using an `AF_PACKET` raw
//! socket on Linux.
//!
//! This is intentionally a separate, optional path from the always-tested
//! pcap-file pipeline in [`crate::analyze`]:
//!
//! - It requires `CAP_NET_RAW` (or root) — CI runners do not have this, and
//!   this module is not compiled or exercised by the default build or test
//!   suite. It only exists under `cargo build --features live-capture` on
//!   `target_os = "linux"`.
//! - Raw-socket behavior is genuinely OS-specific (Linux `AF_PACKET` vs.
//!   BSD/macOS `BPF` vs. Windows `Npcap`/`WinPcap`), so this module makes no
//!   claim to portability — only Linux is implemented here, honestly.
//!
//! Every captured frame is fed through the exact same [`crate::decode`] and
//! [`crate::flow`] logic used for pcap files, so there is only one decoder
//! in this codebase, not two.

use crate::decode::decode_packet;
use crate::flow::{explain_flow, FlowTracker};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

const ETH_P_ALL: u16 = 0x0003;

/// Opens a raw `AF_PACKET`/`SOCK_RAW` socket bound to `iface`, decodes each
/// frame as it arrives, feeds it into a [`FlowTracker`], and prints the
/// current plain-English summary of that packet's flow after every decoded
/// IP packet. Flow state is kept for the whole run (memory grows with the
/// number of distinct flows seen).
///
/// Runs until interrupted (Ctrl-C) or a read error occurs. Requires
/// `CAP_NET_RAW`; without it `socket(2)` fails with `EPERM`.
pub fn capture_loop(iface: &str) -> io::Result<()> {
    let fd = open_raw_socket(iface)?;
    println!("packetlens live: capturing on '{iface}' (Ctrl-C to stop)");
    let mut tracker = FlowTracker::new();
    let mut buf = vec![0u8; 65536];

    loop {
        // SAFETY: `fd` is an open socket owned by this function, and the
        // pointer/length pair describes `buf`, a live, exclusively borrowed
        // allocation of exactly `buf.len()` bytes.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let data = &buf[..n as usize];
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        if let Ok(pkt) = decode_packet(ts, n as u32, n as u32, data) {
            // The tracker returns the flow this exact packet was accounted
            // to (5-tuple match), not merely some flow sharing its source IP.
            if let Some(flow) = tracker.ingest(&pkt) {
                println!("{}", explain_flow(flow));
            }
        }
    }
}

fn open_raw_socket(iface: &str) -> io::Result<OwnedFd> {
    // SAFETY: plain libc calls with valid arguments. `raw_fd` is checked
    // before `OwnedFd` takes ownership (so it is closed exactly once, on every
    // path); `addr` is a fully zero-initialised `sockaddr_ll` (all-zero is a
    // valid value for this C struct) and the length passed to `bind` is its
    // exact size.
    unsafe {
        let raw_fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32);
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw_fd);

        let if_index = if_nametoindex(iface)?;
        let mut addr: libc::sockaddr_ll = mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = if_index as i32;

        let ret = libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}

fn if_nametoindex(iface: &str) -> io::Result<u32> {
    let c_name = std::ffi::CString::new(iface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a NUL byte",
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated C string that outlives the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: '{iface}'"),
        ));
    }
    Ok(index)
}
