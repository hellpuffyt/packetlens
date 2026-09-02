//! Minimal reader for the classic libpcap file format (the format tcpdump,
//! Wireshark, and `pcap_dump()` write by default — RFC-less but documented
//! at <https://www.tcpdump.org/manpages/pcap-savefile.5.html>).
//!
//! Only reading is implemented since packetlens's job is to decode captures,
//! not produce them (the fixture generator in `examples/gen_fixture.rs`
//! writes files by hand to keep this module honest about what it parses).

use std::fmt;

pub const LINKTYPE_ETHERNET: u32 = 1;

const MAGIC_MICRO_LE: u32 = 0xa1b2_c3d4;
const MAGIC_NANO_LE: u32 = 0xa1b2_3c4d;
const MAGIC_MICRO_BE: u32 = 0xd4c3_b2a1;
const MAGIC_NANO_BE: u32 = 0x4d3c_b2a1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeResolution {
    Micros,
    Nanos,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    pub endianness: Endianness,
    pub resolution: TimeResolution,
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub linktype: u32,
}

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub ts_secs: u32,
    pub ts_frac: u32,
    /// Number of octets actually captured and saved in the file.
    pub captured_len: u32,
    /// Length of the packet as it appeared on the wire (may exceed
    /// `captured_len` if the capture was snapped short).
    pub original_len: u32,
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Timestamp normalized to microseconds since the Unix epoch.
    pub fn timestamp_micros(&self, resolution: TimeResolution) -> u64 {
        let frac_us = match resolution {
            TimeResolution::Micros => self.ts_frac as u64,
            TimeResolution::Nanos => self.ts_frac as u64 / 1000,
        };
        self.ts_secs as u64 * 1_000_000 + frac_us
    }
}

#[derive(Debug)]
pub enum PcapError {
    TooShort {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    BadMagic(u32),
    Truncated {
        expected: usize,
        available: usize,
    },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::TooShort { context, needed, available } => write!(
                f,
                "truncated pcap file while reading {context}: needed {needed} bytes, had {available}"
            ),
            PcapError::BadMagic(magic) => {
                write!(f, "not a pcap file: unrecognized magic number 0x{magic:08x}")
            }
            PcapError::Truncated { expected, available } => write!(
                f,
                "packet record truncated: header claims {expected} bytes but only {available} remain"
            ),
        }
    }
}

impl std::error::Error for PcapError {}

/// A parsed classic-format pcap file: one global header plus zero or more
/// packet records, in file order.
pub struct PcapFile {
    pub header: GlobalHeader,
    pub packets: Vec<RawPacket>,
}

fn read_u16(buf: &[u8], endianness: Endianness) -> u16 {
    let arr = [buf[0], buf[1]];
    match endianness {
        Endianness::Little => u16::from_le_bytes(arr),
        Endianness::Big => u16::from_be_bytes(arr),
    }
}

fn read_u32(buf: &[u8], endianness: Endianness) -> u32 {
    let arr = [buf[0], buf[1], buf[2], buf[3]];
    match endianness {
        Endianness::Little => u32::from_le_bytes(arr),
        Endianness::Big => u32::from_be_bytes(arr),
    }
}

pub fn parse(bytes: &[u8]) -> Result<PcapFile, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::TooShort {
            context: "global header",
            needed: 24,
            available: bytes.len(),
        });
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (endianness, resolution) = match magic {
        MAGIC_MICRO_LE => (Endianness::Little, TimeResolution::Micros),
        MAGIC_NANO_LE => (Endianness::Little, TimeResolution::Nanos),
        MAGIC_MICRO_BE => (Endianness::Big, TimeResolution::Micros),
        MAGIC_NANO_BE => (Endianness::Big, TimeResolution::Nanos),
        other => return Err(PcapError::BadMagic(other)),
    };
    let version_major = read_u16(&bytes[4..6], endianness);
    let version_minor = read_u16(&bytes[6..8], endianness);
    // bytes[8..12] thiszone, bytes[12..16] sigfigs: both historical, unused.
    let snaplen = read_u32(&bytes[16..20], endianness);
    let linktype = read_u32(&bytes[20..24], endianness);

    let header = GlobalHeader {
        endianness,
        resolution,
        version_major,
        version_minor,
        snaplen,
        linktype,
    };

    let mut offset = 24;
    let mut packets = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(PcapError::TooShort {
                context: "packet record header",
                needed: 16,
                available: bytes.len() - offset,
            });
        }
        let ts_secs = read_u32(&bytes[offset..offset + 4], endianness);
        let ts_frac = read_u32(&bytes[offset + 4..offset + 8], endianness);
        let captured_len = read_u32(&bytes[offset + 8..offset + 12], endianness);
        let original_len = read_u32(&bytes[offset + 12..offset + 16], endianness);
        offset += 16;

        let data_end = offset
            .checked_add(captured_len as usize)
            .ok_or(PcapError::Truncated {
                expected: captured_len as usize,
                available: 0,
            })?;
        if data_end > bytes.len() {
            return Err(PcapError::Truncated {
                expected: captured_len as usize,
                available: bytes.len() - offset,
            });
        }
        let data = bytes[offset..data_end].to_vec();
        offset = data_end;

        packets.push(RawPacket {
            ts_secs,
            ts_frac,
            captured_len,
            original_len,
            data,
        });
    }

    Ok(PcapFile { header, packets })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_header(magic: [u8; 4]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&magic);
        h.extend_from_slice(&2u16.to_le_bytes()); // version major
        h.extend_from_slice(&4u16.to_le_bytes()); // version minor
        h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        h.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        h.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        h
    }

    #[test]
    fn parses_empty_capture() {
        let bytes = minimal_header([0xd4, 0xc3, 0xb2, 0xa1]);
        let file = parse(&bytes).unwrap();
        assert_eq!(file.header.endianness, Endianness::Little);
        assert_eq!(file.header.resolution, TimeResolution::Micros);
        assert_eq!(file.header.linktype, LINKTYPE_ETHERNET);
        assert!(file.packets.is_empty());
    }

    #[test]
    fn parses_one_record() {
        let mut bytes = minimal_header([0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&100u32.to_le_bytes()); // ts_secs
        bytes.extend_from_slice(&200u32.to_le_bytes()); // ts_frac
        bytes.extend_from_slice(&3u32.to_le_bytes()); // captured_len
        bytes.extend_from_slice(&3u32.to_le_bytes()); // original_len
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let file = parse(&bytes).unwrap();
        assert_eq!(file.packets.len(), 1);
        assert_eq!(file.packets[0].data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(
            file.packets[0].timestamp_micros(TimeResolution::Micros),
            100_000_200
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = vec![0u8; 24];
        assert!(matches!(parse(&bytes), Err(PcapError::BadMagic(_))));
    }

    #[test]
    fn rejects_short_header() {
        let bytes = vec![0u8; 10];
        assert!(matches!(parse(&bytes), Err(PcapError::TooShort { .. })));
    }

    #[test]
    fn rejects_truncated_record() {
        let mut bytes = minimal_header([0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&10u32.to_le_bytes()); // claims 10 bytes
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]); // only 3 present
        assert!(matches!(parse(&bytes), Err(PcapError::Truncated { .. })));
    }

    #[test]
    fn nanosecond_variant_detected() {
        let bytes = minimal_header([0x4d, 0x3c, 0xb2, 0xa1]);
        let file = parse(&bytes).unwrap();
        assert_eq!(file.header.resolution, TimeResolution::Nanos);
        assert_eq!(file.header.endianness, Endianness::Little);
    }

    #[test]
    fn big_endian_variant_detected() {
        // Build a header with genuinely big-endian fields under the
        // big-endian magic, since a real big-endian-host capture would.
        let mut h = Vec::new();
        h.extend_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4]); // magic (micro, BE)
        h.extend_from_slice(&2u16.to_be_bytes());
        h.extend_from_slice(&4u16.to_be_bytes());
        h.extend_from_slice(&0i32.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes());
        h.extend_from_slice(&65535u32.to_be_bytes());
        h.extend_from_slice(&LINKTYPE_ETHERNET.to_be_bytes());
        let file = parse(&h).unwrap();
        assert_eq!(file.header.endianness, Endianness::Big);
        assert_eq!(file.header.resolution, TimeResolution::Micros);
        assert_eq!(file.header.snaplen, 65535);
        assert_eq!(file.header.linktype, LINKTYPE_ETHERNET);
    }
}
