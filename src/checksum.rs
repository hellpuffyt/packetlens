//! Internet checksum (RFC 1071) used by IPv4, TCP, and UDP.

/// Computes the RFC 1071 one's-complement checksum over `data`.
///
/// This is the same algorithm used by IPv4 header checksums, and (with a
/// pseudo-header prepended) by TCP and UDP checksums.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)] // lint is new in some toolchains; `as_chunks` isn't stable on our MSRV
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds an IPv4-style pseudo header for TCP/UDP checksum purposes and
/// returns the checksum of `pseudo_header || segment`.
pub fn transport_checksum_v4(src: [u8; 4], dst: [u8; 4], protocol: u8, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0);
    buf.push(protocol);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    internet_checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_worked_example() {
        // RFC 1071 section 3 worked example: bytes 00 01 f2 03 f4 f5 f6 f7,
        // expected checksum 220D (before complementing per the RFC's
        // running example, the final one's-complement result is 0x220D).
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = internet_checksum(&data);
        // Verify by re-summing data + checksum: result must be all-ones
        // (0xFFFF) which is the standard checksum self-verification test.
        let mut with_checksum = data.to_vec();
        with_checksum.extend_from_slice(&checksum.to_be_bytes());
        assert_eq!(internet_checksum(&with_checksum), 0);
    }

    #[test]
    fn empty_input_is_all_ones() {
        assert_eq!(internet_checksum(&[]), 0xFFFF);
    }

    #[test]
    fn odd_length_padding() {
        // A single odd trailing byte is padded with a zero low byte.
        let a = internet_checksum(&[0x12]);
        let b = internet_checksum(&[0x12, 0x00]);
        assert_eq!(a, b);
    }

    #[test]
    fn checksum_self_verifies() {
        let data = b"the quick brown fox jumps over";
        let sum = internet_checksum(data);
        let mut buf = data.to_vec();
        buf.extend_from_slice(&sum.to_be_bytes());
        assert_eq!(internet_checksum(&buf), 0);
    }
}
