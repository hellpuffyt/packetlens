//! Minimal DNS message parser: enough of RFC 1035 to show what a query or
//! response is actually asking for, without a general-purpose DNS library.
//!
//! Only the pieces the flow/explanation layer needs are exposed: header
//! flags, question count, and the decoded question/answer names + types.
//! Compression pointers (section 4.1.4) are followed with a hop limit so a
//! malformed or adversarial packet can't spin the parser into a loop.

use std::fmt;
use std::net::Ipv4Addr;

pub const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub enum DnsError {
    TooShort,
    BadPointer,
    NameTooLong,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::TooShort => write!(f, "dns message truncated"),
            DnsError::BadPointer => write!(f, "dns name compression pointer out of range"),
            DnsError::NameTooLong => write!(f, "dns name exceeds sanity limit"),
        }
    }
}
impl std::error::Error for DnsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    PTR,
    SOA,
    Other(u16),
}

impl RecordType {
    fn from_u16(v: u16) -> Self {
        match v {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            2 => RecordType::NS,
            12 => RecordType::PTR,
            6 => RecordType::SOA,
            other => RecordType::Other(other),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::NS => write!(f, "NS"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::Other(v) => write!(f, "TYPE{v}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: RecordType,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub name: String,
    pub rtype: RecordType,
    pub ttl: u32,
    /// Rendered value: an IPv4 dotted-quad for A records, otherwise a
    /// human-readable placeholder describing the record's size.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub truncated: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

const MAX_POINTER_HOPS: usize = 32;
const MAX_NAME_LEN: usize = 255;

fn read_name(data: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_of_name: Option<usize> = None; // position right after the name as first encountered
    let mut hops = 0usize;
    let mut total_len = 0usize;

    loop {
        if pos >= data.len() {
            return Err(DnsError::TooShort);
        }
        let len_byte = data[pos];
        if len_byte == 0 {
            if end_of_name.is_none() {
                end_of_name = Some(pos + 1);
            }
            break;
        } else if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(DnsError::TooShort);
            }
            if end_of_name.is_none() {
                end_of_name = Some(pos + 2);
            }
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return Err(DnsError::BadPointer);
            }
            let offset = (((len_byte & 0x3F) as usize) << 8) | data[pos + 1] as usize;
            if offset >= data.len() {
                return Err(DnsError::BadPointer);
            }
            pos = offset;
            continue;
        } else {
            let label_len = len_byte as usize;
            let label_start = pos + 1;
            let label_end = label_start + label_len;
            if label_end > data.len() {
                return Err(DnsError::TooShort);
            }
            total_len += label_len + 1;
            if total_len > MAX_NAME_LEN {
                return Err(DnsError::NameTooLong);
            }
            labels.push(String::from_utf8_lossy(&data[label_start..label_end]).into_owned());
            pos = label_end;
        }
    }

    Ok((labels.join("."), end_of_name.unwrap_or(pos)))
}

/// Parses a DNS message out of a UDP payload (or, byte-for-byte identically,
/// the body of a TCP DNS message once its 2-byte length prefix is stripped).
pub fn parse(data: &[u8]) -> Result<DnsMessage, DnsError> {
    if data.len() < 12 {
        return Err(DnsError::TooShort);
    }
    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut pos = 12;
    let mut questions = Vec::with_capacity(qdcount.min(64));
    for _ in 0..qdcount {
        let (name, next) = read_name(data, pos)?;
        if next + 4 > data.len() {
            return Err(DnsError::TooShort);
        }
        let qtype = u16::from_be_bytes([data[next], data[next + 1]]);
        pos = next + 4; // qtype + qclass
        questions.push(Question {
            name,
            qtype: RecordType::from_u16(qtype),
        });
    }

    let mut answers = Vec::with_capacity(ancount.min(64));
    for _ in 0..ancount {
        let (name, next) = read_name(data, pos)?;
        if next + 10 > data.len() {
            // Truncated answer section is common in snapped captures; stop
            // gracefully rather than failing the whole message.
            break;
        }
        let rtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let ttl = u32::from_be_bytes([
            data[next + 4],
            data[next + 5],
            data[next + 6],
            data[next + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[next + 8], data[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > data.len() {
            break;
        }
        let record_type = RecordType::from_u16(rtype);
        let value = match &record_type {
            RecordType::A if rdlength == 4 => Ipv4Addr::new(
                data[rdata_start],
                data[rdata_start + 1],
                data[rdata_start + 2],
                data[rdata_start + 3],
            )
            .to_string(),
            _ => format!("{rdlength} bytes"),
        };
        answers.push(Answer {
            name,
            rtype: record_type,
            ttl,
            value,
        });
        pos = rdata_end;
    }

    Ok(DnsMessage {
        transaction_id,
        is_response,
        opcode,
        rcode,
        truncated,
        questions,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(s: &str) -> Vec<u8> {
        let mut out = vec![s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn build_query(name_parts: &[&str], qtype: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // txid
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&0u16.to_be_bytes()); // ancount
        m.extend_from_slice(&0u16.to_be_bytes()); // nscount
        m.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for part in name_parts {
            m.extend_from_slice(&label(part));
        }
        m.push(0); // root
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // IN class
        m
    }

    #[test]
    fn parses_simple_a_query() {
        let msg = build_query(&["example", "com"], 1);
        let dns = parse(&msg).unwrap();
        assert!(!dns.is_response);
        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].name, "example.com");
        assert_eq!(dns.questions[0].qtype, RecordType::A);
    }

    #[test]
    fn parses_response_with_a_answer() {
        let mut m = build_query(&["example", "com"], 1);
        // Flip QR bit and set ancount to 1
        m[2] |= 0x80;
        m[7] = 1;
        // Answer: pointer back to question name (offset 12), type A, class IN, ttl, rdlength 4, ip
        m.extend_from_slice(&0xC00Cu16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[93, 184, 216, 34]);

        let dns = parse(&m).unwrap();
        assert!(dns.is_response);
        assert_eq!(dns.answers.len(), 1);
        assert_eq!(dns.answers[0].name, "example.com");
        assert_eq!(dns.answers[0].rtype, RecordType::A);
        assert_eq!(dns.answers[0].value, "93.184.216.34");
        assert_eq!(dns.answers[0].ttl, 300);
    }

    #[test]
    fn rejects_short_message() {
        assert!(matches!(parse(&[0u8; 5]), Err(DnsError::TooShort)));
    }

    #[test]
    fn compression_pointer_loop_is_rejected() {
        // A name that points to itself must not hang the parser.
        let mut m = vec![0u8; 12];
        m[4] = 0;
        m[5] = 1; // qdcount = 1
        m.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to offset 12 = itself
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            parse(&m),
            Err(DnsError::BadPointer) | Err(DnsError::TooShort)
        ));
    }

    #[test]
    fn record_type_display() {
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::Other(99).to_string(), "TYPE99");
    }
}
