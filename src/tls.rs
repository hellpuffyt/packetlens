//! Minimal TLS record + handshake parser, just enough to pull the SNI
//! (server name) and offered version out of a ClientHello — the single most
//! useful "what is this flow actually talking to" signal on port 443, without
//! decrypting anything or depending on a TLS library.
//!
//! Only handles the plaintext ClientHello record: TLS record layer ->
//! handshake header -> legacy_version/random/session_id/cipher_suites/
//! compression -> extensions, looking specifically for the SNI extension
//! (type 0x0000) and, if present, ALPN (0x0010).

use std::fmt;

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;

#[derive(Debug)]
pub enum TlsError {
    NotHandshake,
    NotClientHello,
    TooShort { context: &'static str },
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::NotHandshake => write!(f, "not a TLS handshake record"),
            TlsError::NotClientHello => write!(f, "TLS handshake is not a ClientHello"),
            TlsError::TooShort { context } => write!(f, "TLS ClientHello truncated at {context}"),
        }
    }
}
impl std::error::Error for TlsError {}

#[derive(Debug, Clone)]
pub struct ClientHello {
    /// The TLS version advertised in the record header (e.g. 0x0301 = TLS 1.0
    /// wire version, which is what a TLS-1.3-capable client still sends here
    /// for middlebox compatibility — the real max version lives in the
    /// `supported_versions` extension, which this parser does not decode).
    pub legacy_record_version: u16,
    pub handshake_version: u16,
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub cipher_suite_count: usize,
}

fn version_name(v: u16) -> &'static str {
    match v {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2 (or 1.3 via extension)",
        0x0300 => "SSL 3.0",
        _ => "unknown/reserved",
    }
}

pub fn version_label(v: u16) -> &'static str {
    version_name(v)
}

/// Parses a TLS ClientHello starting at the beginning of `data`, which must
/// be the first bytes of a TCP payload (i.e. `data[0]` is the TLS record
/// content type byte). Returns `Err` for anything that isn't a plaintext
/// ClientHello — most commonly because the flow doesn't start the payload we
/// captured (mid-stream) or because it's some other TLS record type.
pub fn parse_client_hello(data: &[u8]) -> Result<ClientHello, TlsError> {
    if data.len() < 5 {
        return Err(TlsError::TooShort {
            context: "record header",
        });
    }
    if data[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(TlsError::NotHandshake);
    }
    let legacy_record_version = u16::from_be_bytes([data[1], data[2]]);
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let body_start = 5;
    let body_end = (body_start + record_len).min(data.len());
    let body = &data[body_start..body_end];

    if body.len() < 4 {
        return Err(TlsError::TooShort {
            context: "handshake header",
        });
    }
    if body[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(TlsError::NotClientHello);
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let hs_end = (4 + hs_len).min(body.len());
    let hs = &body[4..hs_end];

    let mut pos = 0usize;
    if hs.len() < 2 {
        return Err(TlsError::TooShort {
            context: "client version",
        });
    }
    let handshake_version = u16::from_be_bytes([hs[0], hs[1]]);
    pos += 2;

    // random: 32 bytes
    if hs.len() < pos + 32 {
        return Err(TlsError::TooShort { context: "random" });
    }
    pos += 32;

    // session_id: 1-byte length prefix
    if hs.len() < pos + 1 {
        return Err(TlsError::TooShort {
            context: "session id length",
        });
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;
    if hs.len() < pos {
        return Err(TlsError::TooShort {
            context: "session id",
        });
    }

    // cipher_suites: 2-byte length prefix, then that many bytes (pairs)
    if hs.len() < pos + 2 {
        return Err(TlsError::TooShort {
            context: "cipher suites length",
        });
    }
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    if hs.len() < pos + cs_len {
        return Err(TlsError::TooShort {
            context: "cipher suites",
        });
    }
    let cipher_suite_count = cs_len / 2;
    pos += cs_len;

    // compression_methods: 1-byte length prefix
    if hs.len() < pos + 1 {
        return Err(TlsError::TooShort {
            context: "compression methods length",
        });
    }
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;
    if hs.len() < pos {
        return Err(TlsError::TooShort {
            context: "compression methods",
        });
    }

    let mut server_name = None;
    let mut alpn_protocols = Vec::new();

    // extensions: optional 2-byte total length, then a list of (type, len, data)
    if hs.len() >= pos + 2 {
        let ext_total_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(hs.len());
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
            let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
            let ext_data_start = pos + 4;
            let ext_data_end = (ext_data_start + ext_len).min(ext_end);
            let ext_data = &hs[ext_data_start..ext_data_end];

            match ext_type {
                EXT_SERVER_NAME => {
                    server_name = parse_sni(ext_data);
                }
                EXT_ALPN => {
                    alpn_protocols = parse_alpn(ext_data);
                }
                _ => {}
            }
            pos = ext_data_end;
        }
    }

    Ok(ClientHello {
        legacy_record_version,
        handshake_version,
        server_name,
        alpn_protocols,
        cipher_suite_count,
    })
}

fn parse_sni(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 2 {
        return None;
    }
    let mut pos = 2usize; // server_name_list length
    while pos + 3 <= ext_data.len() {
        let name_type = ext_data[pos];
        let name_len = u16::from_be_bytes([ext_data[pos + 1], ext_data[pos + 2]]) as usize;
        let name_start = pos + 3;
        let name_end = (name_start + name_len).min(ext_data.len());
        if name_type == 0 {
            // host_name
            return Some(String::from_utf8_lossy(&ext_data[name_start..name_end]).into_owned());
        }
        pos = name_end;
    }
    None
}

fn parse_alpn(ext_data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    if ext_data.len() < 2 {
        return protocols;
    }
    let mut pos = 2usize; // protocol_name_list length
    while pos < ext_data.len() {
        let len = ext_data[pos] as usize;
        let start = pos + 1;
        let end = (start + len).min(ext_data.len());
        if start > ext_data.len() {
            break;
        }
        protocols.push(String::from_utf8_lossy(&ext_data[start..end]).into_owned());
        pos = end;
    }
    protocols
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a syntactically valid, minimal TLS 1.2-record ClientHello
    /// carrying an SNI extension for `hostname` and, optionally, ALPN.
    fn build_client_hello(hostname: &str, alpn: &[&str]) -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version TLS 1.2
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id len 0
        let cipher_suites: &[u16] = &[0x1301, 0x1302, 0xc02b];
        hs_body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for cs in cipher_suites {
            hs_body.extend_from_slice(&cs.to_be_bytes());
        }
        hs_body.push(1); // compression methods len 1
        hs_body.push(0); // null compression

        // Extensions
        let mut ext = Vec::new();
        // SNI
        let mut sni_list = Vec::new();
        sni_list.push(0u8); // host_name type
        sni_list.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(hostname.as_bytes());
        let mut sni_ext_body = Vec::new();
        sni_ext_body.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(&sni_list);
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_body);

        if !alpn.is_empty() {
            let mut alpn_list = Vec::new();
            for p in alpn {
                alpn_list.push(p.len() as u8);
                alpn_list.extend_from_slice(p.as_bytes());
            }
            let mut alpn_ext_body = Vec::new();
            alpn_ext_body.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
            alpn_ext_body.extend_from_slice(&alpn_list);
            ext.extend_from_slice(&EXT_ALPN.to_be_bytes());
            ext.extend_from_slice(&(alpn_ext_body.len() as u16).to_be_bytes());
            ext.extend_from_slice(&alpn_ext_body);
        }

        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_and_alpn() {
        let record = build_client_hello("example.com", &["h2", "http/1.1"]);
        let hello = parse_client_hello(&record).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn_protocols, vec!["h2", "http/1.1"]);
        assert_eq!(hello.handshake_version, 0x0303);
        assert_eq!(hello.cipher_suite_count, 3);
    }

    #[test]
    fn parses_sni_without_alpn() {
        let record = build_client_hello("api.internal.example", &[]);
        let hello = parse_client_hello(&record).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("api.internal.example"));
        assert!(hello.alpn_protocols.is_empty());
    }

    #[test]
    fn rejects_non_handshake_record() {
        let record = vec![23, 0x03, 0x03, 0x00, 0x00]; // content type 23 = application_data
        assert!(matches!(
            parse_client_hello(&record),
            Err(TlsError::NotHandshake)
        ));
    }

    #[test]
    fn rejects_short_input() {
        assert!(matches!(
            parse_client_hello(&[22, 3]),
            Err(TlsError::TooShort { .. })
        ));
    }

    #[test]
    fn version_label_known_values() {
        assert_eq!(version_label(0x0303), "TLS 1.2 (or 1.3 via extension)");
        assert_eq!(version_label(0xffff), "unknown/reserved");
    }
}
