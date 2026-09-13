//! Minimal TLS ClientHello SNI extraction (no crypto). Peeked bytes must be replayed.

/// True when `buf` contains a full TLS record header + payload.
pub fn has_complete_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    if buf[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= 5 + record_len
}

/// Returns `(sni, bytes_consumed_hint)` if a complete-enough ClientHello was parsed.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record: type(1)=22 handshake, ver(2), len(2)
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let hs = &buf[5..5 + record_len];
    // Handshake: type(1)=1 client_hello, len(3)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }
    let mut i = 4;
    // client_version(2) + random(32)
    if hs.len() < i + 34 {
        return None;
    }
    i += 34;
    // session_id
    if hs.len() < i + 1 {
        return None;
    }
    let sid_len = hs[i] as usize;
    i += 1 + sid_len;
    // cipher_suites
    if hs.len() < i + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2 + cs_len;
    // compression
    if hs.len() < i + 1 {
        return None;
    }
    let comp_len = hs[i] as usize;
    i += 1 + comp_len;
    // extensions
    if hs.len() < i + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2;
    if hs.len() < i + ext_len {
        return None;
    }
    let end = i + ext_len;
    while i + 4 <= end {
        let typ = u16::from_be_bytes([hs[i], hs[i + 1]]);
        let len = u16::from_be_bytes([hs[i + 2], hs[i + 3]]) as usize;
        i += 4;
        if i + len > end {
            break;
        }
        if typ == 0 {
            // server_name extension
            return parse_sni_list(&hs[i..i + len]);
        }
        i += len;
    }
    None
}

fn parse_sni_list(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    let mut i = 2;
    if ext.len() < 2 + list_len {
        return None;
    }
    while i + 3 <= ext.len() {
        let name_type = ext[i];
        let name_len = u16::from_be_bytes([ext[i + 1], ext[i + 2]]) as usize;
        i += 3;
        if i + name_len > ext.len() {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&ext[i..i + name_len])
                .ok()
                .map(|s| s.to_ascii_lowercase());
        }
        i += name_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Craft a minimal ClientHello with SNI=example.com for unit testing.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut sni_entry = Vec::new();
        sni_entry.push(0); // host_name
        sni_entry.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(host_bytes);

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(sni_entry.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni_entry);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // type server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.push(1); // compression methods len
        body.push(0); // null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut hs = Vec::new();
        hs.push(0x01); // client_hello
        let len = body.len();
        hs.push(((len >> 16) & 0xff) as u8);
        hs.push(((len >> 8) & 0xff) as u8);
        hs.push((len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_sni() {
        let pkt = client_hello_with_sni("www.youtube.com");
        assert_eq!(extract_sni(&pkt).as_deref(), Some("www.youtube.com"));
        assert!(has_complete_tls_record(&pkt));
    }

    #[test]
    fn partial_record_is_incomplete() {
        let pkt = client_hello_with_sni("www.substack.com");
        assert!(extract_sni(&pkt[..10]).is_none());
        assert!(!has_complete_tls_record(&pkt[..10]));
        assert_eq!(extract_sni(&pkt).as_deref(), Some("www.substack.com"));
    }
}
