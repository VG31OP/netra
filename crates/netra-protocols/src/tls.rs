use netra_common::{NetraError, Result};

#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub server_name: Option<String>,
    pub version: u16,
}

impl TlsClientHello {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        // Record layer header: [ContentType:1, Version:2, Length:2]
        if payload.len() < 5 || payload[0] != 0x16 {
            return Err(NetraError::Parser("Not a TLS Handshake record".into()));
        }

        let mut offset = 5;
        // Handshake type: 0x01 = Client Hello
        if offset >= payload.len() || payload[offset] != 0x01 {
            return Err(NetraError::Parser("Not a Client Hello message".into()));
        }

        offset += 4; // skip handshake type (1) + length (3)
        if offset + 2 > payload.len() {
            return Err(NetraError::Parser("Truncated Client Hello".into()));
        }

        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2 + 32; // skip client version (2) + random (32)

        if offset >= payload.len() {
            return Err(NetraError::Parser("Truncated Client Hello session id".into()));
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > payload.len() {
            return Err(NetraError::Parser("Truncated cipher suites length".into()));
        }
        let cipher_suites_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;

        if offset >= payload.len() {
            return Err(NetraError::Parser("Truncated compression methods length".into()));
        }
        let comp_len = payload[offset] as usize;
        offset += 1 + comp_len;

        if offset + 2 > payload.len() {
            return Ok(Self {
                server_name: None,
                version,
            });
        }

        let extensions_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        let end_extensions = offset + extensions_len;
        let mut server_name = None;

        while offset + 4 <= end_extensions && offset + 4 <= payload.len() {
            let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            offset += 4;

            if ext_type == 0 {
                // Server Name Indication (SNI) extension
                if offset + 5 <= payload.len() {
                    let _list_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                    let name_type = payload[offset + 2];
                    let name_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;

                    if name_type == 0 && offset + 5 + name_len <= payload.len() {
                        let name_bytes = &payload[offset + 5..offset + 5 + name_len];
                        server_name = std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
                    }
                }
                break;
            }

            offset += ext_len;
        }

        Ok(Self {
            server_name,
            version,
        })
    }
}
