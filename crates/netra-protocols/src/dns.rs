use netra_common::{NetraError, Result};

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub query_names: Vec<String>,
}

impl DnsMessage {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 12 {
            return Err(NetraError::Parser("DNS packet header truncated".into()));
        }

        let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

        let mut query_names = Vec::new();
        let mut offset = 12;

        for _ in 0..qdcount {
            if offset >= payload.len() {
                break;
            }
            let (name, next_offset) = Self::parse_domain_name(payload, offset)?;
            query_names.push(name);
            offset = next_offset + 4; // skip QTYPE (2) + QCLASS (2)
        }

        Ok(Self {
            transaction_id,
            is_response,
            query_names,
        })
    }

    fn parse_domain_name(payload: &[u8], mut offset: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut looped = 0;

        while offset < payload.len() && looped < 20 {
            let len = payload[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }

            // Standard label (length < 64)
            if len < 64 {
                offset += 1;
                if offset + len > payload.len() {
                    return Err(NetraError::Parser("DNS label out of bounds".into()));
                }
                let label = String::from_utf8_lossy(&payload[offset..offset + len]);
                labels.push(label.to_string());
                offset += len;
            } else {
                // Pointer / compression: skip for lightweight identification
                offset += 2;
                break;
            }
            looped += 1;
        }

        Ok((labels.join("."), offset))
    }
}
