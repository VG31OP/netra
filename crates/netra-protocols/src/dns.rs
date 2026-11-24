use std::net::{Ipv4Addr, Ipv6Addr};
use netra_common::{NetraError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,
    SOA,
    NS,
    SRV,
    Unknown(u16),
}

impl DnsRecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: DnsRecordType,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub rcode: u8, // 0 = NoError, 3 = NXDomain, 2 = ServerFailure, etc.
    pub query_names: Vec<String>,
    pub query_types: Vec<DnsRecordType>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsMessage {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 12 {
            return Err(NetraError::Parser("DNS packet header truncated".into()));
        }

        let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let rcode = (flags & 0x000F) as u8;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        let mut query_names = Vec::new();
        let mut query_types = Vec::new();
        let mut offset = 12;

        for _ in 0..qdcount {
            if offset >= payload.len() {
                break;
            }
            let (name, next_offset) = Self::parse_domain_name(payload, offset)?;
            query_names.push(name);
            if next_offset + 4 <= payload.len() {
                let qtype = u16::from_be_bytes([payload[next_offset], payload[next_offset + 1]]);
                query_types.push(DnsRecordType::from_u16(qtype));
                offset = next_offset + 4; // skip QTYPE (2) + QCLASS (2)
            } else {
                offset = next_offset;
            }
        }

        let mut answers = Vec::new();
        for _ in 0..ancount {
            if offset >= payload.len() {
                break;
            }
            let (aname, after_name) = match Self::parse_domain_name(payload, offset) {
                Ok(res) => res,
                Err(_) => break,
            };
            if after_name + 10 > payload.len() {
                break;
            }
            let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
            let ttl = u32::from_be_bytes([
                payload[after_name + 4],
                payload[after_name + 5],
                payload[after_name + 6],
                payload[after_name + 7],
            ]);
            let rdlength = u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
            let data_offset = after_name + 10;
            if data_offset + rdlength > payload.len() {
                break;
            }

            let rtype = DnsRecordType::from_u16(atype);
            let data_str = match &rtype {
                DnsRecordType::A if rdlength == 4 => {
                    let ip = Ipv4Addr::new(
                        payload[data_offset],
                        payload[data_offset + 1],
                        payload[data_offset + 2],
                        payload[data_offset + 3],
                    );
                    ip.to_string()
                }
                DnsRecordType::AAAA if rdlength == 16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&payload[data_offset..data_offset + 16]);
                    let ip = Ipv6Addr::from(b);
                    ip.to_string()
                }
                DnsRecordType::CNAME | DnsRecordType::PTR => {
                    Self::parse_domain_name(payload, data_offset).map(|(s, _)| s).unwrap_or_else(|_| "cname".into())
                }
                _ => format!("<{} bytes data>", rdlength),
            };

            answers.push(DnsAnswer {
                name: aname,
                rtype,
                ttl,
                data: data_str,
            });

            offset = data_offset + rdlength;
        }

        Ok(Self {
            transaction_id,
            is_response,
            rcode,
            query_names,
            query_types,
            answers,
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

            if len < 64 {
                offset += 1;
                if offset + len > payload.len() {
                    return Err(NetraError::Parser("DNS label out of bounds".into()));
                }
                let label = String::from_utf8_lossy(&payload[offset..offset + len]);
                labels.push(label.to_string());
                offset += len;
            } else {
                offset += 2;
                break;
            }
            looped += 1;
        }

        Ok((labels.join("."), offset))
    }
}
