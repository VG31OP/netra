use netra_common::{NetraError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable(u8), // code: 0=net, 1=host, 3=port, etc.
    EchoRequest,
    TimeExceeded(u8),           // code: 0=ttl expired in transit
    ParameterProblem(u8),
    Unknown(u8, u8),
}

#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub icmp_type: IcmpType,
    pub identifier: Option<u16>,
    pub sequence_number: Option<u16>,
    pub summary: String,
}

impl IcmpInfo {
    pub fn parse_v4(payload: &[u8]) -> Result<Self> {
        if payload.len() < 4 {
            return Err(NetraError::Parser("ICMP packet truncated".into()));
        }

        let type_byte = payload[0];
        let code_byte = payload[1];
        let mut identifier = None;
        let mut sequence_number = None;

        let icmp_type = match type_byte {
            0 => {
                if payload.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([payload[4], payload[5]]));
                    sequence_number = Some(u16::from_be_bytes([payload[6], payload[7]]));
                }
                IcmpType::EchoReply
            }
            3 => IcmpType::DestinationUnreachable(code_byte),
            8 => {
                if payload.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([payload[4], payload[5]]));
                    sequence_number = Some(u16::from_be_bytes([payload[6], payload[7]]));
                }
                IcmpType::EchoRequest
            }
            11 => IcmpType::TimeExceeded(code_byte),
            other => IcmpType::Unknown(other, code_byte),
        };

        let summary = match &icmp_type {
            IcmpType::EchoRequest => format!(
                "Echo (ping) request id={:#06x}, seq={}",
                identifier.unwrap_or(0),
                sequence_number.unwrap_or(0)
            ),
            IcmpType::EchoReply => format!(
                "Echo (ping) reply id={:#06x}, seq={}",
                identifier.unwrap_or(0),
                sequence_number.unwrap_or(0)
            ),
            IcmpType::DestinationUnreachable(c) => match c {
                0 => "Destination Net Unreachable".to_string(),
                1 => "Destination Host Unreachable".to_string(),
                3 => "Destination Port Unreachable (UDP closed)".to_string(),
                _ => format!("Destination Unreachable (code {})", c),
            },
            IcmpType::TimeExceeded(_) => "Time-to-live exceeded in transit".to_string(),
            IcmpType::ParameterProblem(c) => format!("Parameter Problem (code {})", c),
            IcmpType::Unknown(t, c) => format!("ICMP type {}, code {}", t, c),
        };

        Ok(Self {
            icmp_type,
            identifier,
            sequence_number,
            summary,
        })
    }
}
