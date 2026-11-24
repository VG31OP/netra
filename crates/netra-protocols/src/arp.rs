use std::net::Ipv4Addr;
use netra_common::{MacAddress, NetraError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 28 {
            return Err(NetraError::Parser("ARP payload truncated".into()));
        }

        let htype = u16::from_be_bytes([payload[0], payload[1]]);
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        let hlen = payload[4];
        let plen = payload[5];
        let op_code = u16::from_be_bytes([payload[6], payload[7]]);

        if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
            return Err(NetraError::Parser("Unsupported ARP hardware/protocol parameters".into()));
        }

        let mut smac = [0u8; 6];
        smac.copy_from_slice(&payload[8..14]);
        let sip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);

        let mut tmac = [0u8; 6];
        tmac.copy_from_slice(&payload[18..24]);
        let tip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);

        let operation = match op_code {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            other => ArpOperation::Unknown(other),
        };

        Ok(Self {
            operation,
            sender_mac: MacAddress(smac),
            sender_ip: sip,
            target_mac: MacAddress(tmac),
            target_ip: tip,
        })
    }
}
