use netra_common::{NetraError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlanHeader {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub encapsulated_proto: u16,
}

impl VlanHeader {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 4 {
            return Err(NetraError::Parser("802.1Q VLAN header truncated".into()));
        }

        let tci = u16::from_be_bytes([payload[0], payload[1]]);
        let priority = ((tci >> 13) & 0x07) as u8;
        let drop_eligible = ((tci >> 12) & 0x01) != 0;
        let vlan_id = tci & 0x0FFF;
        let encapsulated_proto = u16::from_be_bytes([payload[2], payload[3]]);

        Ok(Self {
            priority,
            drop_eligible,
            vlan_id,
            encapsulated_proto,
        })
    }
}
