use std::net::Ipv4Addr;
use netra_common::{MacAddress, NetraError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub message_type: Option<DhcpMessageType>,
    pub transaction_id: u32,
    pub client_ip: Ipv4Addr,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub client_mac: MacAddress,
    pub requested_ip: Option<Ipv4Addr>,
    pub host_name: Option<String>,
}

impl DhcpInfo {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        // BOOTP/DHCP header is at least 240 bytes
        if payload.len() < 240 {
            return Err(NetraError::Parser("DHCP payload truncated".into()));
        }

        let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
        let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
        let siaddr = Ipv4Addr::new(payload[20], payload[21], payload[22], payload[23]);

        let mut mac_bytes = [0u8; 6];
        mac_bytes.copy_from_slice(&payload[28..34]);
        let client_mac = MacAddress(mac_bytes);

        // Magic cookie: 99, 130, 83, 99 (0x63825363)
        let magic_cookie = &payload[236..240];
        if magic_cookie != [0x63, 0x82, 0x53, 0x63] {
            return Err(NetraError::Parser("Invalid DHCP magic cookie".into()));
        }

        let mut message_type = None;
        let mut requested_ip = None;
        let mut host_name = None;

        let mut offset = 240;
        while offset < payload.len() {
            let opt = payload[offset];
            if opt == 255 {
                break; // End option
            }
            if opt == 0 {
                offset += 1; // Pad option
                continue;
            }

            if offset + 1 >= payload.len() {
                break;
            }
            let len = payload[offset + 1] as usize;
            offset += 2;

            if offset + len > payload.len() {
                break;
            }
            let opt_data = &payload[offset..offset + len];

            match opt {
                53 if len >= 1 => {
                    // DHCP Message Type
                    message_type = Some(match opt_data[0] {
                        1 => DhcpMessageType::Discover,
                        2 => DhcpMessageType::Offer,
                        3 => DhcpMessageType::Request,
                        4 => DhcpMessageType::Decline,
                        5 => DhcpMessageType::Ack,
                        6 => DhcpMessageType::Nak,
                        7 => DhcpMessageType::Release,
                        8 => DhcpMessageType::Inform,
                        other => DhcpMessageType::Unknown(other),
                    });
                }
                50 if len >= 4 => {
                    // Requested IP Address
                    requested_ip = Some(Ipv4Addr::new(
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ));
                }
                12 if len > 0 => {
                    // Host Name
                    host_name = String::from_utf8(opt_data.to_vec()).ok();
                }
                _ => {}
            }

            offset += len;
        }

        Ok(Self {
            message_type,
            transaction_id: xid,
            client_ip: ciaddr,
            your_ip: yiaddr,
            server_ip: siaddr,
            client_mac,
            requested_ip,
            host_name,
        })
    }
}
