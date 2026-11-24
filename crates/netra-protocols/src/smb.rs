#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbMessage {
    pub version: u8, // 1 for SMBv1, 2 for SMBv2/3
    pub command: u16,
    pub command_name: String,
    pub status: u32,
    pub is_response: bool,
}

impl SmbMessage {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < 4 {
            return None;
        }

        // Often prepended by 4-byte NetBIOS Session Service Header (0x00 + 3-byte len)
        let data = if payload[0] == 0x00 && payload.len() > 8 && (payload[4..8] == [0xff, b'S', b'M', b'B'] || payload[4..8] == [0xfe, b'S', b'M', b'B']) {
            &payload[4..]
        } else {
            payload
        };

        if data.len() < 8 {
            return None;
        }

        // SMBv1 magic: 0xFF 'S' 'M' 'B'
        if data.starts_with(&[0xff, b'S', b'M', b'B']) {
            let cmd = data[4];
            let status = if data.len() >= 9 {
                u32::from_le_bytes([data[5], data[6], data[7], data[8]])
            } else {
                0
            };
            let flags = if data.len() >= 10 { data[9] } else { 0 };
            let is_response = (flags & 0x80) != 0;

            let command_name = match cmd {
                0x72 => "Negotiate Protocol",
                0x73 => "Session Setup AndX",
                0x75 => "Tree Connect AndX",
                0x2e => "Read AndX",
                0x2f => "Write AndX",
                0x04 => "Close",
                0x2b => "Echo",
                _ => "SMBv1 Command",
            }
            .to_string();

            return Some(Self {
                version: 1,
                command: cmd as u16,
                command_name,
                status,
                is_response,
            });
        }

        // SMBv2/3 magic: 0xFE 'S' 'M' 'B'
        if data.starts_with(&[0xfe, b'S', b'M', b'B']) && data.len() >= 16 {
            let cmd = u16::from_le_bytes([data[12], data[13]]);
            let status = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            let flags = if data.len() >= 20 {
                u32::from_le_bytes([data[16], data[17], data[18], data[19]])
            } else {
                0
            };
            let is_response = (flags & 0x01) != 0;

            let command_name = match cmd {
                0x0000 => "Negotiate Protocol",
                0x0001 => "Session Setup",
                0x0002 => "Logoff",
                0x0003 => "Tree Connect",
                0x0004 => "Tree Disconnect",
                0x0005 => "Create",
                0x0006 => "Close",
                0x0007 => "Flush",
                0x0008 => "Read",
                0x0009 => "Write",
                0x000b => "Cancel",
                0x000d => "Echo",
                0x000e => "Query Directory",
                0x0010 => "Query Info",
                0x0011 => "Set Info",
                _ => "SMBv2/v3 Command",
            }
            .to_string();

            return Some(Self {
                version: 2,
                command: cmd,
                command_name,
                status,
                is_response,
            });
        }

        None
    }
}
