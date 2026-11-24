#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpMessage {
    pub leap_indicator: u8,
    pub version: u8,
    pub mode: u8,
    pub mode_name: String,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
}

impl NtpMessage {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < 48 {
            return None;
        }

        let first_byte = payload[0];
        let leap_indicator = (first_byte >> 6) & 0x03;
        let version = (first_byte >> 3) & 0x07;
        let mode = first_byte & 0x07;

        let mode_name = match mode {
            1 => "Symmetric Active",
            2 => "Symmetric Passive",
            3 => "Client",
            4 => "Server",
            5 => "Broadcast",
            6 => "NTP Control Message",
            7 => "Reserved for private use",
            _ => "Unknown",
        }
        .to_string();

        let stratum = payload[1];
        let poll = payload[2] as i8;
        let precision = payload[3] as i8;

        Some(Self {
            leap_indicator,
            version,
            mode,
            mode_name,
            stratum,
            poll,
            precision,
        })
    }
}
