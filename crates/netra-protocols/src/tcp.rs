use netra_common::{NetraError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_bits(flags: u8) -> Self {
        Self {
            fin: (flags & 0x01) != 0,
            syn: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            psh: (flags & 0x08) != 0,
            ack: (flags & 0x10) != 0,
            urg: (flags & 0x20) != 0,
            ece: (flags & 0x40) != 0,
            cwr: (flags & 0x80) != 0,
        }
    }

    pub fn summary_string(&self) -> String {
        let mut list = Vec::new();
        if self.syn { list.push("SYN"); }
        if self.ack { list.push("ACK"); }
        if self.fin { list.push("FIN"); }
        if self.rst { list.push("RST"); }
        if self.psh { list.push("PSH"); }
        if self.urg { list.push("URG"); }
        if list.is_empty() {
            "[None]".to_string()
        } else {
            format!("[{}]", list.join(","))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpSegmentDetails {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub header_length: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub mss: Option<u16>,
}

impl TcpSegmentDetails {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 20 {
            return Err(NetraError::Parser("TCP header truncated".into()));
        }

        let source_port = u16::from_be_bytes([payload[0], payload[1]]);
        let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
        let sequence_number = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let acknowledgment_number = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

        let data_offset_byte = payload[12];
        let header_length = (data_offset_byte >> 4) * 4;
        let flags = TcpFlags::from_bits(payload[13]);
        let window_size = u16::from_be_bytes([payload[14], payload[15]]);
        let checksum = u16::from_be_bytes([payload[16], payload[17]]);
        let urgent_pointer = u16::from_be_bytes([payload[18], payload[19]]);

        let mut mss = None;
        if header_length > 20 && payload.len() >= header_length as usize {
            let mut opt_offset = 20;
            while opt_offset < header_length as usize {
                let kind = payload[opt_offset];
                if kind == 0 { break; } // End of Options
                if kind == 1 {
                    opt_offset += 1; // NOP
                    continue;
                }
                if opt_offset + 1 >= header_length as usize { break; }
                let opt_len = payload[opt_offset + 1] as usize;
                if opt_len < 2 || opt_offset + opt_len > header_length as usize { break; }

                if kind == 2 && opt_len == 4 {
                    mss = Some(u16::from_be_bytes([payload[opt_offset + 2], payload[opt_offset + 3]]));
                }

                opt_offset += opt_len;
            }
        }

        Ok(Self {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            header_length,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            mss,
        })
    }
}
