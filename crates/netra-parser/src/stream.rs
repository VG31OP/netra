use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::net::IpAddr;
use etherparse::{SlicedPacket, TransportSlice};
use netra_protocols::TcpSegmentDetails;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub ip_a: IpAddr,
    pub port_a: u16,
    pub ip_b: IpAddr,
    pub port_b: u16,
}

impl StreamKey {
    pub fn normalized(ip1: IpAddr, port1: u16, ip2: IpAddr, port2: u16) -> (Self, bool) {
        if (ip1, port1) <= (ip2, port2) {
            (
                Self {
                    ip_a: ip1,
                    port_a: port1,
                    ip_b: ip2,
                    port_b: port2,
                },
                true,
            )
        } else {
            (
                Self {
                    ip_a: ip2,
                    port_a: port2,
                    ip_b: ip1,
                    port_b: port1,
                },
                false,
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamSegment {
    pub is_a_to_b: bool,
    pub seq: u32,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct TcpStreamReassembler {
    pub streams: HashMap<StreamKey, Vec<StreamSegment>>,
}

impl TcpStreamReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_packet(&mut self, raw_packet: &[u8]) {
        if let Ok(sliced) = SlicedPacket::from_ethernet(raw_packet) {
            let (src_ip, dst_ip) = match &sliced.net {
                Some(etherparse::NetSlice::Ipv4(ip)) => {
                    (IpAddr::V4(ip.header().source_addr()), IpAddr::V4(ip.header().destination_addr()))
                }
                Some(etherparse::NetSlice::Ipv6(ip)) => {
                    (IpAddr::V6(ip.header().source_addr()), IpAddr::V6(ip.header().destination_addr()))
                }
                _ => return,
            };

            if let Some(TransportSlice::Tcp(tcp)) = &sliced.transport {
                let payload = tcp.payload();
                if payload.is_empty() {
                    return;
                }

                let src_port = tcp.source_port();
                let dst_port = tcp.destination_port();
                let seq = if let Ok(det) = TcpSegmentDetails::parse(tcp.slice()) {
                    det.sequence_number
                } else {
                    0
                };

                let (key, is_a_to_b) = StreamKey::normalized(src_ip, src_port, dst_ip, dst_port);
                let segments = self.streams.entry(key).or_default();
                segments.push(StreamSegment {
                    is_a_to_b,
                    seq,
                    data: payload.to_vec(),
                });
            }
        }
    }

    pub fn list_streams(&self) -> Vec<StreamKey> {
        self.streams.keys().cloned().collect()
    }

    pub fn follow_stream(&self, key: &StreamKey) -> Option<String> {
        let segments = self.streams.get(key)?;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "================================================================================"
        );
        let _ = writeln!(
            out,
            "NETRA Follow TCP Stream: {}:{} <--> {}:{}",
            key.ip_a, key.port_a, key.ip_b, key.port_b
        );
        let _ = writeln!(
            out,
            "================================================================================"
        );

        // Sort segments chronologically / by sequence
        let mut sorted = segments.clone();
        sorted.sort_by_key(|s| s.seq);

        for seg in sorted {
            let direction = if seg.is_a_to_b {
                format!("{}:{} -> {}:{}", key.ip_a, key.port_a, key.ip_b, key.port_b)
            } else {
                format!("{}:{} -> {}:{}", key.ip_b, key.port_b, key.ip_a, key.port_a)
            };

            let _ = writeln!(out, "\n--- [{}] ({} bytes) ---", direction, seg.data.len());
            let text = String::from_utf8_lossy(&seg.data);
            out.push_str(&text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }

        Some(out)
    }
}
