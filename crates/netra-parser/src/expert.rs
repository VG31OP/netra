use netra_common::{ExpertInfo, ExpertSeverity, PacketMetadata};

#[derive(Default)]
pub struct ExpertEngine;

impl ExpertEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&mut self, pkt: &PacketMetadata, raw_payload: &[u8]) -> Vec<ExpertInfo> {
        let mut alerts = Vec::new();

        // 1. Analyze TCP specifics
        if let (Some(_src_ip), Some(_dst_ip), Some(_src_port), Some(_dst_port)) =
            (pkt.source_ip, pkt.destination_ip, pkt.source_port, pkt.destination_port)
        {
            if let Some(flags) = &pkt.flags {
                if flags.rst {
                    alerts.push(ExpertInfo {
                        packet_index: pkt.index,
                        severity: ExpertSeverity::Error,
                        group: "Sequence".to_string(),
                        protocol: "TCP".to_string(),
                        message: "Connection reset by peer (RST flag set)".to_string(),
                    });
                }

                if flags.syn && !flags.ack {
                    alerts.push(ExpertInfo {
                        packet_index: pkt.index,
                        severity: ExpertSeverity::Chat,
                        group: "Connection".to_string(),
                        protocol: "TCP".to_string(),
                        message: "TCP Connection initiation (SYN)".to_string(),
                    });
                }

                if flags.fin {
                    alerts.push(ExpertInfo {
                        packet_index: pkt.index,
                        severity: ExpertSeverity::Chat,
                        group: "Connection".to_string(),
                        protocol: "TCP".to_string(),
                        message: "TCP Connection termination (FIN)".to_string(),
                    });
                }
            }

            // Inspect raw TCP window size if raw ethernet frame has TCP header
            if raw_payload.len() >= 34 {
                // Quick check for IPv4 TCP window size
                if raw_payload.get(12..14) == Some(&[0x08, 0x00]) && raw_payload.len() >= 54 {
                    let win = u16::from_be_bytes([raw_payload[48], raw_payload[49]]);
                    if win == 0 {
                        alerts.push(ExpertInfo {
                            packet_index: pkt.index,
                            severity: ExpertSeverity::Warn,
                            group: "Window".to_string(),
                            protocol: "TCP".to_string(),
                            message: "TCP Zero Window - Receiver flow control stall".to_string(),
                        });
                    }
                }
            }
        }

        // 2. Analyze HTTP specifics
        if let Some(status) = pkt.http_status {
            if status >= 500 {
                alerts.push(ExpertInfo {
                    packet_index: pkt.index,
                    severity: ExpertSeverity::Error,
                    group: "Response Code".to_string(),
                    protocol: "HTTP".to_string(),
                    message: format!("HTTP Server Error {}", status),
                });
            } else if status >= 400 {
                alerts.push(ExpertInfo {
                    packet_index: pkt.index,
                    severity: ExpertSeverity::Warn,
                    group: "Response Code".to_string(),
                    protocol: "HTTP".to_string(),
                    message: format!("HTTP Client Error {}", status),
                });
            } else {
                alerts.push(ExpertInfo {
                    packet_index: pkt.index,
                    severity: ExpertSeverity::Chat,
                    group: "Response Code".to_string(),
                    protocol: "HTTP".to_string(),
                    message: format!("HTTP Response {}", status),
                });
            }
        }

        // 3. Analyze DNS specifics
        if pkt.protocol == netra_common::NetworkProtocol::Dns {
            if let Some(name) = &pkt.dns_name {
                alerts.push(ExpertInfo {
                    packet_index: pkt.index,
                    severity: ExpertSeverity::Chat,
                    group: "Name Resolution".to_string(),
                    protocol: "DNS".to_string(),
                    message: format!("DNS resolution query for {}", name),
                });
            }
        }

        alerts
    }
}
