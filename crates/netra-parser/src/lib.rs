use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use chrono::{DateTime, TimeZone, Utc};
use etherparse::{SlicedPacket, TransportSlice};
use netra_common::{MacAddress, NetworkProtocol, PacketMetadata, NetraError, Result};
use netra_protocols::{ArpPacket, DnsMessage, HttpMetadata, TlsClientHello};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;

pub struct PacketParser;

impl PacketParser {
    pub fn parse_raw(packet_data: &[u8], index: u64, timestamp: DateTime<Utc>) -> Result<PacketMetadata> {
        let length = packet_data.len() as u32;

        let sliced = match SlicedPacket::from_ethernet(packet_data) {
            Ok(s) => s,
            Err(_) => {
                return Ok(PacketMetadata {
                    index,
                    timestamp,
                    source_mac: None,
                    destination_mac: None,
                    source_ip: None,
                    destination_ip: None,
                    source_port: None,
                    destination_port: None,
                    protocol: NetworkProtocol::Unknown("Raw".to_string()),
                    length,
                    summary: format!("Unparsed Ethernet frame ({} bytes)", length),
                });
            }
        };

        let mut source_mac = None;
        let mut destination_mac = None;
        let mut ether_type = 0u16;

        if let Some(eth) = &sliced.link {
            match eth {
                etherparse::LinkSlice::Ethernet2(e) => {
                    source_mac = Some(MacAddress(e.source()));
                    destination_mac = Some(MacAddress(e.destination()));
                    ether_type = e.ether_type().0;
                }
                _ => {}
            }
        }

        let mut source_ip = None;
        let mut destination_ip = None;
        let mut protocol = NetworkProtocol::Ethernet;
        let mut summary = String::new();

        if ether_type == 0x0806 {
            protocol = NetworkProtocol::Arp;
            if let Ok(parsed_arp) = ArpPacket::parse(packet_data.get(14..).unwrap_or(&[])) {
                summary = format!("ARP: {} is at {}", parsed_arp.sender_ip, parsed_arp.sender_mac);
            } else {
                summary = "ARP packet".to_string();
            }
        } else if let Some(net) = &sliced.net {
            match net {
                etherparse::NetSlice::Ipv4(ip) => {
                    source_ip = Some(IpAddr::V4(ip.header().source_addr()));
                    destination_ip = Some(IpAddr::V4(ip.header().destination_addr()));
                    protocol = NetworkProtocol::Ipv4;
                }
                etherparse::NetSlice::Ipv6(ip) => {
                    source_ip = Some(IpAddr::V6(ip.header().source_addr()));
                    destination_ip = Some(IpAddr::V6(ip.header().destination_addr()));
                    protocol = NetworkProtocol::Ipv6;
                }
            }
        }

        let mut source_port = None;
        let mut destination_port = None;

        if let Some(transport) = &sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    protocol = NetworkProtocol::Tcp;
                    source_port = Some(tcp.source_port());
                    destination_port = Some(tcp.destination_port());

                    let payload = tcp.payload();
                    if let Ok(tls) = TlsClientHello::parse(payload) {
                        protocol = NetworkProtocol::Tls;
                        if let Some(sni) = tls.server_name {
                            summary = format!("TLS Client Hello (SNI: {})", sni);
                        } else {
                            summary = "TLS Handshake".to_string();
                        }
                    } else if let Ok(http) = HttpMetadata::parse(payload) {
                        protocol = NetworkProtocol::Http;
                        if let (Some(m), Some(u)) = (http.method, http.uri) {
                            summary = format!("HTTP {} {}", m, u);
                        } else if let Some(code) = http.status_code {
                            summary = format!("HTTP Response {}", code);
                        }
                    } else {
                        summary = format!("TCP: {} -> {} ({} bytes)", tcp.source_port(), tcp.destination_port(), payload.len());
                    }
                }
                TransportSlice::Udp(udp) => {
                    protocol = NetworkProtocol::Udp;
                    source_port = Some(udp.source_port());
                    destination_port = Some(udp.destination_port());

                    let payload = udp.payload();
                    if udp.source_port() == 53 || udp.destination_port() == 53 {
                        if let Ok(dns) = DnsMessage::parse(payload) {
                            protocol = NetworkProtocol::Dns;
                            let role = if dns.is_response { "Response" } else { "Query" };
                            let names = if dns.query_names.is_empty() {
                                "(none)".to_string()
                            } else {
                                dns.query_names.join(", ")
                            };
                            summary = format!("DNS {} for {}", role, names);
                        } else {
                            summary = "DNS Packet".to_string();
                        }
                    } else {
                        summary = format!("UDP: {} -> {} ({} bytes)", udp.source_port(), udp.destination_port(), payload.len());
                    }
                }
                TransportSlice::Icmpv4(_) => {
                    protocol = NetworkProtocol::Icmp;
                    summary = "ICMPv4 Echo/Information".to_string();
                }
                TransportSlice::Icmpv6(_) => {
                    protocol = NetworkProtocol::Icmp;
                    summary = "ICMPv6 Message".to_string();
                }
            }
        }

        if summary.is_empty() {
            summary = format!("{} packet ({} bytes)", protocol, length);
        }

        Ok(PacketMetadata {
            index,
            timestamp,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            length,
            summary,
        })
    }
}

pub struct CaptureFileReader;

impl CaptureFileReader {
    pub fn read_file<P: AsRef<Path>, F: FnMut(PacketMetadata) -> bool>(
        path: P,
        mut on_packet: F,
    ) -> Result<u64> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;

        let ext = path_ref
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let mut index = 0u64;

        if ext == "pcapng" {
            let mut reader = PcapNgReader::new(file)
                .map_err(|e| NetraError::Parser(format!("Failed to open PCAPNG: {}", e)))?;

            while let Some(block) = reader.next_block() {
                match block {
                    Ok(pcap_file::pcapng::Block::EnhancedPacket(epb)) => {
                        index += 1;
                        let ts_nanos = epb.timestamp.as_nanos();
                        let secs = (ts_nanos / 1_000_000_000) as i64;
                        let subsec = (ts_nanos % 1_000_000_000) as u32;
                        let timestamp = Utc.timestamp_opt(secs, subsec).single().unwrap_or_else(Utc::now);

                        if let Ok(meta) = PacketParser::parse_raw(&epb.data, index, timestamp) {
                            if !on_packet(meta) {
                                break;
                            }
                        }
                    }
                    Ok(pcap_file::pcapng::Block::SimplePacket(spb)) => {
                        index += 1;
                        let timestamp = Utc::now();
                        if let Ok(meta) = PacketParser::parse_raw(&spb.data, index, timestamp) {
                            if !on_packet(meta) {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Corrupted PCAPNG block encountered: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            let mut reader = PcapReader::new(file)
                .map_err(|e| NetraError::Parser(format!("Failed to open PCAP: {}", e)))?;

            while let Some(packet_res) = reader.next_packet() {
                match packet_res {
                    Ok(pkt) => {
                        index += 1;
                        let secs = pkt.timestamp.as_secs() as i64;
                        let subsec_nanos = pkt.timestamp.subsec_nanos();
                        let timestamp = Utc.timestamp_opt(secs, subsec_nanos).single().unwrap_or_else(Utc::now);

                        if let Ok(meta) = PacketParser::parse_raw(&pkt.data, index, timestamp) {
                            if !on_packet(meta) {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Corrupted PCAP packet encountered: {}", e);
                        break;
                    }
                }
            }
        }

        Ok(index)
    }
}
