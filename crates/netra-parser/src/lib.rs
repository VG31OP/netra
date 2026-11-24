pub mod stream;

pub use stream::{StreamKey, StreamSegment, TcpStreamReassembler};

use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use chrono::{DateTime, TimeZone, Utc};
use etherparse::{SlicedPacket, TransportSlice};
use netra_common::{MacAddress, NetraError, NetworkProtocol, PacketFlags, PacketMetadata, Result};
use netra_protocols::{
    ArpPacket, DhcpInfo, DnsMessage, HttpMetadata, IcmpInfo, NtpMessage, SmbMessage, SshBanner,
    SsdpMessage, TcpSegmentDetails, TlsClientHello,
};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;

#[derive(Debug, Clone)]
pub struct DissectedLayer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct PacketTree {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub length: u32,
    pub layers: Vec<DissectedLayer>,
}

pub struct HexDumpViewer;

impl HexDumpViewer {
    pub fn format(data: &[u8]) -> String {
        let mut out = String::new();
        let chunk_size = 16;

        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let offset = i * chunk_size;
            let _ = write!(out, "{:04x}   ", offset);

            // Hex portion
            for j in 0..chunk_size {
                if j == 8 {
                    out.push(' ');
                }
                if j < chunk.len() {
                    let _ = write!(out, "{:02x} ", chunk[j]);
                } else {
                    out.push_str("   ");
                }
            }

            out.push_str("  |");

            // ASCII portion
            for &b in chunk {
                if (0x20..=0x7e).contains(&b) {
                    out.push(b as char);
                } else {
                    out.push('.');
                }
            }
            out.push_str("|\n");
        }

        out
    }
}

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
                    flags: None,
                    sni: None,
                    dns_name: None,
                    http_method: None,
                    http_status: None,
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
        let mut flags = None;
        let mut sni = None;
        let mut dns_name = None;
        let mut http_method = None;
        let mut http_status = None;

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

                    let tcp_details = TcpSegmentDetails::parse(tcp.slice()).ok();
                    let flags_summary = if let Some(ref d) = tcp_details {
                        flags = Some(PacketFlags {
                            syn: d.flags.syn,
                            ack: d.flags.ack,
                            fin: d.flags.fin,
                            rst: d.flags.rst,
                            psh: d.flags.psh,
                        });
                        d.flags.summary_string()
                    } else {
                        String::new()
                    };

                    let payload = tcp.payload();
                    if let Ok(tls) = TlsClientHello::parse(payload) {
                        protocol = NetworkProtocol::Tls;
                        sni = tls.server_name.clone();
                        if let Some(ref s) = sni {
                            summary = format!("TLS Client Hello (SNI: {})", s);
                        } else {
                            summary = "TLS Handshake".to_string();
                        }
                    } else if let Ok(http) = HttpMetadata::parse(payload) {
                        protocol = NetworkProtocol::Http;
                        http_method = http.method.clone();
                        http_status = http.status_code;
                        if let (Some(ref m), Some(ref u)) = (&http.method, &http.uri) {
                            summary = format!("HTTP {} {}", m, u);
                        } else if let Some(code) = http.status_code {
                            summary = format!("HTTP Response {}", code);
                        }
                    } else if let Some(ssh) = SshBanner::parse(payload) {
                        protocol = NetworkProtocol::Ssh;
                        summary = format!("SSH-{} ({})", ssh.proto_version, ssh.software_version);
                    } else if let Some(smb) = SmbMessage::parse(payload) {
                        protocol = NetworkProtocol::Smb;
                        let dir = if smb.is_response { "Response" } else { "Request" };
                        summary = format!("SMBv{} {}: {}", smb.version, dir, smb.command_name);
                    } else {
                        summary = format!("TCP: {} -> {} {} seq={}",
                            tcp.source_port(),
                            tcp.destination_port(),
                            flags_summary,
                            tcp_details.as_ref().map(|d| d.sequence_number).unwrap_or(0)
                        );
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
                                dns_name = dns.query_names.first().cloned();
                                dns.query_names.join(", ")
                            };
                            summary = format!("DNS {} for {}", role, names);
                        } else {
                            summary = "DNS Packet".to_string();
                        }
                    } else if udp.source_port() == 5353 || udp.destination_port() == 5353 {
                        protocol = NetworkProtocol::Mdns;
                        if let Ok(dns) = DnsMessage::parse(payload) {
                            let role = if dns.is_response { "Response" } else { "Query" };
                            let names = dns.query_names.join(", ");
                            summary = format!("mDNS {} for {}", role, if names.is_empty() { "services" } else { &names });
                        } else {
                            summary = "mDNS Packet".to_string();
                        }
                    } else if udp.source_port() == 123 || udp.destination_port() == 123 {
                        if let Some(ntp) = NtpMessage::parse(payload) {
                            protocol = NetworkProtocol::Ntp;
                            summary = format!("NTP: {} (v{}, stratum {})", ntp.mode_name, ntp.version, ntp.stratum);
                        } else {
                            protocol = NetworkProtocol::Ntp;
                            summary = "NTP Packet".to_string();
                        }
                    } else if udp.source_port() == 67 || udp.destination_port() == 67 || udp.source_port() == 68 || udp.destination_port() == 68 {
                        if let Ok(dhcp) = DhcpInfo::parse(payload) {
                            protocol = NetworkProtocol::Dhcp;
                            let msg_name = match dhcp.message_type {
                                Some(ref t) => format!("{:?}", t),
                                None => "BOOTP".to_string(),
                            };
                            summary = format!("DHCP {}: xid={:#010x} client={}", msg_name, dhcp.transaction_id, dhcp.client_mac);
                        } else {
                            summary = "DHCP Packet".to_string();
                        }
                    } else if udp.destination_port() == 1900 {
                        if let Ok(ssdp) = SsdpMessage::parse(payload) {
                            protocol = NetworkProtocol::Ssdp;
                            summary = format!("SSDP: {}", ssdp.search_target.unwrap_or_else(|| "Discovery".to_string()));
                        } else {
                            summary = "SSDP Packet".to_string();
                        }
                    } else {
                        summary = format!("UDP: {} -> {} ({} bytes)", udp.source_port(), udp.destination_port(), payload.len());
                    }
                }
                TransportSlice::Icmpv4(icmp) => {
                    protocol = NetworkProtocol::Icmp;
                    if let Ok(info) = IcmpInfo::parse_v4(icmp.slice()) {
                        summary = format!("ICMPv4: {}", info.summary);
                    } else {
                        summary = "ICMPv4 Message".to_string();
                    }
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
            flags,
            sni,
            dns_name,
            http_method,
            http_status,
        })
    }

    pub fn dissect_tree(packet_data: &[u8], index: u64, timestamp: DateTime<Utc>) -> PacketTree {
        let length = packet_data.len() as u32;
        let mut layers = Vec::new();

        // Layer 1: Frame
        layers.push(DissectedLayer {
            name: format!("Frame {} ({} bytes)", index, length),
            fields: vec![
                ("Arrival Time".to_string(), timestamp.to_rfc3339()),
                ("Frame Length".to_string(), format!("{} bytes", length)),
            ],
        });

        // Layer 2: Ethernet
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet_data) {
            if let Some(etherparse::LinkSlice::Ethernet2(eth)) = &sliced.link {
                layers.push(DissectedLayer {
                    name: "Ethernet II".to_string(),
                    fields: vec![
                        ("Destination".to_string(), MacAddress(eth.destination()).to_string()),
                        ("Source".to_string(), MacAddress(eth.source()).to_string()),
                        ("Type".to_string(), format!("{:#06x}", eth.ether_type().0)),
                    ],
                });
            }

            // Layer 3: Network Layer
            if let Some(net) = &sliced.net {
                match net {
                    etherparse::NetSlice::Ipv4(ip) => {
                        layers.push(DissectedLayer {
                            name: "Internet Protocol Version 4".to_string(),
                            fields: vec![
                                ("Source Address".to_string(), ip.header().source_addr().to_string()),
                                ("Destination Address".to_string(), ip.header().destination_addr().to_string()),
                                ("TTL".to_string(), ip.header().ttl().to_string()),
                                ("Protocol".to_string(), ip.header().protocol().0.to_string()),
                            ],
                        });
                    }
                    etherparse::NetSlice::Ipv6(ip) => {
                        layers.push(DissectedLayer {
                            name: "Internet Protocol Version 6".to_string(),
                            fields: vec![
                                ("Source Address".to_string(), ip.header().source_addr().to_string()),
                                ("Destination Address".to_string(), ip.header().destination_addr().to_string()),
                                ("Hop Limit".to_string(), ip.header().hop_limit().to_string()),
                            ],
                        });
                    }
                }
            }

            // Layer 4: Transport Layer
            if let Some(transport) = &sliced.transport {
                match transport {
                    TransportSlice::Tcp(tcp) => {
                        let mut fields = vec![
                            ("Source Port".to_string(), tcp.source_port().to_string()),
                            ("Destination Port".to_string(), tcp.destination_port().to_string()),
                            ("Payload Length".to_string(), format!("{} bytes", tcp.payload().len())),
                        ];
                        if let Ok(details) = TcpSegmentDetails::parse(tcp.slice()) {
                            fields.push(("Sequence Number".to_string(), details.sequence_number.to_string()));
                            fields.push(("Acknowledgment Number".to_string(), details.acknowledgment_number.to_string()));
                            fields.push(("Flags".to_string(), details.flags.summary_string()));
                            fields.push(("Window Size".to_string(), details.window_size.to_string()));
                        }
                        layers.push(DissectedLayer {
                            name: "Transmission Control Protocol (TCP)".to_string(),
                            fields,
                        });
                    }
                    TransportSlice::Udp(udp) => {
                        layers.push(DissectedLayer {
                            name: "User Datagram Protocol (UDP)".to_string(),
                            fields: vec![
                                ("Source Port".to_string(), udp.source_port().to_string()),
                                ("Destination Port".to_string(), udp.destination_port().to_string()),
                                ("Length".to_string(), udp.length().to_string()),
                            ],
                        });
                    }
                    _ => {}
                }
            }

            // Layer 5: Application Layer
            if let Some(transport) = &sliced.transport {
                let payload = match transport {
                    TransportSlice::Tcp(tcp) => tcp.payload(),
                    TransportSlice::Udp(udp) => udp.payload(),
                    _ => &[],
                };

                if !payload.is_empty() {
                    if let Ok(dns) = DnsMessage::parse(payload) {
                        layers.push(DissectedLayer {
                            name: "Domain Name System (DNS)".to_string(),
                            fields: vec![
                                ("Transaction ID".to_string(), format!("{:#06x}", dns.transaction_id)),
                                ("Type".to_string(), if dns.is_response { "Response".to_string() } else { "Query".to_string() }),
                                ("Query Count".to_string(), dns.query_names.len().to_string()),
                                ("Query Names".to_string(), dns.query_names.join(", ")),
                            ],
                        });
                    } else if let Ok(http) = HttpMetadata::parse(payload) {
                        let mut fields = Vec::new();
                        if let Some(m) = http.method { fields.push(("Request Method".to_string(), m)); }
                        if let Some(u) = http.uri { fields.push(("Request URI".to_string(), u)); }
                        if let Some(h) = http.host { fields.push(("Host".to_string(), h)); }
                        if let Some(ua) = http.user_agent { fields.push(("User-Agent".to_string(), ua)); }
                        if let Some(c) = http.status_code { fields.push(("Status Code".to_string(), c.to_string())); }
                        layers.push(DissectedLayer {
                            name: "Hypertext Transfer Protocol (HTTP)".to_string(),
                            fields,
                        });
                    } else if let Ok(tls) = TlsClientHello::parse(payload) {
                        let mut fields = vec![
                            ("Handshake Type".to_string(), "Client Hello (1)".to_string()),
                            ("Version".to_string(), format!("{:#06x}", tls.version)),
                        ];
                        if let Some(sni) = tls.server_name {
                            fields.push(("Server Name Indication (SNI)".to_string(), sni));
                        }
                        layers.push(DissectedLayer {
                            name: "Transport Layer Security (TLS)".to_string(),
                            fields,
                        });
                    } else if let Some(ssh) = SshBanner::parse(payload) {
                        layers.push(DissectedLayer {
                            name: "Secure Shell (SSH)".to_string(),
                            fields: vec![
                                ("Protocol Version".to_string(), ssh.proto_version),
                                ("Software Version".to_string(), ssh.software_version),
                                ("Comments".to_string(), ssh.comments.unwrap_or_else(|| "-".to_string())),
                            ],
                        });
                    } else if let Some(smb) = SmbMessage::parse(payload) {
                        layers.push(DissectedLayer {
                            name: format!("Server Message Block (SMBv{})", smb.version),
                            fields: vec![
                                ("Command".to_string(), format!("{} ({:#06x})", smb.command_name, smb.command)),
                                ("Direction".to_string(), if smb.is_response { "Response" } else { "Request" }.to_string()),
                                ("NT Status".to_string(), format!("{:#010x}", smb.status)),
                            ],
                        });
                    } else if let Some(ntp) = NtpMessage::parse(payload) {
                        layers.push(DissectedLayer {
                            name: "Network Time Protocol (NTP)".to_string(),
                            fields: vec![
                                ("Mode".to_string(), ntp.mode_name),
                                ("Version".to_string(), ntp.version.to_string()),
                                ("Stratum".to_string(), ntp.stratum.to_string()),
                                ("Leap Indicator".to_string(), ntp.leap_indicator.to_string()),
                                ("Precision".to_string(), format!("2^{} seconds", ntp.precision)),
                            ],
                        });
                    } else if let Ok(dhcp) = DhcpInfo::parse(payload) {
                        layers.push(DissectedLayer {
                            name: "Dynamic Host Configuration Protocol (DHCP)".to_string(),
                            fields: vec![
                                ("Message Type".to_string(), format!("{:?}", dhcp.message_type)),
                                ("Transaction ID".to_string(), format!("{:#010x}", dhcp.transaction_id)),
                                ("Client MAC".to_string(), dhcp.client_mac.to_string()),
                            ],
                        });
                    }
                }
            }
        }

        PacketTree {
            index,
            timestamp,
            length,
            layers,
        }
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

    pub fn read_packet_raw<P: AsRef<Path>>(path: P, target_index: u64) -> Result<Option<Vec<u8>>> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let mut index = 0u64;

        let mut reader = PcapReader::new(file)
            .map_err(|e| NetraError::Parser(format!("Failed to open PCAP: {}", e)))?;

        while let Some(packet_res) = reader.next_packet() {
            if let Ok(pkt) = packet_res {
                index += 1;
                if index == target_index {
                    return Ok(Some(pkt.data.to_vec()));
                }
            }
        }
        Ok(None)
    }

    pub fn read_packets_streaming<P: AsRef<Path>, F: FnMut(u64, &[u8]) -> bool>(
        path: P,
        mut on_raw: F,
    ) -> Result<u64> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let mut index = 0u64;

        let mut reader = PcapReader::new(file)
            .map_err(|e| NetraError::Parser(format!("Failed to open PCAP: {}", e)))?;

        while let Some(packet_res) = reader.next_packet() {
            if let Ok(pkt) = packet_res {
                index += 1;
                if !on_raw(index, &pkt.data) {
                    break;
                }
            }
        }
        Ok(index)
    }
}
