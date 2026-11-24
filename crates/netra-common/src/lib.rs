use std::fmt;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetraError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Database error: {0}")]
    Storage(String),
    #[error("Packet parsing error: {0}")]
    Parser(String),
    #[error("Filter syntax error: {0}")]
    Filter(String),
    #[error("Capture error: {0}")]
    Capture(String),
    #[error("Scanner error: {0}")]
    Scanner(String),
    #[error("Discovery error: {0}")]
    Discovery(String),
    #[error("Intelligence error: {0}")]
    Intelligence(String),
    #[error("Export error: {0}")]
    Export(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

pub type Result<T> = std::result::Result<T, NetraError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::str::FromStr for MacAddress {
    type Err = NetraError;
    fn from_str(s: &str) -> Result<Self> {
        let parts: std::result::Result<Vec<u8>, _> = s
            .split([':', '-'])
            .map(|p| u8::from_str_radix(p, 16))
            .collect();
        match parts {
            Ok(bytes) if bytes.len() == 6 => {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(&bytes);
                Ok(MacAddress(arr))
            }
            _ => Err(NetraError::Parser(format!("Invalid MAC address: {}", s))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Tcp,
    Udp,
    Dns,
    Http,
    Tls,
    Dhcp,
    Ssdp,
    Smb,
    Ntp,
    Mdns,
    Ssh,
    Vlan,
    Icmpv6,
    Unknown(String),
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethernet => write!(f, "Ethernet"),
            Self::Arp => write!(f, "ARP"),
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Ipv6 => write!(f, "IPv6"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Dns => write!(f, "DNS"),
            Self::Http => write!(f, "HTTP"),
            Self::Tls => write!(f, "TLS"),
            Self::Dhcp => write!(f, "DHCP"),
            Self::Ssdp => write!(f, "SSDP"),
            Self::Smb => write!(f, "SMB"),
            Self::Ntp => write!(f, "NTP"),
            Self::Mdns => write!(f, "mDNS"),
            Self::Ssh => write!(f, "SSH"),
            Self::Vlan => write!(f, "VLAN"),
            Self::Icmpv6 => write!(f, "ICMPv6"),
            Self::Unknown(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub source_mac: Option<MacAddress>,
    pub destination_mac: Option<MacAddress>,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: NetworkProtocol,
    pub length: u32,
    pub summary: String,
    pub flags: Option<PacketFlags>,
    pub sni: Option<String>,
    pub dns_name: Option<String>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8,
    pub family: String,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub banner: Option<String>,
    pub last_observed: DateTime<Utc>,
}

impl ServiceRecord {
    pub fn simple(port: u16, protocol: impl Into<String>, state: PortState) -> Self {
        Self {
            port,
            protocol: protocol.into(),
            state,
            service_name: None,
            product: None,
            version: None,
            extra_info: None,
            banner: None,
            last_observed: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExpertSeverity {
    Chat,
    Note,
    Warn,
    Error,
}

impl fmt::Display for ExpertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chat => write!(f, "Chat"),
            Self::Note => write!(f, "Note"),
            Self::Warn => write!(f, "Warning"),
            Self::Error => write!(f, "Error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertInfo {
    pub packet_index: u64,
    pub severity: ExpertSeverity,
    pub group: String,
    pub protocol: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: Option<f32>,
    pub hostname: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityVulnerability {
    pub id: String,
    pub title: String,
    pub severity: VulnerabilitySeverity,
    pub target: IpAddr,
    pub port: Option<u16>,
    pub service: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TcpScanType {
    #[default]
    Connect,
    Syn,
    Fin,
    Null,
    Xmas,
    Ack,
    Window,
    Maimon,
}

impl fmt::Display for TcpScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => write!(f, "Connect (-sT)"),
            Self::Syn => write!(f, "SYN Stealth (-sS)"),
            Self::Fin => write!(f, "FIN (-sF)"),
            Self::Null => write!(f, "NULL (-sN)"),
            Self::Xmas => write!(f, "XMAS (-sX)"),
            Self::Ack => write!(f, "ACK (-sA)"),
            Self::Window => write!(f, "Window (-sW)"),
            Self::Maimon => write!(f, "Maimon (-sM)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub device_type: Option<String>,
    pub os_match: Option<OsMatch>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub services: Vec<ServiceRecord>,
    pub packet_count: u64,
}

impl HostRecord {
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            mac: None,
            hostname: None,
            device_type: None,
            os_match: None,
            first_seen: now,
            last_seen: now,
            services: Vec::new(),
            packet_count: 0,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_formatting_and_parsing() {
        let mac_str = "00:1a:2b:3c:4d:5e";
        let mac: MacAddress = mac_str.parse().expect("Failed to parse valid MAC");
        assert_eq!(mac.0, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), mac_str);

        let hyphen_mac: MacAddress = "00-1A-2B-3C-4D-5E".parse().expect("Failed hyphen MAC");
        assert_eq!(hyphen_mac.0, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

        assert!("invalid-mac".parse::<MacAddress>().is_err());
        assert!("00:11:22:33:44".parse::<MacAddress>().is_err());
    }

    #[test]
    fn test_host_record_initialization() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let host = HostRecord::new(ip);
        assert_eq!(host.ip, ip);
        assert!(host.services.is_empty());
        assert_eq!(host.packet_count, 0);
    }
}
