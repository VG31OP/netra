use std::net::IpAddr;
use netra_common::{NetworkProtocol, PacketMetadata};

#[derive(Debug, Clone)]
pub enum FilterExpr {
    All,
    Protocol(NetworkProtocol),
    Ip(IpAddr),
    Port(u16),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

impl FilterExpr {
    pub fn parse(filter: &str) -> Self {
        let trimmed = filter.trim();
        if trimmed.is_empty() {
            return FilterExpr::All;
        }

        let lower = trimmed.to_lowercase();
        match lower.as_str() {
            "tcp" => FilterExpr::Protocol(NetworkProtocol::Tcp),
            "udp" => FilterExpr::Protocol(NetworkProtocol::Udp),
            "dns" => FilterExpr::Protocol(NetworkProtocol::Dns),
            "http" => FilterExpr::Protocol(NetworkProtocol::Http),
            "tls" => FilterExpr::Protocol(NetworkProtocol::Tls),
            "arp" => FilterExpr::Protocol(NetworkProtocol::Arp),
            "icmp" => FilterExpr::Protocol(NetworkProtocol::Icmp),
            "ip" | "ipv4" => FilterExpr::Protocol(NetworkProtocol::Ipv4),
            "ipv6" => FilterExpr::Protocol(NetworkProtocol::Ipv6),
            s if s.starts_with("port ") => {
                if let Ok(port) = s["port ".len()..].trim().parse::<u16>() {
                    FilterExpr::Port(port)
                } else {
                    FilterExpr::All
                }
            }
            s if s.starts_with("host ") => {
                if let Ok(ip) = s["host ".len()..].trim().parse::<IpAddr>() {
                    FilterExpr::Ip(ip)
                } else {
                    FilterExpr::All
                }
            }
            _ => {
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    FilterExpr::Ip(ip)
                } else if let Ok(port) = trimmed.parse::<u16>() {
                    FilterExpr::Port(port)
                } else {
                    FilterExpr::All
                }
            }
        }
    }

    pub fn matches(&self, packet: &PacketMetadata) -> bool {
        match self {
            Self::All => true,
            Self::Protocol(proto) => &packet.protocol == proto,
            Self::Ip(ip) => {
                packet.source_ip.as_ref() == Some(ip) || packet.destination_ip.as_ref() == Some(ip)
            }
            Self::Port(port) => {
                packet.source_port == Some(*port) || packet.destination_port == Some(*port)
            }
            Self::And(left, right) => left.matches(packet) && right.matches(packet),
            Self::Or(left, right) => left.matches(packet) || right.matches(packet),
            Self::Not(expr) => !expr.matches(packet),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_matching() {
        let ts = chrono::Utc::now();
        let pkt = PacketMetadata {
            index: 1,
            timestamp: ts,
            source_mac: None,
            destination_mac: None,
            source_ip: Some("192.168.1.50".parse().unwrap()),
            destination_ip: Some("10.0.0.1".parse().unwrap()),
            source_port: Some(443),
            destination_port: Some(51234),
            protocol: NetworkProtocol::Tcp,
            length: 120,
            summary: "Test TCP packet".to_string(),
        };

        let filter_all = FilterExpr::parse("");
        assert!(filter_all.matches(&pkt));

        let filter_tcp = FilterExpr::parse("tcp");
        assert!(filter_tcp.matches(&pkt));

        let filter_udp = FilterExpr::parse("udp");
        assert!(!filter_udp.matches(&pkt));

        let filter_ip = FilterExpr::parse("192.168.1.50");
        assert!(filter_ip.matches(&pkt));

        let filter_port = FilterExpr::parse("443");
        assert!(filter_port.matches(&pkt));

        let filter_other_port = FilterExpr::parse("80");
        assert!(!filter_other_port.matches(&pkt));
    }
}
