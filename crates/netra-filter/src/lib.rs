use std::net::IpAddr;
use netra_common::{NetworkProtocol, PacketMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    Contains,
}

#[derive(Debug, Clone)]
pub enum FilterNode {
    All,
    Protocol(NetworkProtocol),
    IpSrc(IpAddr),
    IpDst(IpAddr),
    IpAddrMatch(IpAddr),
    Port(u16),
    TcpPort(u16),
    UdpPort(u16),
    TcpSyn,
    TcpReset,
    TcpFin,
    FrameLen(ComparisonOp, u32),
    HttpMethod(String),
    HttpStatus(u16),
    DnsName(String),
    TlsSni(String),
    And(Box<FilterNode>, Box<FilterNode>),
    Or(Box<FilterNode>, Box<FilterNode>),
    Not(Box<FilterNode>),
}

impl FilterNode {
    pub fn parse(input: &str) -> Self {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return FilterNode::All;
        }

        // Check for logical OR (split top level)
        if let Some((left, right)) = Self::split_logical(trimmed, &["||", " or "]) {
            return FilterNode::Or(Box::new(Self::parse(left)), Box::new(Self::parse(right)));
        }

        // Check for logical AND (split top level)
        if let Some((left, right)) = Self::split_logical(trimmed, &["&&", " and "]) {
            return FilterNode::And(Box::new(Self::parse(left)), Box::new(Self::parse(right)));
        }

        // Check for logical NOT
        if trimmed.starts_with('!') || trimmed.starts_with("not ") {
            let inner = if trimmed.starts_with('!') {
                &trimmed[1..]
            } else {
                &trimmed[4..]
            };
            return FilterNode::Not(Box::new(Self::parse(inner)));
        }

        // Strip parentheses if wrapped
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            return Self::parse(&trimmed[1..trimmed.len() - 1]);
        }

        // Parse individual field predicates
        Self::parse_predicate(trimmed)
    }

    fn split_logical<'a>(text: &'a str, delimiters: &[&str]) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let bytes = text.as_bytes();

        for i in 0..bytes.len() {
            if bytes[i] == b'(' {
                depth += 1;
            } else if bytes[i] == b')' {
                if depth > 0 { depth -= 1; }
            } else if depth == 0 {
                for &delim in delimiters {
                    if text[i..].starts_with(delim) {
                        return Some((&text[..i], &text[i + delim.len()..]));
                    }
                }
            }
        }
        None
    }

    fn parse_predicate(pred: &str) -> Self {
        let lower = pred.to_lowercase();

        // Protocol shortcuts
        match lower.as_str() {
            "tcp" => return FilterNode::Protocol(NetworkProtocol::Tcp),
            "udp" => return FilterNode::Protocol(NetworkProtocol::Udp),
            "dns" => return FilterNode::Protocol(NetworkProtocol::Dns),
            "http" => return FilterNode::Protocol(NetworkProtocol::Http),
            "tls" | "ssl" => return FilterNode::Protocol(NetworkProtocol::Tls),
            "arp" => return FilterNode::Protocol(NetworkProtocol::Arp),
            "icmp" => return FilterNode::Protocol(NetworkProtocol::Icmp),
            "dhcp" | "bootp" => return FilterNode::Protocol(NetworkProtocol::Dhcp),
            "ssdp" => return FilterNode::Protocol(NetworkProtocol::Ssdp),
            "ip" | "ipv4" => return FilterNode::Protocol(NetworkProtocol::Ipv4),
            "ipv6" => return FilterNode::Protocol(NetworkProtocol::Ipv6),
            "tcp.flags.syn" => return FilterNode::TcpSyn,
            "tcp.flags.reset" => return FilterNode::TcpReset,
            "tcp.flags.fin" => return FilterNode::TcpFin,
            _ => {}
        }

        // Wireshark style field comparisons
        if let Some((field, val)) = Self::split_op(pred) {
            let f = field.trim().to_lowercase();
            let v = val.trim().trim_matches('"').trim_matches('\'');

            match f.as_str() {
                "ip.src" => {
                    if let Ok(ip) = v.parse::<IpAddr>() { return FilterNode::IpSrc(ip); }
                }
                "ip.dst" => {
                    if let Ok(ip) = v.parse::<IpAddr>() { return FilterNode::IpDst(ip); }
                }
                "ip.addr" | "host" => {
                    if let Ok(ip) = v.parse::<IpAddr>() { return FilterNode::IpAddrMatch(ip); }
                }
                "tcp.port" => {
                    if let Ok(port) = v.parse::<u16>() { return FilterNode::TcpPort(port); }
                }
                "udp.port" => {
                    if let Ok(port) = v.parse::<u16>() { return FilterNode::UdpPort(port); }
                }
                "port" => {
                    if let Ok(port) = v.parse::<u16>() { return FilterNode::Port(port); }
                }
                "frame.len" => {
                    if let Ok(len) = v.parse::<u32>() {
                        return FilterNode::FrameLen(ComparisonOp::GreaterThan, len);
                    }
                }
                "http.request.method" => return FilterNode::HttpMethod(v.to_uppercase()),
                "http.response.code" => {
                    if let Ok(code) = v.parse::<u16>() { return FilterNode::HttpStatus(code); }
                }
                "dns.qry.name" => return FilterNode::DnsName(v.to_string()),
                "tls.handshake.extensions_server_name" | "tls.sni" => {
                    return FilterNode::TlsSni(v.to_string());
                }
                _ => {}
            }
        }

        // Direct IP or port fallback
        if let Ok(ip) = pred.trim().parse::<IpAddr>() {
            FilterNode::IpAddrMatch(ip)
        } else if let Ok(port) = pred.trim().parse::<u16>() {
            FilterNode::Port(port)
        } else {
            FilterNode::All
        }
    }

    fn split_op(text: &str) -> Option<(&str, &str)> {
        for op in &["==", "!=", ">=", "<=", " contains ", "=", ">", "<"] {
            if let Some(pos) = text.find(op) {
                return Some((&text[..pos], &text[pos + op.len()..]));
            }
        }
        None
    }

    pub fn matches(&self, packet: &PacketMetadata) -> bool {
        match self {
            Self::All => true,
            Self::Protocol(proto) => &packet.protocol == proto,
            Self::IpSrc(ip) => packet.source_ip.as_ref() == Some(ip),
            Self::IpDst(ip) => packet.destination_ip.as_ref() == Some(ip),
            Self::IpAddrMatch(ip) => {
                packet.source_ip.as_ref() == Some(ip) || packet.destination_ip.as_ref() == Some(ip)
            }
            Self::Port(port) => {
                packet.source_port == Some(*port) || packet.destination_port == Some(*port)
            }
            Self::TcpPort(port) => {
                packet.protocol == NetworkProtocol::Tcp
                    && (packet.source_port == Some(*port) || packet.destination_port == Some(*port))
            }
            Self::UdpPort(port) => {
                packet.protocol == NetworkProtocol::Udp
                    && (packet.source_port == Some(*port) || packet.destination_port == Some(*port))
            }
            Self::TcpSyn => packet.flags.as_ref().map(|f| f.syn).unwrap_or(false),
            Self::TcpReset => packet.flags.as_ref().map(|f| f.rst).unwrap_or(false),
            Self::TcpFin => packet.flags.as_ref().map(|f| f.fin).unwrap_or(false),
            Self::FrameLen(op, val) => match op {
                ComparisonOp::GreaterThan => packet.length > *val,
                ComparisonOp::LessThan => packet.length < *val,
                ComparisonOp::GreaterOrEqual => packet.length >= *val,
                ComparisonOp::LessOrEqual => packet.length <= *val,
                ComparisonOp::Equal => packet.length == *val,
                ComparisonOp::NotEqual => packet.length != *val,
                ComparisonOp::Contains => false,
            },
            Self::HttpMethod(m) => packet.http_method.as_ref().map(|x| x == m).unwrap_or(false),
            Self::HttpStatus(code) => packet.http_status == Some(*code),
            Self::DnsName(q) => packet.dns_name.as_ref().map(|x| x.contains(q)).unwrap_or(false),
            Self::TlsSni(s) => packet.sni.as_ref().map(|x| x.contains(s)).unwrap_or(false),
            Self::And(l, r) => l.matches(packet) && r.matches(packet),
            Self::Or(l, r) => l.matches(packet) || r.matches(packet),
            Self::Not(inner) => !inner.matches(packet),
        }
    }
}

pub type FilterExpr = FilterNode;

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
            flags: None,
            sni: None,
            dns_name: None,
            http_method: None,
            http_status: None,
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

        // Test Wireshark style expressions
        let filter_wireshark = FilterExpr::parse("tcp.port == 443 && ip.src == 192.168.1.50");
        assert!(filter_wireshark.matches(&pkt));

        let filter_negative = FilterExpr::parse("!udp and tcp");
        assert!(filter_negative.matches(&pkt));
    }
}
