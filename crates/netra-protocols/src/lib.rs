pub mod arp;
pub mod dns;
pub mod http;
pub mod tls;

pub use arp::ArpPacket;
pub use dns::DnsMessage;
pub use http::HttpMetadata;
pub use tls::TlsClientHello;
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_arp_parsing() {
        let mut arp_bytes = vec![
            0x00, 0x01, // htype = 1 (Ethernet)
            0x08, 0x00, // ptype = 0x0800 (IPv4)
            0x06,       // hlen = 6
            0x04,       // plen = 4
            0x00, 0x01, // op = 1 (Request)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // smac
            192, 168, 1, 10,                    // sip
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tmac
            192, 168, 1, 1,                     // tip
        ];

        let parsed = ArpPacket::parse(&arp_bytes).expect("Failed to parse valid ARP");
        assert_eq!(parsed.operation, arp::ArpOperation::Request);
        assert_eq!(parsed.sender_ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(parsed.target_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.sender_mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_http_parsing_request_and_response() {
        let req = b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetraAgent\r\n\r\n";
        let parsed_req = HttpMetadata::parse(req).expect("Failed to parse HTTP request");
        assert!(parsed_req.is_request);
        assert_eq!(parsed_req.method.as_deref(), Some("GET"));
        assert_eq!(parsed_req.uri.as_deref(), Some("/api/v1/status"));
        assert_eq!(parsed_req.host.as_deref(), Some("example.com"));

        let res = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let parsed_res = HttpMetadata::parse(res).expect("Failed to parse HTTP response");
        assert!(!parsed_res.is_request);
        assert_eq!(parsed_res.status_code, Some(200));
    }
}
