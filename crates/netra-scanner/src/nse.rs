use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use netra_common::{SecurityVulnerability, VulnerabilitySeverity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct NseEngine {
    pub timeout: Duration,
}

impl Default for NseEngine {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1500),
        }
    }
}

impl NseEngine {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn audit_target(&self, target: IpAddr, open_ports: &[u16]) -> Vec<SecurityVulnerability> {
        let mut vulns = Vec::new();

        for &port in open_ports {
            match port {
                21 => {
                    if let Some(v) = self.check_ftp_anonymous(target, port).await {
                        vulns.push(v);
                    }
                }
                80 | 8080 | 3000 | 8000 => {
                    let mut http_vulns = self.check_http_security(target, port, false).await;
                    vulns.append(&mut http_vulns);
                }
                443 | 8443 => {
                    let mut https_vulns = self.check_http_security(target, port, true).await;
                    vulns.append(&mut https_vulns);
                }
                445 => {
                    if let Some(v) = self.check_smb_security(target, port).await {
                        vulns.push(v);
                    }
                }
                6379 => {
                    if let Some(v) = self.check_redis_noauth(target, port).await {
                        vulns.push(v);
                    }
                }
                _ => {}
            }
        }

        vulns
    }

    async fn check_ftp_anonymous(&self, target: IpAddr, port: u16) -> Option<SecurityVulnerability> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

        let mut buf = [0u8; 1024];
        let _ = timeout(self.timeout, stream.read(&mut buf)).await.ok()?;

        let _ = timeout(self.timeout, stream.write_all(b"USER anonymous\r\n")).await.ok()?;
        let n = timeout(self.timeout, stream.read(&mut buf)).await.ok()?.ok()?;
        let resp = String::from_utf8_lossy(&buf[..n]);

        if resp.starts_with("331") {
            let _ = timeout(self.timeout, stream.write_all(b"PASS anonymous@netra.local\r\n")).await.ok()?;
            let n2 = timeout(self.timeout, stream.read(&mut buf)).await.ok()?.ok()?;
            let resp2 = String::from_utf8_lossy(&buf[..n2]);
            if resp2.starts_with("230") {
                return Some(SecurityVulnerability {
                    id: "NETRA-VULN-FTP-ANON".to_string(),
                    title: "Anonymous FTP Login Permitted".to_string(),
                    severity: VulnerabilitySeverity::High,
                    target,
                    port: Some(port),
                    service: "ftp".to_string(),
                    description: "The remote FTP server allows unauthenticated login via 'anonymous' credentials.".to_string(),
                    evidence: format!("Server response: {}", resp2.trim()),
                    remediation: "Disable anonymous authentication in your FTP server configuration.".to_string(),
                });
            }
        }

        None
    }

    async fn check_smb_security(&self, target: IpAddr, port: u16) -> Option<SecurityVulnerability> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

        // Send SMBv1 negotiate request
        let smb1_negotiate: [u8; 85] = [
            0x00, 0x00, 0x00, 0x51, 0xff, 0x53, 0x4d, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x02,
            0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
            0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
            0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
            0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
            0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
            0x77, 0x73, 0x20, 0x66, 0x6f
        ];

        let _ = timeout(self.timeout, stream.write_all(&smb1_negotiate)).await.ok()?;
        let mut buf = [0u8; 512];
        let n = timeout(self.timeout, stream.read(&mut buf)).await.ok()?.ok()?;

        if n > 8 && buf[4..8] == [0xff, 0x53, 0x4d, 0x42] {
            return Some(SecurityVulnerability {
                id: "NETRA-VULN-SMBV1-ENABLED".to_string(),
                title: "Legacy SMBv1 Protocol Supported (MS17-010 EternalBlue Risk)".to_string(),
                severity: VulnerabilitySeverity::High,
                target,
                port: Some(port),
                service: "smb".to_string(),
                description: "The remote host accepted SMBv1 dialect negotiation. SMBv1 is an obsolete protocol vulnerable to remote code execution (e.g., WannaCry / EternalBlue).".to_string(),
                evidence: "SMBv1 negotiation accepted with dialect index in response.".to_string(),
                remediation: "Disable SMBv1 across all endpoints and enforce SMBv2/SMBv3.".to_string(),
            });
        }

        None
    }

    async fn check_redis_noauth(&self, target: IpAddr, port: u16) -> Option<SecurityVulnerability> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

        let _ = timeout(self.timeout, stream.write_all(b"PING\r\n")).await.ok()?;
        let mut buf = [0u8; 128];
        let n = timeout(self.timeout, stream.read(&mut buf)).await.ok()?.ok()?;
        let resp = String::from_utf8_lossy(&buf[..n]);

        if resp.contains("+PONG") {
            return Some(SecurityVulnerability {
                id: "NETRA-VULN-REDIS-NOAUTH".to_string(),
                title: "Unauthenticated Redis Database Exposure".to_string(),
                severity: VulnerabilitySeverity::Critical,
                target,
                port: Some(port),
                service: "redis".to_string(),
                description: "The Redis database server replied to PING without requiring authentication. Anyone on the network can execute commands, read data, or write arbitrary files.".to_string(),
                evidence: format!("Command output: {}", resp.trim()),
                remediation: "Configure 'requirepass' in redis.conf and bind Redis to 127.0.0.1.".to_string(),
            });
        }

        None
    }

    async fn check_http_security(&self, target: IpAddr, port: u16, is_tls: bool) -> Vec<SecurityVulnerability> {
        let mut vulns = Vec::new();
        if is_tls {
            return vulns; // TLS connection requires crypto handshake; standard HTTP inspected below
        }

        let addr = SocketAddr::new(target, port);
        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return vulns,
        };

        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NETRA-Auditor/1.0\r\nConnection: close\r\n\r\n", target);
        let _ = stream.write_all(req.as_bytes()).await;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return vulns;
        }

        let text = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();

        // 1. Missing HSTS check
        if !text.contains("strict-transport-security") {
            vulns.push(SecurityVulnerability {
                id: "NETRA-SEC-MISSING-HSTS".to_string(),
                title: "Missing Strict-Transport-Security (HSTS) Header".to_string(),
                severity: VulnerabilitySeverity::Low,
                target,
                port: Some(port),
                service: "http".to_string(),
                description: "The HTTP response does not include the HSTS header, allowing potential SSL-stripping man-in-the-middle attacks.".to_string(),
                evidence: "Strict-Transport-Security header omitted in response.".to_string(),
                remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to server responses.".to_string(),
            });
        }

        // 2. Missing Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
        if !text.contains("x-frame-options") && !text.contains("frame-ancestors") {
            vulns.push(SecurityVulnerability {
                id: "NETRA-SEC-CLICKJACKING".to_string(),
                title: "Missing Clickjacking Protection (X-Frame-Options)".to_string(),
                severity: VulnerabilitySeverity::Medium,
                target,
                port: Some(port),
                service: "http".to_string(),
                description: "The web application can be embedded in an <iframe> on third-party sites, making it vulnerable to clickjacking attacks.".to_string(),
                evidence: "Neither X-Frame-Options nor CSP frame-ancestors header present.".to_string(),
                remediation: "Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''. ".to_string(),
            });
        }

        // 3. Information Disclosure in Server header
        if let Some(pos) = text.find("server:") {
            let line = text[pos..].lines().next().unwrap_or("");
            if line.contains('/') {
                vulns.push(SecurityVulnerability {
                    id: "NETRA-SEC-SERVER-BANNER".to_string(),
                    title: "Detailed Web Server Software & Version Disclosure".to_string(),
                    severity: VulnerabilitySeverity::Info,
                    target,
                    port: Some(port),
                    service: "http".to_string(),
                    description: "The web server discloses exact software product and version information in the 'Server' header, facilitating targeted exploit research.".to_string(),
                    evidence: line.to_string(),
                    remediation: "Configure the web server to suppress product version tokens (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx).".to_string(),
                });
            }
        }

        vulns
    }
}
