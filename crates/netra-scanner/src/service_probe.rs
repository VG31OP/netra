#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}

pub struct ServiceProbeEngine;

impl ServiceProbeEngine {
    pub fn probe_payload(port: u16) -> Option<&'static [u8]> {
        match port {
            80 | 8080 | 8000 | 8888 | 8081 | 3000 | 5000 => {
                Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Netra/0.1\r\nAccept: */*\r\n\r\n")
            }
            443 | 8443 => {
                // TLS ClientHello (TLS 1.2 handshake simulation)
                Some(&[
                    0x16, 0x03, 0x01, 0x00, 0x4a, 0x01, 0x00, 0x00, 0x46, 0x03, 0x03,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00,
                    0x00, 0x04, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00, 0x00, 0x19, 0x00,
                    0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63,
                    0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
                ])
            }
            6379 => Some(b"PING\r\nINFO\r\n"),
            25 | 587 => Some(b"EHLO netra.local\r\n"),
            110 => Some(b"USER test\r\n"),
            143 => Some(b"a001 CAPABILITY\r\n"),
            21 => Some(b"HELP\r\n"),
            445 | 139 => {
                // SMBv1/v2 Negotiate Protocol Request
                Some(&[
                    0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00,
                    0x00, 0x00, 0x08, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c,
                    0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
                ])
            }
            _ => Some(b"\r\n\r\n"),
        }
    }

    pub fn analyze_banner(port: u16, banner: Option<&str>) -> ServiceInfo {
        let default_name = Self::port_to_default_service(port);
        let b = match banner {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return ServiceInfo {
                    name: default_name.to_string(),
                    product: None,
                    version: None,
                    extra_info: None,
                    cpe: None,
                };
            }
        };

        // 1. SSH probe match
        if b.starts_with("SSH-") {
            let mut product = "OpenSSH".to_string();
            let mut version = None;
            let mut extra = None;
            let mut cpe = Some("cpe:/a:openbsd:openssh".to_string());

            if let Some(pos) = b.find("OpenSSH_") {
                let rest = &b[pos + 8..];
                let v = rest.split_whitespace().next().unwrap_or(rest);
                version = Some(v.to_string());
            } else if b.contains("dropbear") {
                product = "Dropbear sshd".to_string();
                cpe = Some("cpe:/a:matt_johnston:dropbear_sshd".to_string());
            }

            if b.contains("Ubuntu") {
                extra = Some("Ubuntu Linux; protocol 2.0".to_string());
            } else if b.contains("Debian") {
                extra = Some("Debian Linux; protocol 2.0".to_string());
            }

            return ServiceInfo {
                name: "ssh".to_string(),
                product: Some(product),
                version,
                extra_info: extra,
                cpe,
            };
        }

        // 2. HTTP probe match
        if b.starts_with("HTTP/") || b.contains("Server:") || b.contains("<html") || b.contains("<!DOCTYPE") {
            let mut product = None;
            let mut version = None;
            let mut extra = None;

            for line in b.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("server:") {
                    let s = line[7..].trim();
                    if s.contains("Apache") {
                        product = Some("Apache httpd".to_string());
                        if let Some(v_part) = s.strip_prefix("Apache/") {
                            version = Some(v_part.split_whitespace().next().unwrap_or("").to_string());
                        }
                    } else if s.contains("nginx") {
                        product = Some("nginx".to_string());
                        if let Some(v_part) = s.strip_prefix("nginx/") {
                            version = Some(v_part.split_whitespace().next().unwrap_or("").to_string());
                        }
                    } else if s.contains("Microsoft-IIS") {
                        product = Some("Microsoft IIS httpd".to_string());
                        if let Some(v_part) = s.strip_prefix("Microsoft-IIS/") {
                            version = Some(v_part.split_whitespace().next().unwrap_or("").to_string());
                        }
                    } else if s.contains("Caddy") {
                        product = Some("Caddy web server".to_string());
                    } else if s.contains("cloudflare") {
                        product = Some("Cloudflare reverse proxy".to_string());
                    } else {
                        product = Some(s.to_string());
                    }
                    extra = Some(s.to_string());
                }
            }

            return ServiceInfo {
                name: if port == 443 || port == 8443 { "https".to_string() } else { "http".to_string() },
                product: product.or_else(|| Some("HTTP Server".to_string())),
                version,
                extra_info: extra,
                cpe: Some("cpe:/a:apache:http_server".to_string()),
            };
        }

        // 3. FTP probe match
        if b.starts_with("220") && (b.contains("FTP") || b.contains("vsftpd") || b.contains("FileZilla") || b.contains("Pure-FTPd") || port == 21) {
            let mut product = "FTP Server".to_string();
            let mut version = None;

            if b.contains("vsftpd") {
                product = "vsftpd".to_string();
                if let Some(idx) = b.find("vsftpd ") {
                    let v = &b[idx + 7..];
                    version = Some(v.split_whitespace().next().unwrap_or("").trim_matches(')').to_string());
                }
            } else if b.contains("Pure-FTPd") {
                product = "Pure-FTPd".to_string();
            } else if b.contains("FileZilla") {
                product = "FileZilla Server".to_string();
            }

            return ServiceInfo {
                name: "ftp".to_string(),
                product: Some(product),
                version,
                extra_info: Some(b.lines().next().unwrap_or("").to_string()),
                cpe: Some("cpe:/a:vsftpd:vsftpd".to_string()),
            };
        }

        // 4. SMTP match
        if (b.starts_with("220") || b.starts_with("250")) && (b.contains("ESMTP") || b.contains("Postfix") || b.contains("Exim") || port == 25 || port == 587) {
            let mut product = "SMTP Server".to_string();
            if b.contains("Postfix") {
                product = "Postfix smtpd".to_string();
            } else if b.contains("Exim") {
                product = "Exim smtpd".to_string();
            } else if b.contains("Microsoft") {
                product = "Microsoft Exchange smtpd".to_string();
            }

            return ServiceInfo {
                name: "smtp".to_string(),
                product: Some(product),
                version: None,
                extra_info: Some(b.lines().next().unwrap_or("").to_string()),
                cpe: Some("cpe:/a:postfix:postfix".to_string()),
            };
        }

        // 5. Redis match
        if b.contains("PONG") || b.contains("redis_version") || b.contains("ERR unknown command") || port == 6379 {
            let mut version = None;
            for line in b.lines() {
                if let Some(v) = line.strip_prefix("redis_version:") {
                    version = Some(v.trim().to_string());
                }
            }

            return ServiceInfo {
                name: "redis".to_string(),
                product: Some("Redis key-value store".to_string()),
                version,
                extra_info: None,
                cpe: Some("cpe:/a:redis:redis".to_string()),
            };
        }

        // 6. MySQL / MariaDB match
        if b.contains("mysql") || b.contains("mariadb") || port == 3306 {
            let product = if b.to_lowercase().contains("mariadb") {
                "MariaDB"
            } else {
                "MySQL"
            };

            return ServiceInfo {
                name: "mysql".to_string(),
                product: Some(product.to_string()),
                version: None,
                extra_info: None,
                cpe: Some("cpe:/a:oracle:mysql".to_string()),
            };
        }

        // Fallback default
        ServiceInfo {
            name: default_name.to_string(),
            product: None,
            version: None,
            extra_info: Some(b.lines().next().unwrap_or("").chars().take(80).collect()),
            cpe: None,
        }
    }

    pub fn port_to_default_service(port: u16) -> &'static str {
        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "domain",
            80 => "http",
            88 => "kerberos-sec",
            110 => "pop3",
            111 => "rpcbind",
            123 => "ntp",
            135 => "msrpc",
            139 => "netbios-ssn",
            143 => "imap",
            161 => "snmp",
            389 => "ldap",
            443 => "https",
            445 => "microsoft-ds",
            465 => "smtps",
            514 => "syslog",
            587 => "submission",
            636 => "ldaps",
            993 => "imaps",
            995 => "pop3s",
            1433 => "ms-sql-s",
            1521 => "oracle",
            1723 => "pptp",
            1883 => "mqtt",
            1900 => "upnp",
            2049 => "nfs",
            3000 => "ppp",
            3306 => "mysql",
            3389 => "ms-wbt-server",
            5000 => "upnp",
            5060 => "sip",
            5353 => "zeroconf",
            5432 => "postgresql",
            5900 => "vnc",
            6379 => "redis",
            8000 => "http-alt",
            8080 => "http-proxy",
            8443 => "https-alt",
            8888 => "sun-answerbook",
            9092 => "kafka",
            9200 => "elasticsearch",
            27017 => "mongodb",
            _ => "unknown",
        }
    }
}
