use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use netra_common::{NetraError, PortState, Result, ServiceRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingTemplate {
    Paranoid,   // T0
    Sneaky,     // T1
    Polite,     // T2
    Normal,     // T3 (default)
    Aggressive, // T4
    Insane,     // T5
}

impl TimingTemplate {
    pub fn from_level(level: u8) -> Self {
        match level {
            0 => Self::Paranoid,
            1 => Self::Sneaky,
            2 => Self::Polite,
            3 => Self::Normal,
            4 => Self::Aggressive,
            _ => Self::Insane,
        }
    }

    pub fn config(&self) -> (Duration, usize, Option<Duration>) {
        // (timeout, concurrency, delay_between_probes)
        match self {
            Self::Paranoid => (Duration::from_secs(5), 1, Some(Duration::from_secs(15))),
            Self::Sneaky => (Duration::from_millis(2500), 2, Some(Duration::from_millis(500))),
            Self::Polite => (Duration::from_millis(1500), 10, Some(Duration::from_millis(50))),
            Self::Normal => (Duration::from_millis(1000), 100, None),
            Self::Aggressive => (Duration::from_millis(600), 400, None),
            Self::Insane => (Duration::from_millis(300), 1000, None),
        }
    }
}

pub struct PortPresets;

impl PortPresets {
    pub const TOP_100: &'static [u16] = &[
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157,
    ];

    pub fn parse_port_expression(expr: &str) -> Result<Vec<u16>> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Ok(Self::TOP_100.to_vec());
        }

        if trimmed == "-F" || trimmed == "fast" {
            return Ok(Self::TOP_100.to_vec());
        }

        if trimmed == "-p-" || trimmed == "all" {
            return Ok((1..=65535).collect());
        }

        let mut ports = Vec::new();
        for part in trimmed.split(',') {
            let p = part.trim();
            if let Some((start_s, end_s)) = p.split_once('-') {
                let start: u16 = start_s.parse().map_err(|_| NetraError::Scanner("Invalid port range start".into()))?;
                let end: u16 = end_s.parse().map_err(|_| NetraError::Scanner("Invalid port range end".into()))?;
                for port in start..=end {
                    ports.push(port);
                }
            } else if let Ok(port) = p.parse::<u16>() {
                ports.push(port);
            }
        }

        ports.sort_unstable();
        ports.dedup();
        Ok(ports)
    }
}

pub struct PortScanner {
    timeout: Duration,
    concurrency: usize,
    probe_delay: Option<Duration>,
    stop_signal: Arc<AtomicBool>,
}

impl PortScanner {
    pub fn new(timeout_ms: u64, concurrency: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            concurrency,
            probe_delay: None,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_timing(template: TimingTemplate) -> Self {
        let (timeout, concurrency, delay) = template.config();
        Self {
            timeout,
            concurrency,
            probe_delay: delay,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
    }

    pub async fn scan_port(&self, target: IpAddr, port: u16) -> ServiceRecord {
        let addr = SocketAddr::new(target, port);
        let start = Utc::now();

        match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                let banner = Self::probe_service(stream, port).await;
                let service_name = Self::identify_service(port, banner.as_deref());
                ServiceRecord {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service_name: Some(service_name),
                    banner,
                    last_observed: Utc::now(),
                }
            }
            Ok(Err(_)) => ServiceRecord {
                port,
                protocol: "tcp".to_string(),
                state: PortState::Closed,
                service_name: None,
                banner: None,
                last_observed: start,
            },
            Err(_) => ServiceRecord {
                port,
                protocol: "tcp".to_string(),
                state: PortState::Filtered,
                service_name: None,
                banner: None,
                last_observed: start,
            },
        }
    }

    async fn probe_service(mut stream: TcpStream, port: u16) -> Option<String> {
        let mut buf = [0u8; 1024];

        // 1. Passive banner read (FTP, SSH, SMTP send greeting automatically)
        if let Ok(Ok(n)) = timeout(Duration::from_millis(400), stream.read(&mut buf)).await {
            if n > 0 {
                return Some(String::from_utf8_lossy(&buf[..n]).trim().to_string());
            }
        }

        // 2. Active probe based on port heuristics
        let probe: Option<&[u8]> = match port {
            80 | 8080 | 8000 | 8888 => Some(b"HEAD / HTTP/1.0\r\n\r\n"),
            443 | 8443 => None, // TLS handshake handled separately
            6379 => Some(b"PING\r\n"),
            _ => Some(b"\r\n\r\n"),
        };

        if let Some(data) = probe {
            if stream.write_all(data).await.is_ok() {
                if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                    if n > 0 {
                        let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        return Some(text);
                    }
                }
            }
        }

        None
    }

    pub fn identify_service(port: u16, banner: Option<&str>) -> String {
        if let Some(b) = banner {
            let lower = b.to_lowercase();
            if lower.contains("ssh") { return "ssh".to_string(); }
            if lower.contains("http") || lower.contains("server:") { return "http".to_string(); }
            if lower.contains("ftp") { return "ftp".to_string(); }
            if lower.contains("smtp") || lower.contains("esmtp") { return "smtp".to_string(); }
            if lower.contains("mysql") || lower.contains("mariadb") { return "mysql".to_string(); }
            if lower.contains("redis") || lower.contains("pong") { return "redis".to_string(); }
            if lower.contains("rfb") { return "vnc".to_string(); }
        }

        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 => "http",
            110 => "pop3",
            135 => "msrpc",
            139 => "netbios-ssn",
            143 => "imap",
            443 => "https",
            445 => "microsoft-ds",
            1433 => "ms-sql-s",
            1521 => "oracle",
            3306 => "mysql",
            3389 => "ms-wbt-server",
            5432 => "postgresql",
            5900 => "vnc",
            6379 => "redis",
            8000 => "http-alt",
            8080 => "http-proxy",
            8443 => "https-alt",
            9092 => "kafka",
            27017 => "mongodb",
            _ => "unknown",
        }
        .to_string()
    }

    pub async fn scan_ports<F: Fn(ServiceRecord) + Send + Sync + 'static>(
        &self,
        target: IpAddr,
        ports: Vec<u16>,
        on_result: F,
    ) {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let on_result = Arc::new(on_result);
        let timeout_dur = self.timeout;
        let delay = self.probe_delay;

        let mut handles = Vec::new();
        for port in ports {
            if self.stop_signal.load(Ordering::Relaxed) {
                break;
            }

            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }

            let permit = sem.clone().acquire_owned().await;
            if permit.is_err() {
                break;
            }

            let on_res = on_result.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = SocketAddr::new(target, port);
                let record = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
                    Ok(Ok(stream)) => {
                        let banner = Self::probe_service(stream, port).await;
                        let service_name = Self::identify_service(port, banner.as_deref());
                        ServiceRecord {
                            port,
                            protocol: "tcp".to_string(),
                            state: PortState::Open,
                            service_name: Some(service_name),
                            banner,
                            last_observed: Utc::now(),
                        }
                    }
                    Ok(Err(_)) => ServiceRecord {
                        port,
                        protocol: "tcp".to_string(),
                        state: PortState::Closed,
                        service_name: None,
                        banner: None,
                        last_observed: Utc::now(),
                    },
                    Err(_) => ServiceRecord {
                        port,
                        protocol: "tcp".to_string(),
                        state: PortState::Filtered,
                        service_name: None,
                        banner: None,
                        last_observed: Utc::now(),
                    },
                };
                on_res(record);
            }));
        }

        for h in handles {
            let _ = h.await;
        }
    }
}
