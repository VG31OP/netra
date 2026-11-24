pub mod nse;
pub mod os_fingerprint;
pub mod service_probe;
pub mod traceroute;
pub mod udp;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use netra_common::{NetraError, OsMatch, PortState, Result, ServiceRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub use nse::NseEngine;
pub use os_fingerprint::OsFingerprinter;
pub use service_probe::{ServiceInfo, ServiceProbeEngine};
pub use traceroute::TracerouteEngine;
pub use udp::UdpScanner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTechnique {
    TcpConnect,
    Udp,
}

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

    pub fn top_1000() -> Vec<u16> {
        let mut ports = Vec::with_capacity(1000);
        // Standard system/privileged range
        for p in 1..=850 {
            ports.push(p);
        }
        // Most common registered/high services
        let high_common: &[u16] = &[
            873, 902, 990, 993, 995, 1025, 1026, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082,
            2083, 2086, 2087, 2181, 2222, 2375, 2376, 3000, 3128, 3306, 3389, 4243, 4443, 5000,
            5060, 5432, 5672, 5900, 6000, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
            9000, 9090, 9092, 9200, 9418, 9999, 10000, 11211, 27017, 50000,
        ];
        ports.extend_from_slice(high_common);
        ports.sort_unstable();
        ports.dedup();
        ports.truncate(1000);
        ports
    }

    pub fn parse_port_expression(expr: &str) -> Result<Vec<u16>> {
        let trimmed = expr.trim();
        if trimmed.is_empty() || trimmed == "top-100" {
            return Ok(Self::TOP_100.to_vec());
        }

        if trimmed == "top-1000" || trimmed == "default" {
            return Ok(Self::top_1000());
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

pub struct ScanReport {
    pub target: IpAddr,
    pub open_ports: Vec<ServiceRecord>,
    pub os_match: OsMatch,
    pub scan_duration: Duration,
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
                let info = ServiceProbeEngine::analyze_banner(port, banner.as_deref());
                ServiceRecord {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service_name: Some(info.name),
                    product: info.product,
                    version: info.version,
                    extra_info: info.extra_info,
                    banner,
                    last_observed: Utc::now(),
                }
            }
            Ok(Err(_)) => ServiceRecord {
                port,
                protocol: "tcp".to_string(),
                state: PortState::Closed,
                service_name: None,
                product: None,
                version: None,
                extra_info: None,
                banner: None,
                last_observed: start,
            },
            Err(_) => ServiceRecord {
                port,
                protocol: "tcp".to_string(),
                state: PortState::Filtered,
                service_name: None,
                product: None,
                version: None,
                extra_info: None,
                banner: None,
                last_observed: start,
            },
        }
    }

    async fn probe_service(mut stream: TcpStream, port: u16) -> Option<String> {
        let mut buf = [0u8; 2048];

        // 1. Passive banner read (FTP, SSH, SMTP send greeting automatically)
        if let Ok(Ok(n)) = timeout(Duration::from_millis(400), stream.read(&mut buf)).await {
            if n > 0 {
                return Some(String::from_utf8_lossy(&buf[..n]).trim().to_string());
            }
        }

        // 2. Active probe payload
        if let Some(payload) = ServiceProbeEngine::probe_payload(port) {
            if stream.write_all(payload).await.is_ok() {
                if let Ok(Ok(n)) = timeout(Duration::from_millis(600), stream.read(&mut buf)).await {
                    if n > 0 {
                        let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        return Some(text);
                    }
                }
            }
        }

        None
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

            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let on_res = on_result.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = SocketAddr::new(target, port);
                let record = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
                    Ok(Ok(stream)) => {
                        let banner = Self::probe_service(stream, port).await;
                        let info = ServiceProbeEngine::analyze_banner(port, banner.as_deref());
                        ServiceRecord {
                            port,
                            protocol: "tcp".to_string(),
                            state: PortState::Open,
                            service_name: Some(info.name),
                            product: info.product,
                            version: info.version,
                            extra_info: info.extra_info,
                            banner,
                            last_observed: Utc::now(),
                        }
                    }
                    Ok(Err(_)) => ServiceRecord {
                        port,
                        protocol: "tcp".to_string(),
                        state: PortState::Closed,
                        service_name: None,
                        product: None,
                        version: None,
                        extra_info: None,
                        banner: None,
                        last_observed: Utc::now(),
                    },
                    Err(_) => ServiceRecord {
                        port,
                        protocol: "tcp".to_string(),
                        state: PortState::Filtered,
                        service_name: None,
                        product: None,
                        version: None,
                        extra_info: None,
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
