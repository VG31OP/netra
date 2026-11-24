use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use netra_common::{PortState, ServiceRecord};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct PortScanner {
    timeout: Duration,
    concurrency: usize,
    stop_signal: Arc<AtomicBool>,
}

impl PortScanner {
    pub fn new(timeout_ms: u64, concurrency: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            concurrency,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
    }

    pub async fn scan_port(&self, target: IpAddr, port: u16) -> ServiceRecord {
        let addr = SocketAddr::new(target, port);
        let start = Utc::now();

        let state = match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                let banner = Self::grab_banner(stream).await;
                let service_name = Self::guess_service_name(port);
                return ServiceRecord {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service_name: Some(service_name),
                    banner,
                    last_observed: Utc::now(),
                };
            }
            Ok(Err(_)) => PortState::Closed,
            Err(_) => PortState::Filtered,
        };

        ServiceRecord {
            port,
            protocol: "tcp".to_string(),
            state,
            service_name: None,
            banner: None,
            last_observed: start,
        }
    }

    async fn grab_banner(mut stream: TcpStream) -> Option<String> {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 512];
        match timeout(Duration::from_millis(600), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if !text.is_empty() {
                    Some(text)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn guess_service_name(port: u16) -> String {
        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 => "http",
            110 => "pop3",
            143 => "imap",
            443 => "https",
            445 => "smb",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            6379 => "redis",
            8080 => "http-alt",
            8443 => "https-alt",
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

        let mut handles = Vec::new();
        for port in ports {
            if self.stop_signal.load(Ordering::Relaxed) {
                break;
            }
            let permit = sem.clone().acquire_owned().await;
            if permit.is_err() {
                break;
            }
            let timeout = self.timeout;
            let on_res = on_result.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = SocketAddr::new(target, port);
                let record = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                    Ok(Ok(stream)) => {
                        let banner = Self::grab_banner(stream).await;
                        let service_name = Self::guess_service_name(port);
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
