use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use netra_common::{PortState, ServiceRecord};
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub struct UdpScanner {
    timeout: Duration,
    concurrency: usize,
    stop_signal: Arc<AtomicBool>,
}

impl UdpScanner {
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

    pub fn probe_payload(port: u16) -> &'static [u8] {
        match port {
            53 => &[
                // DNS query for "." IN A
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x01,
            ],
            123 => &[
                // NTP v3 client request
                0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            161 => &[
                // SNMP v1 GetRequest for sysDescr (community: public)
                0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
                0x63, 0xa0, 0x1c, 0x02, 0x04, 0x72, 0x93, 0x6a, 0x2b, 0x02, 0x01, 0x00,
                0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
                0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
            ],
            1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
            _ => &[0x00, 0x00, 0x00, 0x00],
        }
    }

    pub async fn scan_port(&self, target: IpAddr, port: u16) -> ServiceRecord {
        let bind_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let start = Utc::now();
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => {
                return ServiceRecord {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::Filtered,
                    service_name: None,
                    product: None,
                    version: None,
                    extra_info: None,
                    banner: None,
                    last_observed: start,
                }
            }
        };

        let target_sock = SocketAddr::new(target, port);
        let payload = Self::probe_payload(port);

        if sock.send_to(payload, target_sock).await.is_err() {
            return ServiceRecord {
                port,
                protocol: "udp".to_string(),
                state: PortState::Filtered,
                service_name: None,
                product: None,
                version: None,
                extra_info: None,
                banner: None,
                last_observed: start,
            };
        }

        let mut buf = [0u8; 1024];
        match timeout(self.timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let banner = if len > 0 {
                    Some(String::from_utf8_lossy(&buf[..len]).trim().to_string())
                } else {
                    None
                };
                let service_name = match port {
                    53 => "domain",
                    123 => "ntp",
                    161 => "snmp",
                    1900 => "upnp",
                    _ => "udp-service",
                };

                ServiceRecord {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::Open,
                    service_name: Some(service_name.to_string()),
                    product: None,
                    version: None,
                    extra_info: None,
                    banner,
                    last_observed: Utc::now(),
                }
            }
            _ => {
                // In UDP scanning without ICMP unreachable feedback, no response is open|filtered
                ServiceRecord {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::OpenFiltered,
                    service_name: None,
                    product: None,
                    version: None,
                    extra_info: None,
                    banner: None,
                    last_observed: start,
                }
            }
        }
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

        let mut handles = Vec::new();
        for port in ports {
            if self.stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let on_res = on_result.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let scanner = UdpScanner::new(timeout_dur.as_millis() as u64, 1);
                let record = scanner.scan_port(target, port).await;
                on_res(record);
            }));
        }

        for h in handles {
            let _ = h.await;
        }
    }
}
