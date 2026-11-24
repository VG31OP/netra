use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use netra_common::{HostRecord, Result};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct SubnetScanner {
    timeout: Duration,
    concurrency: usize,
    stop_signal: Arc<AtomicBool>,
}

impl SubnetScanner {
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

    pub fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(netra_common::NetraError::Discovery(format!(
                "Invalid CIDR notation: {}",
                cidr
            )));
        }

        let base_ip: Ipv4Addr = parts[0].parse().map_err(|e| {
            netra_common::NetraError::Discovery(format!("Invalid IP in CIDR: {}", e))
        })?;
        let prefix_len: u32 = parts[1].parse().map_err(|e| {
            netra_common::NetraError::Discovery(format!("Invalid prefix in CIDR: {}", e))
        })?;

        if prefix_len > 32 {
            return Err(netra_common::NetraError::Discovery(
                "Prefix length must be <= 32".into(),
            ));
        }

        let base_u32 = u32::from(base_ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let network = base_u32 & mask;
        let count = 1u32 << (32 - prefix_len);

        let mut ips = Vec::new();
        // Skip network and broadcast for typical /24 subnets
        let (start, end) = if prefix_len >= 31 {
            (0, count)
        } else {
            (1, count - 1)
        };

        for i in start..end {
            ips.push(Ipv4Addr::from(network + i));
        }

        Ok(ips)
    }

    pub async fn discover_subnet<F: Fn(HostRecord) + Send + Sync + 'static>(
        &self,
        targets: Vec<Ipv4Addr>,
        on_host: F,
    ) {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let on_host = Arc::new(on_host);

        let probe_ports = [80, 443, 22, 445, 139, 8080];
        let mut handles = Vec::new();

        for ip in targets {
            if self.stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let permit = sem.clone().acquire_owned().await;
            if permit.is_err() {
                break;
            }

            let timeout_dur = self.timeout;
            let on_host_cb = on_host.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let ip_addr = IpAddr::V4(ip);

                // Quick TCP probe across common ports to check if host is responsive
                for &port in &probe_ports {
                    let addr = SocketAddr::new(ip_addr, port);
                    if let Ok(Ok(_)) = timeout(timeout_dur, TcpStream::connect(&addr)).await {
                        let mut host = HostRecord::new(ip_addr);
                        host.last_seen = Utc::now();
                        on_host_cb(host);
                        return;
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_slash_24() {
        let ips = SubnetScanner::parse_cidr("192.168.1.0/24").expect("Failed to parse /24");
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_parse_cidr_slash_30() {
        let ips = SubnetScanner::parse_cidr("10.0.0.0/30").expect("Failed to parse /30");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[1], Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_parse_invalid_cidr() {
        assert!(SubnetScanner::parse_cidr("not-a-cidr").is_err());
        assert!(SubnetScanner::parse_cidr("192.168.1.0/33").is_err());
    }
}
