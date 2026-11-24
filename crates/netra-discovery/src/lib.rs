use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
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

    pub fn parse_targets(target_spec: &str) -> Result<Vec<IpAddr>> {
        let trimmed = target_spec.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }

        // 1. CIDR notation
        if trimmed.contains('/') {
            let v4s = Self::parse_cidr(trimmed)?;
            return Ok(v4s.into_iter().map(IpAddr::V4).collect());
        }

        // 2. IP Range notation (e.g. 192.168.1.1-50 or 192.168.1.10-192.168.1.20)
        if let Some((start_s, end_s)) = trimmed.split_once('-') {
            if let Ok(start_ip) = start_s.trim().parse::<Ipv4Addr>() {
                let start_u32 = u32::from(start_ip);
                let end_u32 = if let Ok(end_ip) = end_s.trim().parse::<Ipv4Addr>() {
                    u32::from(end_ip)
                } else if let Ok(end_last_octet) = end_s.trim().parse::<u8>() {
                    let octets = start_ip.octets();
                    u32::from(Ipv4Addr::new(octets[0], octets[1], octets[2], end_last_octet))
                } else {
                    return Err(netra_common::NetraError::Discovery("Invalid range end".into()));
                };

                if end_u32 >= start_u32 {
                    let mut res = Vec::new();
                    for ip_int in start_u32..=end_u32 {
                        res.push(IpAddr::V4(Ipv4Addr::from(ip_int)));
                    }
                    return Ok(res);
                }
            }
        }

        // 3. Single IP
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // 4. Hostname resolution
        let host_port = format!("{}:80", trimmed);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort();
            ips.dedup();
            if !ips.is_empty() {
                return Ok(ips);
            }
        }

        Err(netra_common::NetraError::Discovery(format!(
            "Unable to parse target specification: {}",
            trimmed
        )))
    }

    pub async fn discover_subnet<F: Fn(HostRecord) + Send + Sync + 'static>(
        &self,
        targets: Vec<Ipv4Addr>,
        on_host: F,
    ) {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let on_host = Arc::new(on_host);

        let probe_ports = [80, 443, 22, 445, 139, 8080, 53];
        let mut handles = Vec::new();

        for ip in targets {
            if self.stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

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
    fn test_parse_targets_range() {
        let ips = SubnetScanner::parse_targets("192.168.1.1-10").expect("Failed to parse range");
        assert_eq!(ips.len(), 10);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ips[9], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn test_parse_targets_single_ip() {
        let ips = SubnetScanner::parse_targets("10.0.0.1").expect("Failed single IP");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
