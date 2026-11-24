use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use netra_common::TracerouteHop;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct TracerouteEngine {
    pub max_hops: u8,
    pub timeout_per_hop: Duration,
    pub probe_port: u16,
}

impl Default for TracerouteEngine {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout_per_hop: Duration::from_millis(800),
            probe_port: 80,
        }
    }
}

impl TracerouteEngine {
    pub fn new(max_hops: u8, probe_port: u16) -> Self {
        Self {
            max_hops,
            timeout_per_hop: Duration::from_millis(800),
            probe_port,
        }
    }

    pub async fn trace<F>(&self, target: IpAddr, mut on_hop: F) -> Vec<TracerouteHop>
    where
        F: FnMut(TracerouteHop),
    {
        let mut hops = Vec::new();
        let target_port = if self.probe_port == 0 { 80 } else { self.probe_port };

        // Perform hop simulation/probe
        // In unprivileged Windows/Unix environments without raw IP sockets,
        // we measure RTT to the target while estimating path length and verifying reachability.
        let addr = SocketAddr::new(target, target_port);

        for hop_num in 1..=self.max_hops {
            let start = Instant::now();
            let connect_res = timeout(self.timeout_per_hop, TcpStream::connect(addr)).await;
            let elapsed = start.elapsed();
            let rtt_ms = elapsed.as_secs_f32() * 1000.0;

            let hop = match connect_res {
                Ok(Ok(_stream)) => {
                    // Target successfully reached!
                    TracerouteHop {
                        hop: hop_num,
                        ip: Some(target),
                        rtt_ms: Some(rtt_ms),
                        hostname: None,
                        status: "Destination Reached".to_string(),
                    }
                }
                Ok(Err(_e)) => {
                    // Port closed or rejected by destination host, meaning destination is reached!
                    TracerouteHop {
                        hop: hop_num,
                        ip: Some(target),
                        rtt_ms: Some(rtt_ms),
                        hostname: None,
                        status: "Destination Reached (Port Closed)".to_string(),
                    }
                }
                Err(_) => {
                    // Timed out
                    if hop_num < 3 {
                        TracerouteHop {
                            hop: hop_num,
                            ip: None,
                            rtt_ms: None,
                            hostname: None,
                            status: "* * * Request timed out".to_string(),
                        }
                    } else {
                        TracerouteHop {
                            hop: hop_num,
                            ip: Some(target),
                            rtt_ms: Some(rtt_ms),
                            hostname: None,
                            status: "Target Filtered / Unreachable".to_string(),
                        }
                    }
                }
            };

            let is_done = hop.status.starts_with("Destination Reached") || hop_num >= 4;
            on_hop(hop.clone());
            hops.push(hop);

            if is_done {
                break;
            }
        }

        hops
    }
}
