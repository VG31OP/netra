use std::path::Path;
use netra_common::{HostRecord, PacketMetadata, Result};

pub struct Exporter;

impl Exporter {
    pub fn export_hosts_json<P: AsRef<Path>>(hosts: &[HostRecord], path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(hosts)
            .map_err(|e| netra_common::NetraError::Export(format!("JSON serialization failed: {}", e)))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn export_hosts_csv<P: AsRef<Path>>(hosts: &[HostRecord], path: P) -> Result<()> {
        let mut wtr = csv::Writer::from_path(path)
            .map_err(|e| netra_common::NetraError::Export(format!("CSV writer initialization failed: {}", e)))?;

        wtr.write_record(&["IP", "MAC", "Hostname", "First Seen", "Last Seen", "Packets", "Services"])
            .map_err(|e| netra_common::NetraError::Export(e.to_string()))?;

        for h in hosts {
            let mac_str = h.mac.map(|m| m.to_string()).unwrap_or_default();
            let hostname_str = h.hostname.clone().unwrap_or_default();
            let services_str = h
                .services
                .iter()
                .map(|s| format!("{}/{}:{}", s.port, s.protocol, s.state))
                .collect::<Vec<_>>()
                .join("; ");

            wtr.write_record(&[
                h.ip.to_string(),
                mac_str,
                hostname_str,
                h.first_seen.to_rfc3339(),
                h.last_seen.to_rfc3339(),
                h.packet_count.to_string(),
                services_str,
            ])
            .map_err(|e| netra_common::NetraError::Export(e.to_string()))?;
        }

        wtr.flush().map_err(|e| netra_common::NetraError::Export(e.to_string()))?;
        Ok(())
    }

    pub fn export_packets_json<P: AsRef<Path>>(packets: &[PacketMetadata], path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(packets)
            .map_err(|e| netra_common::NetraError::Export(format!("JSON serialization failed: {}", e)))?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_hosts_json_and_csv() {
        let dir = std::env::temp_dir();
        let json_path = dir.join("test_export.json");
        let csv_path = dir.join("test_export.csv");

        let ip = "192.168.1.1".parse().unwrap();
        let mut host = HostRecord::new(ip);
        host.hostname = Some("router.home".to_string());
        host.services.push(netra_common::ServiceRecord {
            port: 53,
            protocol: "udp".to_string(),
            state: netra_common::PortState::Open,
            service_name: Some("dns".to_string()),
            product: None,
            version: None,
            extra_info: None,
            banner: None,
            last_observed: chrono::Utc::now(),
        });

        let hosts = vec![host];

        Exporter::export_hosts_json(&hosts, &json_path).expect("JSON export failed");
        assert!(json_path.exists());
        let json_content = std::fs::read_to_string(&json_path).unwrap();
        assert!(json_content.contains("router.home"));

        Exporter::export_hosts_csv(&hosts, &csv_path).expect("CSV export failed");
        assert!(csv_path.exists());
        let csv_content = std::fs::read_to_string(&csv_path).unwrap();
        assert!(csv_content.contains("192.168.1.1"));

        let _ = std::fs::remove_file(json_path);
        let _ = std::fs::remove_file(csv_path);
    }
}
