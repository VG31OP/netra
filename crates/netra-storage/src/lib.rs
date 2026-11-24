use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use netra_common::{HostRecord, MacAddress, NetraError, PortState, Result, ServiceRecord};
use parking_lot::Mutex;
use rusqlite::{params, Connection};

#[derive(Clone)]
pub struct StorageEngine {
    conn: Arc<Mutex<Connection>>,
}

impl StorageEngine {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| NetraError::Storage(format!("Failed to open SQLite database: {}", e)))?;

        // Configure WAL mode and busy timeout for concurrent safety and performance
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| NetraError::Storage(format!("Failed to set database PRAGMAs: {}", e)))?;

        let engine = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        engine.init_schema()?;
        Ok(engine)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| NetraError::Storage(format!("Failed to open in-memory database: {}", e)))?;
        let engine = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        engine.init_schema()?;
        Ok(engine)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                packet_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                banner TEXT,
                last_observed TEXT NOT NULL,
                FOREIGN KEY(host_ip) REFERENCES hosts(ip) ON DELETE CASCADE,
                UNIQUE(host_ip, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS capture_sessions (
                id TEXT PRIMARY KEY,
                interface_name TEXT,
                file_path TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_ip);
            CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
            ",
        )
        .map_err(|e| NetraError::Storage(format!("Schema initialization failed: {}", e)))?;

        Ok(())
    }

    pub fn upsert_host(&self, host: &HostRecord) -> Result<()> {
        let conn = self.conn.lock();
        let mac_str = host.mac.as_ref().map(|m| m.to_string());
        conn.execute(
            "INSERT INTO hosts (ip, mac, hostname, first_seen, last_seen, packet_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(ip) DO UPDATE SET
                mac = COALESCE(?2, hosts.mac),
                hostname = COALESCE(?3, hosts.hostname),
                last_seen = ?5,
                packet_count = hosts.packet_count + ?6",
            params![
                host.ip.to_string(),
                mac_str,
                host.hostname,
                host.first_seen.to_rfc3339(),
                host.last_seen.to_rfc3339(),
                host.packet_count
            ],
        )
        .map_err(|e| NetraError::Storage(format!("Failed to upsert host: {}", e)))?;

        for svc in &host.services {
            conn.execute(
                "INSERT INTO services (host_ip, port, protocol, state, service_name, banner, last_observed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(host_ip, port, protocol) DO UPDATE SET
                    state = ?4,
                    service_name = COALESCE(?5, services.service_name),
                    banner = COALESCE(?6, services.banner),
                    last_observed = ?7",
                params![
                    host.ip.to_string(),
                    svc.port,
                    svc.protocol,
                    svc.state.to_string(),
                    svc.service_name,
                    svc.banner,
                    svc.last_observed.to_rfc3339()
                ],
            )
            .map_err(|e| NetraError::Storage(format!("Failed to upsert service: {}", e)))?;
        }

        Ok(())
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT ip, mac, hostname, first_seen, last_seen, packet_count FROM hosts ORDER BY last_seen DESC")
            .map_err(|e| NetraError::Storage(e.to_string()))?;

        let host_rows = stmt
            .query_map([], |row| {
                let ip_str: String = row.get(0)?;
                let mac_str: Option<String> = row.get(1)?;
                let hostname: Option<String> = row.get(2)?;
                let first_seen_str: String = row.get(3)?;
                let last_seen_str: String = row.get(4)?;
                let packet_count: u64 = row.get(5)?;

                Ok((ip_str, mac_str, hostname, first_seen_str, last_seen_str, packet_count))
            })
            .map_err(|e| NetraError::Storage(e.to_string()))?;

        let mut hosts = Vec::new();
        for r in host_rows {
            let (ip_str, mac_str, hostname, first_seen_str, last_seen_str, packet_count) =
                r.map_err(|e| NetraError::Storage(e.to_string()))?;

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let mac = mac_str.and_then(|m| m.parse::<MacAddress>().ok());
                let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                hosts.push(HostRecord {
                    ip,
                    mac,
                    hostname,
                    first_seen,
                    last_seen,
                    services: Vec::new(),
                    packet_count,
                });
            }
        }

        // Fetch services for each host
        for host in &mut hosts {
            let mut svc_stmt = conn
                .prepare("SELECT port, protocol, state, service_name, banner, last_observed FROM services WHERE host_ip = ?1")
                .map_err(|e| NetraError::Storage(e.to_string()))?;

            let svcs = svc_stmt
                .query_map([host.ip.to_string()], |row| {
                    let port: u16 = row.get(0)?;
                    let protocol: String = row.get(1)?;
                    let state_str: String = row.get(2)?;
                    let service_name: Option<String> = row.get(3)?;
                    let banner: Option<String> = row.get(4)?;
                    let last_obs_str: String = row.get(5)?;

                    let state = match state_str.as_str() {
                        "open" => PortState::Open,
                        "closed" => PortState::Closed,
                        "open|filtered" => PortState::OpenFiltered,
                        _ => PortState::Filtered,
                    };
                    let last_observed = DateTime::parse_from_rfc3339(&last_obs_str)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    Ok(ServiceRecord {
                        port,
                        protocol,
                        state,
                        service_name,
                        banner,
                        last_observed,
                    })
                })
                .map_err(|e| NetraError::Storage(e.to_string()))?;

            for s in svcs {
                if let Ok(svc) = s {
                    host.services.push(svc);
                }
            }
        }

        Ok(hosts)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_engine_in_memory() {
        let storage = StorageEngine::open_in_memory().expect("Failed to open in-memory DB");
        let ip: IpAddr = "192.168.1.15".parse().unwrap();
        let mut host = HostRecord::new(ip);
        host.hostname = Some("gateway.local".to_string());
        host.services.push(ServiceRecord {
            port: 80,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service_name: Some("http".to_string()),
            banner: Some("Apache/2.4".to_string()),
            last_observed: Utc::now(),
        });

        storage.upsert_host(&host).expect("Upsert failed");
        let hosts = storage.list_hosts().expect("Failed to list hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, ip);
        assert_eq!(hosts[0].hostname.as_deref(), Some("gateway.local"));
        assert_eq!(hosts[0].services.len(), 1);
        assert_eq!(hosts[0].services[0].port, 80);
    }
}
