use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::Utc;
use netra_common::{HostRecord, MacAddress, PacketMetadata, Result, ServiceRecord};
use netra_storage::StorageEngine;
use parking_lot::RwLock;

#[derive(Clone)]
pub struct IntelligenceEngine {
    storage: StorageEngine,
    known_hosts: Arc<RwLock<HashMap<IpAddr, HostRecord>>>,
    dns_cache: Arc<RwLock<HashMap<String, IpAddr>>>,
}

impl IntelligenceEngine {
    pub fn new(storage: StorageEngine) -> Self {
        Self {
            storage,
            known_hosts: Arc::new(RwLock::new(HashMap::new())),
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn load_from_storage(&self) -> Result<()> {
        let hosts = self.storage.list_hosts()?;
        let mut map = self.known_hosts.write();
        for h in hosts {
            map.insert(h.ip, h);
        }
        Ok(())
    }

    pub fn observe_packet(&self, packet: &PacketMetadata) {
        if let Some(src_ip) = packet.source_ip {
            self.update_host_observation(src_ip, packet.source_mac);
        }
        if let Some(dst_ip) = packet.destination_ip {
            self.update_host_observation(dst_ip, packet.destination_mac);
        }
    }

    fn update_host_observation(&self, ip: IpAddr, mac: Option<MacAddress>) {
        let mut map = self.known_hosts.write();
        let entry = map.entry(ip).or_insert_with(|| HostRecord::new(ip));
        entry.last_seen = Utc::now();
        entry.packet_count += 1;
        if mac.is_some() && entry.mac.is_none() {
            entry.mac = mac;
        }

        // Persist periodically or update in storage
        let host_copy = entry.clone();
        drop(map);
        let _ = self.storage.upsert_host(&host_copy);
    }

    pub fn record_service(&self, host_ip: IpAddr, service: ServiceRecord) -> Result<()> {
        let mut map = self.known_hosts.write();
        let entry = map.entry(host_ip).or_insert_with(|| HostRecord::new(host_ip));
        entry.last_seen = Utc::now();

        // Update existing or append
        if let Some(existing) = entry.services.iter_mut().find(|s| s.port == service.port && s.protocol == service.protocol) {
            *existing = service;
        } else {
            entry.services.push(service);
        }

        let host_copy = entry.clone();
        drop(map);
        self.storage.upsert_host(&host_copy)
    }

    pub fn get_host(&self, ip: &IpAddr) -> Option<HostRecord> {
        self.known_hosts.read().get(ip).cloned()
    }

    pub fn all_hosts(&self) -> Vec<HostRecord> {
        self.known_hosts.read().values().cloned().collect()
    }
}
