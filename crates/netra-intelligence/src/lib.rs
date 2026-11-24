use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use netra_common::{HostRecord, MacAddress, NetworkProtocol, PacketMetadata, Result, ServiceRecord};
use netra_storage::StorageEngine;
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct ConversationKey {
    pub ip_a: IpAddr,
    pub ip_b: IpAddr,
}

impl PartialEq for ConversationKey {
    fn eq(&self, other: &Self) -> bool {
        (self.ip_a == other.ip_a && self.ip_b == other.ip_b)
            || (self.ip_a == other.ip_b && self.ip_b == other.ip_a)
    }
}

impl Eq for ConversationKey {}

impl std::hash::Hash for ConversationKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if self.ip_a <= self.ip_b {
            self.ip_a.hash(state);
            self.ip_b.hash(state);
        } else {
            self.ip_b.hash(state);
            self.ip_a.hash(state);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConversationStats {
    pub packets_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone)]
pub struct IntelligenceEngine {
    storage: StorageEngine,
    known_hosts: Arc<RwLock<HashMap<IpAddr, HostRecord>>>,
    conversations: Arc<RwLock<HashMap<ConversationKey, ConversationStats>>>,
    protocol_distribution: Arc<RwLock<HashMap<NetworkProtocol, u64>>>,
    dns_cache: Arc<RwLock<HashMap<String, IpAddr>>>,
}

impl IntelligenceEngine {
    pub fn new(storage: StorageEngine) -> Self {
        Self {
            storage,
            known_hosts: Arc::new(RwLock::new(HashMap::new())),
            conversations: Arc::new(RwLock::new(HashMap::new())),
            protocol_distribution: Arc::new(RwLock::new(HashMap::new())),
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
        // 1. Update protocol distribution
        {
            let mut p_map = self.protocol_distribution.write();
            *p_map.entry(packet.protocol.clone()).or_insert(0) += 1;
        }

        // 2. Update host observations
        if let Some(src_ip) = packet.source_ip {
            self.update_host_observation(src_ip, packet.source_mac);
        }
        if let Some(dst_ip) = packet.destination_ip {
            self.update_host_observation(dst_ip, packet.destination_mac);
        }

        // 3. Update conversation statistics
        if let (Some(src), Some(dst)) = (packet.source_ip, packet.destination_ip) {
            let key = ConversationKey { ip_a: src, ip_b: dst };
            let mut convs = self.conversations.write();
            let entry = convs.entry(key).or_insert_with(|| ConversationStats {
                packets_a_to_b: 0,
                bytes_a_to_b: 0,
                packets_b_to_a: 0,
                bytes_b_to_a: 0,
                first_seen: packet.timestamp,
                last_seen: packet.timestamp,
            });

            entry.last_seen = packet.timestamp;
            if src <= dst {
                entry.packets_a_to_b += 1;
                entry.bytes_a_to_b += packet.length as u64;
            } else {
                entry.packets_b_to_a += 1;
                entry.bytes_b_to_a += packet.length as u64;
            }
        }

        // 4. Update DNS mappings
        if let (Some(ref name), Some(src_ip)) = (&packet.dns_name, packet.source_ip) {
            let mut dns = self.dns_cache.write();
            dns.insert(name.clone(), src_ip);
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

        let host_copy = entry.clone();
        drop(map);
        let _ = self.storage.upsert_host(&host_copy);
    }

    pub fn record_service(&self, host_ip: IpAddr, service: ServiceRecord) -> Result<()> {
        let mut map = self.known_hosts.write();
        let entry = map.entry(host_ip).or_insert_with(|| HostRecord::new(host_ip));
        entry.last_seen = Utc::now();

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

    pub fn protocol_stats(&self) -> Vec<(NetworkProtocol, u64)> {
        self.protocol_distribution.read().iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    pub fn conversations(&self) -> Vec<(ConversationKey, ConversationStats)> {
        self.conversations.read().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}
