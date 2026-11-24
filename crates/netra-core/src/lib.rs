use netra_common::{ExpertInfo, PacketMetadata, Result, SecurityVulnerability, TracerouteHop};
use netra_config::{AppConfig, RuntimePaths};
use netra_filter::FilterExpr;
use netra_intelligence::IntelligenceEngine;
use netra_parser::{CaptureFileReader, ExpertEngine};
use netra_scanner::{NseEngine, TracerouteEngine};
use netra_storage::StorageEngine;

pub struct NetraCore {
    pub paths: RuntimePaths,
    pub config: AppConfig,
    pub storage: StorageEngine,
    pub intelligence: IntelligenceEngine,
}

impl NetraCore {
    pub fn initialize() -> Result<Self> {
        let paths = RuntimePaths::resolve()?;
        let config = paths.load_or_init_config()?;
        let storage = StorageEngine::open(&paths.db_file)?;
        let intelligence = IntelligenceEngine::new(storage.clone());
        let _ = intelligence.load_from_storage();

        Ok(Self {
            paths,
            config,
            storage,
            intelligence,
        })
    }

    pub fn analyze_file<P: AsRef<std::path::Path>, F: FnMut(PacketMetadata) -> bool>(
        &self,
        path: P,
        filter_str: Option<&str>,
        mut on_match: F,
    ) -> Result<u64> {
        let filter = filter_str.map(FilterExpr::parse).unwrap_or(FilterExpr::All);

        CaptureFileReader::read_file(path, |packet| {
            if filter.matches(&packet) {
                self.intelligence.observe_packet(&packet);
                on_match(packet)
            } else {
                true
            }
        })
    }

    pub fn expert_info_for_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<Vec<ExpertInfo>> {
        let mut engine = ExpertEngine::new();
        let mut results = Vec::new();

        CaptureFileReader::read_packets_streaming(path, |index, raw| {
            if let Ok(meta) = netra_parser::PacketParser::parse_raw(raw, index, chrono::Utc::now()) {
                let alerts = engine.analyze(&meta, raw);
                results.extend(alerts);
            }
            true
        })?;

        Ok(results)
    }

    pub async fn traceroute<F>(&self, target: std::net::IpAddr, on_hop: F) -> Vec<TracerouteHop>
    where
        F: FnMut(TracerouteHop),
    {
        let engine = TracerouteEngine::default();
        engine.trace(target, on_hop).await
    }

    pub async fn audit_target(&self, target: std::net::IpAddr, open_ports: &[u16]) -> Vec<SecurityVulnerability> {
        let engine = NseEngine::default();
        engine.audit_target(target, open_ports).await
    }
}
