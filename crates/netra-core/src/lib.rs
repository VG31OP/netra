use netra_common::{PacketMetadata, Result};
use netra_config::{AppConfig, RuntimePaths};
use netra_filter::FilterExpr;
use netra_intelligence::IntelligenceEngine;
use netra_parser::CaptureFileReader;
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
}
