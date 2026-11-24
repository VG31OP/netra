use std::path::PathBuf;
use netra_common::{NetraError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub storage: StorageConfig,
    pub capture: CaptureConfig,
    pub scanner: ScannerConfig,
    pub logging: LoggingConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            storage: StorageConfig::default(),
            capture: CaptureConfig::default(),
            scanner: ScannerConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub offline_mode: bool,
    pub check_updates: bool,
    pub theme: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            offline_mode: true,
            check_updates: false,
            theme: "dark".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    pub portable_mode: bool,
    pub max_db_size_mb: u64,
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            portable_mode: false,
            max_db_size_mb: 1024,
            retention_days: 90,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub buffer_size_kb: usize,
    pub snaplen: u32,
    pub promiscuous: bool,
    pub default_filter: String,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            buffer_size_kb: 2048,
            snaplen: 65535,
            promiscuous: false,
            default_filter: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub default_timeout_ms: u64,
    pub default_concurrency: usize,
    pub max_rate_limit_pps: u32,
    pub resolve_dns: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 1200,
            default_concurrency: 100,
            max_rate_limit_pps: 500,
            resolve_dns: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub log_to_file: bool,
    pub redact_sensitive: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_to_file: true,
            redact_sensitive: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimePaths {
    pub is_portable: bool,
    pub root_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub captures_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub db_file: PathBuf,
}

impl RuntimePaths {
    pub fn resolve() -> Result<Self> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        let portable_flag = exe_dir.join("portable.flag");
        let is_portable = portable_flag.exists();

        let (root_dir, data_dir, config_file, logs_dir) = if is_portable {
            let root = exe_dir.clone();
            let data = root.join("data");
            let conf = root.join("config").join("settings.toml");
            let logs = root.join("logs");
            (root, data, conf, logs)
        } else {
            let proj_dirs = directories::ProjectDirs::from("org", "netra", "netra")
                .ok_or_else(|| NetraError::Config("Could not resolve system directories".into()))?;
            let data = proj_dirs.data_dir().to_path_buf();
            let conf = proj_dirs.config_dir().join("settings.toml");
            let logs = data.join("logs");
            (data.clone(), data, conf, logs)
        };

        let captures_dir = data_dir.join("captures");
        let exports_dir = data_dir.join("exports");
        let db_file = data_dir.join("netra.db");

        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&captures_dir)?;
        std::fs::create_dir_all(&exports_dir)?;
        std::fs::create_dir_all(&logs_dir)?;
        if let Some(parent) = config_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(Self {
            is_portable,
            root_dir,
            config_file,
            data_dir,
            captures_dir,
            exports_dir,
            logs_dir,
            db_file,
        })
    }

    pub fn load_or_init_config(&self) -> Result<AppConfig> {
        if self.config_file.exists() {
            let content = std::fs::read_to_string(&self.config_file)?;
            toml::from_str(&content)
                .map_err(|e| NetraError::Config(format!("Failed to parse TOML configuration: {}", e)))
        } else {
            let mut conf = AppConfig::default();
            conf.storage.portable_mode = self.is_portable;
            let serialized = toml::to_string_pretty(&conf)
                .map_err(|e| NetraError::Config(format!("Failed to serialize default config: {}", e)))?;
            std::fs::write(&self.config_file, serialized)?;
            Ok(conf)
        }
    }
}
