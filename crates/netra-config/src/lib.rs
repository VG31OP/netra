use std::path::PathBuf;
use netra_common::{NetraError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub storage: StorageConfig,
    pub capture: CaptureConfig,
    pub dissection: DissectionConfig,
    pub scanner: ScannerConfig,
    pub security_audit: SecurityAuditConfig,
    pub logging: LoggingConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            storage: StorageConfig::default(),
            capture: CaptureConfig::default(),
            dissection: DissectionConfig::default(),
            scanner: ScannerConfig::default(),
            security_audit: SecurityAuditConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub offline_mode: bool,
    pub check_updates: bool,
    pub theme: String,
    pub time_display_format: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            offline_mode: true,
            check_updates: false,
            theme: "dark".to_string(),
            time_display_format: "relative".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
pub struct CaptureConfig {
    pub buffer_size_kb: usize,
    pub snaplen: u32,
    pub promiscuous: bool,
    pub default_filter: String,
    pub ring_buffer_count: usize,
    pub auto_stop_packets: Option<u64>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            buffer_size_kb: 2048,
            snaplen: 65535,
            promiscuous: false,
            default_filter: String::new(),
            ring_buffer_count: 5,
            auto_stop_packets: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DissectionConfig {
    pub relative_seq_numbers: bool,
    pub checksum_verification: bool,
    pub reassemble_tcp: bool,
    pub desegment_ssl: bool,
    pub resolve_mac_oui: bool,
}

impl Default for DissectionConfig {
    fn default() -> Self {
        Self {
            relative_seq_numbers: true,
            checksum_verification: true,
            reassemble_tcp: true,
            desegment_ssl: true,
            resolve_mac_oui: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub default_timeout_ms: u64,
    pub default_concurrency: usize,
    pub max_rate_limit_pps: u32,
    pub resolve_dns: bool,
    pub default_timing: u8,
    pub min_rtt_ms: u64,
    pub max_rtt_ms: u64,
    pub max_retries: u32,
    pub scan_delay_ms: u64,
    pub data_length: usize,
    pub scan_type: String,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 1200,
            default_concurrency: 100,
            max_rate_limit_pps: 500,
            resolve_dns: false,
            default_timing: 3,
            min_rtt_ms: 50,
            max_rtt_ms: 2000,
            max_retries: 2,
            scan_delay_ms: 0,
            data_length: 0,
            scan_type: "connect".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityAuditConfig {
    pub enabled: bool,
    pub check_ciphers: bool,
    pub check_anon_ftp: bool,
    pub check_smb_signing: bool,
    pub check_http_headers: bool,
    pub check_common_endpoints: bool,
    pub custom_user_agent: String,
}

impl Default for SecurityAuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_ciphers: true,
            check_anon_ftp: true,
            check_smb_signing: true,
            check_http_headers: true,
            check_common_endpoints: true,
            custom_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NETRA-Auditor/1.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_toml_backward_compatibility() {
        let partial_toml = r#"
            [general]
            offline_mode = true

            [storage]
            portable_mode = true
        "#;
        let config: AppConfig = toml::from_str(partial_toml).expect("Should deserialize partial config");
        assert!(config.general.offline_mode);
        assert_eq!(config.general.theme, "dark");
        assert_eq!(config.general.time_display_format, "relative");
        assert!(config.dissection.checksum_verification);
        assert_eq!(config.scanner.default_timing, 3);
        assert!(config.security_audit.enabled);
    }
}
