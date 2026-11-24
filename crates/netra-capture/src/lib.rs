use std::borrow::Cow;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use crossbeam_channel::Sender;
use netra_common::{MacAddress, NetraError, PacketMetadata, Result};
use pcap_file::pcap::{PcapHeader, PcapWriter, RawPcapPacket};

#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<MacAddress>,
    pub is_up: bool,
    pub is_loopback: bool,
}

pub trait CaptureAdapter: Send + Sync {
    fn list_interfaces(&self) -> Result<Vec<NetworkInterfaceInfo>>;
    fn start_capture(
        &self,
        interface_name: &str,
        packet_sender: Sender<PacketMetadata>,
        stop_signal: Arc<AtomicBool>,
    ) -> Result<()>;
}

pub struct CaptureManager {
    stop_signal: Arc<AtomicBool>,
}

impl Default for CaptureManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureManager {
    pub fn new() -> Self {
        Self {
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_signal.load(Ordering::SeqCst)
    }

    pub fn export_to_pcap<P: AsRef<Path>>(
        packets: &[Vec<u8>],
        output_path: P,
    ) -> Result<()> {
        let file = File::create(output_path)?;
        let header = PcapHeader::default();
        let mut writer = PcapWriter::with_header(file, header)
            .map_err(|e| NetraError::Capture(format!("Failed to initialize PCAP writer: {}", e)))?;

        for pkt in packets {
            let now = Utc::now();
            let duration = Duration::new(now.timestamp() as u64, now.timestamp_subsec_nanos());
            let raw_pkt = RawPcapPacket {
                ts_sec: duration.as_secs() as u32,
                ts_frac: duration.subsec_micros(),
                incl_len: pkt.len() as u32,
                orig_len: pkt.len() as u32,
                data: Cow::Borrowed(pkt),
            };
            writer
                .write_raw_packet(&raw_pkt)
                .map_err(|e| NetraError::Capture(format!("Failed to write packet: {}", e)))?;
        }

        Ok(())
    }
}
