use std::rc::Rc;
use netra_core::NetraCore;
use slint::VecModel;

slint::include_modules!();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Initializing NETRA Desktop Application...");

    let core = match NetraCore::initialize() {
        Ok(c) => Rc::new(c),
        Err(e) => {
            eprintln!("Failed to initialize NETRA Core: {}", e);
            std::process::exit(1);
        }
    };

    let main_window = MainWindow::new()?;

    // Update initial status
    let mode_str = if core.paths.is_portable {
        "Portable Mode (Active)"
    } else {
        "Installed Mode"
    };
    main_window.set_storage_mode(mode_str.into());

    let hosts = core.intelligence.all_hosts();
    main_window.set_known_hosts_count(hosts.len() as i32);
    main_window.set_status_message("NETRA Core Engine Online".into());

    // Connect Load Capture File callback
    let core_for_capture = core.clone();
    let window_handle = main_window.as_weak();
    main_window.on_load_capture_file(move || {
        let core = core_for_capture.clone();
        if let Some(ui) = window_handle.upgrade() {
            // Check if sample_capture.pcap exists or load default
            let capture_path = std::path::Path::new("sample_capture.pcap");
            if capture_path.exists() {
                let mut packets = Vec::new();
                let _ = core.analyze_file(capture_path, None, |pkt| {
                    packets.push(PacketItem {
                        index: pkt.index as i32,
                        protocol: pkt.protocol.to_string().into(),
                        source: pkt.source_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()).into(),
                        destination: pkt.destination_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()).into(),
                        length: pkt.length as i32,
                        summary: pkt.summary.into(),
                    });
                    packets.len() < 100
                });

                let count = packets.len() as i32;
                let model = Rc::new(VecModel::from(packets));
                ui.set_packet_list(model.into());
                ui.set_total_packets_count(count);
                ui.set_status_message(format!("Loaded {} packets from {}", count, capture_path.display()).into());
            } else {
                ui.set_status_message("No sample_capture.pcap found in current directory.".into());
            }
        }
    });

    main_window.run()?;
    Ok(())
}
