use std::path::Path;
use std::sync::{Arc, Mutex};
use netra_core::NetraCore;
use netra_discovery::SubnetScanner;
use netra_parser::{CaptureFileReader, HexDumpViewer, PacketParser};
use netra_scanner::{OsFingerprinter, PortPresets, PortScanner, TimingTemplate};
use slint::{ComponentHandle, ModelRc, VecModel};

slint::include_modules!();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Initializing NETRA Desktop Application (Wireshark + Nmap Engine)...");

    let core = match NetraCore::initialize() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Failed to initialize NETRA Core: {}", e);
            std::process::exit(1);
        }
    };

    let main_window = MainWindow::new()?;

    // Update storage mode badge
    let mode_str = if core.paths.is_portable {
        "Portable Mode (Active)"
    } else {
        "Installed Mode"
    };
    main_window.set_storage_mode(mode_str.into());

    let hosts = core.intelligence.all_hosts();
    main_window.set_known_hosts_count(hosts.len() as i32);
    main_window.set_status_message("NETRA Unified Engine Online".into());

    // Helper closure to load packets and refresh 3-pane views
    let load_packets_ui = {
        let core = core.clone();
        let window_weak = main_window.as_weak();
        move |filter: Option<String>| {
            if let Some(ui) = window_weak.upgrade() {
                let capture_path = Path::new("sample_capture.pcap");
                if capture_path.exists() {
                    let mut packets = Vec::new();
                    let filter_ref = filter.as_deref().filter(|s| !s.trim().is_empty());
                    let _ = core.analyze_file(capture_path, filter_ref, |pkt| {
                        packets.push(PacketItem {
                            index: pkt.index as i32,
                            protocol: pkt.protocol.to_string().into(),
                            source: pkt.source_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()).into(),
                            destination: pkt.destination_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()).into(),
                            length: pkt.length as i32,
                            summary: pkt.summary.into(),
                        });
                        packets.len() < 200
                    });

                    let count = packets.len() as i32;
                    let first_index = packets.first().map(|p| p.index).unwrap_or(1);
                    ui.set_packet_list(ModelRc::new(VecModel::from(packets)));
                    ui.set_total_packets_count(count);
                    ui.set_selected_packet_index(first_index);

                    // Load packet #1 details and hex dump
                    if let Ok(Some(raw)) = CaptureFileReader::read_packet_raw(capture_path, first_index as u64) {
                        let hex = HexDumpViewer::format(&raw);
                        ui.set_hexdump_content(hex.into());

                        let tree = PacketParser::dissect_tree(&raw, first_index as u64, chrono::Utc::now());
                        let mut layers = Vec::new();
                        for layer in tree.layers {
                            let details_str = layer.fields.iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect::<Vec<_>>()
                                .join("  |  ");
                            layers.push(DissectedLayerItem {
                                name: layer.name.into(),
                                detail: details_str.into(),
                            });
                        }
                        ui.set_layer_list(ModelRc::new(VecModel::from(layers)));
                    }

                    let msg = if let Some(f) = filter {
                        format!("Loaded {} packets (Filter: \"{}\")", count, f)
                    } else {
                        format!("Loaded {} packets from {}", count, capture_path.display())
                    };
                    ui.set_status_message(msg.into());
                } else {
                    ui.set_status_message("No sample_capture.pcap found in current directory.".into());
                }
            }
        }
    };

    // Load initial packets if sample_capture.pcap exists
    load_packets_ui(None);

    // Callback: Open / Reload capture file
    {
        let load_fn = load_packets_ui.clone();
        main_window.on_load_capture_file(move || {
            load_fn(None);
        });
    }

    // Callback: Apply display filter
    {
        let load_fn = load_packets_ui.clone();
        main_window.on_apply_filter(move |filter_str| {
            load_fn(Some(filter_str.to_string()));
        });
    }

    // Callback: Select packet in table (Update middle tree and bottom hex dump)
    {
        let window_weak = main_window.as_weak();
        main_window.on_select_packet(move |index| {
            if let Some(ui) = window_weak.upgrade() {
                let capture_path = Path::new("sample_capture.pcap");
                if let Ok(Some(raw)) = CaptureFileReader::read_packet_raw(capture_path, index as u64) {
                    let hex = HexDumpViewer::format(&raw);
                    ui.set_hexdump_content(hex.into());

                    let tree = PacketParser::dissect_tree(&raw, index as u64, chrono::Utc::now());
                    let mut layers = Vec::new();
                    for layer in tree.layers {
                        let details_str = layer.fields.iter()
                            .map(|(k, v)| format!("{}: {}", k, v))
                            .collect::<Vec<_>>()
                            .join("  |  ");
                        layers.push(DissectedLayerItem {
                            name: layer.name.into(),
                            detail: details_str.into(),
                        });
                    }
                    ui.set_layer_list(ModelRc::new(VecModel::from(layers)));
                    ui.set_status_message(format!("Inspecting packet #{} ({} bytes)", index, raw.len()).into());
                }
            }
        });
    }

    // Callback: Run Nmap scan
    {
        let core = core.clone();
        let window_weak = main_window.as_weak();
        main_window.on_run_scan(move |target_str, ports_str, timing| {
            let _core = core.clone();
            let window_weak = window_weak.clone();
            let target_s = target_str.to_string();
            let ports_s = ports_str.to_string();

            if let Some(ui) = window_weak.upgrade() {
                ui.set_status_message(format!("Nmap Scan running against {}...", target_s).into());
            }

            tokio::spawn(async move {
                let target_ips = match SubnetScanner::parse_targets(&target_s) {
                    Ok(ips) if !ips.is_empty() => ips,
                    _ => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = window_weak.upgrade() {
                                ui.set_status_message("Error: Invalid target IP or hostname".into());
                            }
                        });
                        return;
                    }
                };

                let target_ip = target_ips[0];
                let port_list = PortPresets::parse_port_expression(&ports_s).unwrap_or_else(|_| PortPresets::TOP_100.to_vec());
                let template = TimingTemplate::from_level(timing as u8);
                let scanner = PortScanner::with_timing(template);

                let discovered = Arc::new(Mutex::new(Vec::new()));
                let disc_clone = discovered.clone();

                scanner.scan_ports(target_ip, port_list, move |rec| {
                    if rec.state == netra_common::PortState::Open {
                        if let Ok(mut lock) = disc_clone.lock() {
                            lock.push(rec);
                        }
                    }
                }).await;

                let open_svcs = match discovered.lock() {
                    Ok(guard) => guard.clone(),
                    Err(poisoned) => poisoned.into_inner().clone(),
                };
                let svc_infos: Vec<netra_scanner::ServiceInfo> = open_svcs.iter().map(|s| {
                    netra_scanner::ServiceInfo {
                        name: s.service_name.clone().unwrap_or_default(),
                        product: s.product.clone(),
                        version: s.version.clone(),
                        extra_info: s.extra_info.clone(),
                        cpe: None,
                    }
                }).collect();
                let banners: Vec<String> = open_svcs.iter().filter_map(|s| s.banner.clone()).collect();
                let os_match = OsFingerprinter::fingerprint(Some(64), Some(65535), &svc_infos, &banners);

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = window_weak.upgrade() {
                        let mut results = Vec::new();
                        for s in &open_svcs {
                            let ver_str = match (&s.product, &s.version, &s.extra_info) {
                                (Some(p), Some(v), Some(e)) => format!("{} {} ({})", p, v, e),
                                (Some(p), Some(v), None) => format!("{} {}", p, v),
                                (Some(p), None, Some(e)) => format!("{} ({})", p, e),
                                (Some(p), None, None) => p.clone(),
                                _ => s.banner.clone().unwrap_or_default(),
                            };

                            results.push(ScannedPortItem {
                                port: format!("{}/tcp", s.port).into(),
                                state: "open".into(),
                                service: s.service_name.clone().unwrap_or_else(|| "unknown".into()).into(),
                                version: ver_str.into(),
                            });
                        }

                        let count = results.len();
                        ui.set_scan_results(ModelRc::new(VecModel::from(results)));
                        ui.set_open_ports_count(count as i32);
                        ui.set_os_match_text(format!("OS Match: {} (Family: {}, Accuracy: {}%)", os_match.name, os_match.family, os_match.accuracy).into());
                        ui.set_status_message(format!("Nmap Scan completed: {} open ports discovered on {}", count, target_ip).into());
                    }
                });
            });
        });
    }

    // Callback: Refresh Traffic Statistics
    {
        let core = core.clone();
        let window_weak = main_window.as_weak();
        main_window.on_refresh_stats(move || {
            if let Some(ui) = window_weak.upgrade() {
                // Protocol stats
                let mut p_stats = Vec::new();
                for (proto, count) in core.intelligence.protocol_stats() {
                    p_stats.push(ProtocolStatItem {
                        protocol: proto.to_string().into(),
                        packets: count as i32,
                    });
                }
                ui.set_protocol_stats(ModelRc::new(VecModel::from(p_stats)));

                // Conversations
                let mut convs = Vec::new();
                for (k, s) in core.intelligence.conversations() {
                    let total_packets = s.packets_a_to_b + s.packets_b_to_a;
                    let total_bytes = s.bytes_a_to_b + s.bytes_b_to_a;
                    convs.push(ConversationItem {
                        endpoint_a: k.ip_a.to_string().into(),
                        endpoint_b: k.ip_b.to_string().into(),
                        packets: total_packets as i32,
                        bytes: total_bytes as i32,
                    });
                }
                ui.set_conversation_list(ModelRc::new(VecModel::from(convs)));
            }
        });
    }

    // Callback: Nav changed
    {
        let core = core.clone();
        let window_weak = main_window.as_weak();
        main_window.on_nav_changed(move |nav| {
            if let Some(ui) = window_weak.upgrade() {
                if nav == "inventory" {
                    let hosts = core.intelligence.all_hosts();
                    let mut items = Vec::new();
                    for h in hosts {
                        let svcs = h.services.iter()
                            .map(|s| format!("{}/{}", s.port, s.protocol))
                            .collect::<Vec<_>>()
                            .join(", ");

                        items.push(HostItem {
                            ip: h.ip.to_string().into(),
                            mac: h.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".to_string()).into(),
                            os: h.os_match.map(|o| o.name).unwrap_or_else(|| "General IP Host".to_string()).into(),
                            services: if svcs.is_empty() { "-".into() } else { svcs.into() },
                            packets: h.packet_count as i32,
                        });
                    }
                    ui.set_host_list(ModelRc::new(VecModel::from(items)));
                }
            }
        });
    }

    main_window.run()?;
    Ok(())
}
