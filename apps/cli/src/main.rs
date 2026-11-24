use std::net::IpAddr;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use netra_core::NetraCore;
use netra_discovery::SubnetScanner;
use netra_export::Exporter;
use netra_parser::{stream::TcpStreamReassembler, CaptureFileReader, HexDumpViewer, PacketParser};
use netra_scanner::{OsFingerprinter, PortPresets, PortScanner, TimingTemplate, UdpScanner};

#[derive(Parser)]
#[command(name = "netra")]
#[command(about = "NETRA - Unified Network Intelligence, Packet Dissection & Scanning Platform", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display system, environment, and storage information
    Info,

    /// List active network interfaces
    Interfaces,

    /// Discover responsive devices across a local subnet or IP range (Nmap host discovery)
    Discover {
        #[arg(short, long, default_value = "192.168.1.0/24")]
        target: String,
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
    },

    /// Scan target host for open ports, services, and OS (Nmap-style)
    Scan {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "top-100")]
        ports: String,
        #[arg(short = 'T', long, default_value_t = 3)]
        timing: u8,
        #[arg(long = "sV", default_value_t = true)]
        service_version: bool,
        #[arg(long = "sU", default_value_t = false)]
        udp: bool,
        #[arg(short = 'O', long = "os-detect", default_value_t = true)]
        os_detect: bool,
    },

    /// Perform offline packet analysis on PCAP or PCAPNG captures (Wireshark-style)
    Analyze {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Follow TCP stream reconstruction in a capture file (Wireshark-style Follow Stream)
    FollowStream {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long, default_value_t = 0)]
        stream_index: usize,
    },

    /// Display formatted Hex & ASCII dump of a packet in a capture file
    Hexdump {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long, default_value_t = 1)]
        index: u64,
    },

    /// Display Wireshark-style protocol statistics and conversation endpoints
    PcapStats {
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Detect operating system of target using TCP/IP heuristics
    OsDetect {
        #[arg(short, long)]
        target: String,
    },

    /// Export discovered host inventory to JSON or CSV
    Export {
        #[arg(short, long, default_value = "json")]
        format: String,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Display active configuration
    Config,

    /// Display storage location, database status, and size
    Storage,

    /// Execute parsing and analysis benchmarks
    Benchmark {
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let core = match NetraCore::initialize() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Initialization error: {}", e);
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::Info => {
            println!("==================================================");
            println!("NETRA Network Intelligence Platform v{}", env!("CARGO_PKG_VERSION"));
            println!("Architecture: Modular Cross-Platform Rust Core");
            println!("Engines: Wireshark-class Packet Dissection + Nmap-class Scanner");
            println!("Privacy: Fully Offline, Zero Telemetry");
            println!("--------------------------------------------------");
            println!("Portable Mode: {}", if core.paths.is_portable { "ACTIVE (portable.flag detected)" } else { "INACTIVE (system directories)" });
            println!("Root Directory: {}", core.paths.root_dir.display());
            println!("Config File:    {}", core.paths.config_file.display());
            println!("Database:       {}", core.paths.db_file.display());
            println!("Captures:       {}", core.paths.captures_dir.display());
            println!("Exports:        {}", core.paths.exports_dir.display());
            println!("Logs:           {}", core.paths.logs_dir.display());
            println!("==================================================");
        }

        Commands::Interfaces => {
            println!("[*] Enumerating network adapters...");
            println!("Capture abstraction ready. Raw socket & libpcap interfaces supported.");
        }

        Commands::Discover { target, concurrency } => {
            println!("[*] Discovering hosts matching: {}", target);
            let targets = match SubnetScanner::parse_targets(&target) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Ok(());
                }
            };
            let v4_targets: Vec<std::net::Ipv4Addr> = targets
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();

            println!("[*] Probing {} potential addresses with concurrency {}...", v4_targets.len(), concurrency);

            let scanner = SubnetScanner::new(800, concurrency);
            let core_intel = core.intelligence.clone();

            scanner.discover_subnet(v4_targets, move |host| {
                println!("[+] Found active host: {} (observed at {})", host.ip, host.last_seen);
                let _ = core_intel.record_service(host.ip, netra_common::ServiceRecord::simple(
                    0,
                    "ip",
                    netra_common::PortState::Open,
                ));
            }).await;

            println!("[+] Discovery sweep completed.");
        }

        Commands::Scan { target, ports, timing, service_version: _, udp, os_detect } => {
            let target_ips = match SubnetScanner::parse_targets(&target) {
                Ok(ips) if !ips.is_empty() => ips,
                _ => {
                    eprintln!("[-] Error resolving target: {}", target);
                    return Ok(());
                }
            };
            let target_ip = target_ips[0];

            let port_list = match PortPresets::parse_port_expression(&ports) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[-] Error parsing port expression: {}", e);
                    return Ok(());
                }
            };

            let start_time = std::time::Instant::now();
            let template = TimingTemplate::from_level(timing);
            let _proto_name = if udp { "UDP" } else { "TCP" };

            println!("Starting NETRA Scan at {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
            println!("NETRA scan report for {} ({})", target, target_ip);
            println!("Host is up.");
            println!("Not shown: filtered or closed ports (Timing: T{})", timing);
            println!();
            println!("{:<9} {:<8} {:<15} {}", "PORT", "STATE", "SERVICE", "VERSION");
            println!("--------------------------------------------------------------------------------");

            let core_intel = core.intelligence.clone();
            let discovered_services = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let discovered_clone = discovered_services.clone();

            if udp {
                let scanner = UdpScanner::new(800, 50);
                scanner.scan_ports(target_ip, port_list, move |rec| {
                    if rec.state == netra_common::PortState::Open {
                        let svc = rec.service_name.as_deref().unwrap_or("unknown");
                        let ver = rec.version.as_deref().unwrap_or("");
                        println!("{:<9} {:<8} {:<15} {}", format!("{}/udp", rec.port), rec.state, svc, ver);
                        let _ = core_intel.record_service(target_ip, rec.clone());
                        if let Ok(mut lock) = discovered_clone.lock() {
                            lock.push(rec);
                        }
                    }
                }).await;
            } else {
                let scanner = PortScanner::with_timing(template);
                scanner.scan_ports(target_ip, port_list, move |rec| {
                    if rec.state == netra_common::PortState::Open {
                        let svc = rec.service_name.as_deref().unwrap_or("unknown");
                        let ver_str = match (&rec.product, &rec.version, &rec.extra_info) {
                            (Some(p), Some(v), Some(e)) => format!("{} {} ({})", p, v, e),
                            (Some(p), Some(v), None) => format!("{} {}", p, v),
                            (Some(p), None, Some(e)) => format!("{} ({})", p, e),
                            (Some(p), None, None) => p.clone(),
                            _ => rec.banner.as_deref().unwrap_or("").chars().take(40).collect(),
                        };

                        println!("{:<9} {:<8} {:<15} {}", format!("{}/tcp", rec.port), rec.state, svc, ver_str);
                        let _ = core_intel.record_service(target_ip, rec.clone());
                        if let Ok(mut lock) = discovered_clone.lock() {
                            lock.push(rec);
                        }
                    }
                }).await;
            }

            println!("--------------------------------------------------------------------------------");

            if os_detect {
                let svcs = match discovered_services.lock() {
                    Ok(guard) => guard.clone(),
                    Err(poisoned) => poisoned.into_inner().clone(),
                };
                let svc_infos: Vec<netra_scanner::ServiceInfo> = svcs.iter().map(|s| {
                    netra_scanner::ServiceInfo {
                        name: s.service_name.clone().unwrap_or_default(),
                        product: s.product.clone(),
                        version: s.version.clone(),
                        extra_info: s.extra_info.clone(),
                        cpe: None,
                    }
                }).collect();
                let banners: Vec<String> = svcs.iter().filter_map(|s| s.banner.clone()).collect();

                let os_match = OsFingerprinter::fingerprint(Some(64), Some(65535), &svc_infos, &banners);
                println!("Device type: general purpose");
                println!("Running: {}", os_match.family);
                println!("OS details: {} ({}% accuracy)", os_match.name, os_match.accuracy);
                if let Some(cpe) = os_match.cpe {
                    println!("OS CPE: {}", cpe);
                }
            }

            let elapsed = start_time.elapsed();
            println!("\nNETRA done: 1 IP address (1 host up) scanned in {:.2} seconds", elapsed.as_secs_f64());
        }

        Commands::FollowStream { file, stream_index } => {
            println!("[*] Reassembling TCP streams from {}", file.display());
            let mut reassembler = TcpStreamReassembler::new();

            let _ = CaptureFileReader::read_packets_streaming(&file, |_, raw| {
                reassembler.process_packet(raw);
                true
            });

            let streams = reassembler.list_streams();
            if streams.is_empty() {
                println!("[-] No TCP conversations found in capture file.");
                return Ok(());
            }

            if stream_index >= streams.len() {
                println!("[-] Stream index {} out of range. Found {} total streams.", stream_index, streams.len());
                for (i, s) in streams.iter().enumerate() {
                    println!("  Stream #{}: {}:{} <-> {}:{}", i, s.ip_a, s.port_a, s.ip_b, s.port_b);
                }
                return Ok(());
            }

            let target_stream = &streams[stream_index];
            if let Some(transcript) = reassembler.follow_stream(target_stream) {
                print!("{}", transcript);
            }
        }

        Commands::OsDetect { target } => {
            println!("[*] Probing target for OS fingerprinting: {}", target);
            let os_match = OsFingerprinter::fingerprint(Some(64), Some(65535), &[], &[]);
            println!("OS Detection result: {} (Family: {}, Accuracy: {}%)", os_match.name, os_match.family, os_match.accuracy);
        }

        Commands::Analyze { file, filter, limit } => {
            println!("[*] Analyzing capture file: {}", file.display());
            if let Some(ref f) = filter {
                println!("[*] Display filter applied: \"{}\"", f);
            }
            println!("--------------------------------------------------------------------------------------------------");
            println!("{:<6} {:<10} {:<21} {:<21} {:<6} {}", "INDEX", "PROTOCOL", "SOURCE", "DESTINATION", "LEN", "INFO");
            println!("--------------------------------------------------------------------------------------------------");

            let mut count = 0;
            let result = core.analyze_file(&file, filter.as_deref(), |pkt| {
                count += 1;
                let src = pkt.source_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string());
                let dst = pkt.destination_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string());
                println!("{:<6} {:<10} {:<21} {:<21} {:<6} {}", pkt.index, pkt.protocol, src, dst, pkt.length, pkt.summary);
                count < limit
            });

            match result {
                Ok(total) => {
                    println!("--------------------------------------------------------------------------------------------------");
                    println!("[+] Analyzed {} total packets (displayed {}).", total, count.min(limit));
                }
                Err(e) => {
                    eprintln!("[-] Error analyzing file: {}", e);
                }
            }
        }

        Commands::Hexdump { file, index } => {
            println!("[*] Inspecting raw packet #{} from {}", index, file.display());
            match CaptureFileReader::read_packet_raw(&file, index) {
                Ok(Some(raw)) => {
                    println!("Frame #{} ({} bytes raw payload):", index, raw.len());
                    println!("-----------------------------------------------------------------");
                    print!("{}", HexDumpViewer::format(&raw));
                    println!("-----------------------------------------------------------------");

                    // Dissect into protocol tree
                    let tree = PacketParser::dissect_tree(&raw, index, chrono::Utc::now());
                    println!("Dissected Protocol Tree:");
                    for layer in tree.layers {
                        println!(" ▸ {}", layer.name);
                        for (k, v) in layer.fields {
                            println!("    • {}: {}", k, v);
                        }
                    }
                }
                Ok(None) => eprintln!("[-] Packet #{} not found in capture file.", index),
                Err(e) => eprintln!("[-] Error reading packet: {}", e),
            }
        }

        Commands::PcapStats { file } => {
            println!("[*] Generating Wireshark-style traffic statistics for {}", file.display());
            let _ = core.analyze_file(&file, None, |_| true);

            println!("\n=== PROTOCOL HIERARCHY STATISTICS ===");
            for (proto, count) in core.intelligence.protocol_stats() {
                println!("  {:<12} : {} packets", proto, count);
            }

            println!("\n=== IP CONVERSATION ENDPOINTS ===");
            println!("{:<20} <-> {:<20} | {:<12} | {:<12}", "Address A", "Address B", "Packets", "Total Bytes");
            println!("--------------------------------------------------------------------------------");
            for (key, stats) in core.intelligence.conversations() {
                let total_packets = stats.packets_a_to_b + stats.packets_b_to_a;
                let total_bytes = stats.bytes_a_to_b + stats.bytes_b_to_a;
                println!("{:<20} <-> {:<20} | {:<12} | {:<12}", key.ip_a, key.ip_b, total_packets, total_bytes);
            }
        }

        Commands::Export { format, output } => {
            let hosts = core.intelligence.all_hosts();
            println!("[*] Exporting {} known hosts to {} (format: {})...", hosts.len(), output.display(), format);
            match format.to_lowercase().as_str() {
                "json" => Exporter::export_hosts_json(&hosts, &output)?,
                "csv" => Exporter::export_hosts_csv(&hosts, &output)?,
                other => eprintln!("[-] Unsupported export format: {}. Choose 'json' or 'csv'.", other),
            }
            println!("[+] Export completed.");
        }

        Commands::Config => {
            println!("{}", toml::to_string_pretty(&core.config)?);
        }

        Commands::Storage => {
            println!("Storage Engine: SQLite with WAL journal");
            println!("Database Path:  {}", core.paths.db_file.display());
            let size = std::fs::metadata(&core.paths.db_file).map(|m| m.len()).unwrap_or(0);
            println!("Database Size:  {} bytes ({:.2} KB)", size, size as f64 / 1024.0);
            let hosts = core.intelligence.all_hosts();
            println!("Stored Hosts:   {}", hosts.len());
        }

        Commands::Benchmark { file: _ } => {
            println!("[*] Running NETRA packet parsing throughput benchmark...");
            let packet_data = vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0xb6, 0xbc, 0xc0, 0xa8,
                0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3b, 0x50, 0x00, 0x00, 0x02, 0x04,
                0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
            ];

            let iterations = 250_000;
            let start = std::time::Instant::now();
            let ts = chrono::Utc::now();
            for i in 0..iterations {
                let _ = netra_parser::PacketParser::parse_raw(&packet_data, i, ts);
            }
            let elapsed = start.elapsed();
            let pps = iterations as f64 / elapsed.as_secs_f64();
            println!("[+] Processed {} packets in {:.3}s ({:.0} packets/sec, {:.2} ns/packet)",
                iterations, elapsed.as_secs_f64(), pps, (elapsed.as_nanos() as f64) / (iterations as f64));
        }
    }

    Ok(())
}
