use std::net::IpAddr;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use netra_core::NetraCore;
use netra_discovery::SubnetScanner;
use netra_export::Exporter;
use netra_scanner::PortScanner;

#[derive(Parser)]
#[command(name = "netra")]
#[command(about = "NETRA - Portable Network Intelligence & Analysis Engine", long_about = None)]
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

    /// Discover responsive devices across a local subnet
    Discover {
        #[arg(short, long, default_value = "192.168.1.0/24")]
        subnet: String,
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
    },

    /// Scan target host for open ports and services
    Scan {
        #[arg(short, long)]
        target: IpAddr,
        #[arg(short, long, default_value = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080,8443")]
        ports: String,
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
    },

    /// Perform offline packet analysis on PCAP or PCAPNG captures
    Analyze {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
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
            println!("Interface enumeration requires capture adapter initialization.");
            println!("Default loopback and host socket communication are ready.");
        }

        Commands::Discover { subnet, concurrency } => {
            println!("[*] Discovering hosts on subnet: {}", subnet);
            let targets = match SubnetScanner::parse_cidr(&subnet) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return Ok(());
                }
            };
            println!("[*] Probing {} potential addresses with concurrency {}...", targets.len(), concurrency);

            let scanner = SubnetScanner::new(800, concurrency);
            let core_intel = core.intelligence.clone();

            scanner.discover_subnet(targets, move |host| {
                println!("[+] Found active host: {} (observed at {})", host.ip, host.last_seen);
                let _ = core_intel.record_service(host.ip, netra_common::ServiceRecord {
                    port: 0,
                    protocol: "ip".to_string(),
                    state: netra_common::PortState::Open,
                    service_name: Some("host".to_string()),
                    banner: None,
                    last_observed: host.last_seen,
                });
            }).await;

            println!("[+] Discovery sweep completed.");
        }

        Commands::Scan { target, ports, concurrency } => {
            let port_list: Vec<u16> = ports
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect();

            println!("[*] Scanning {} ({} ports) with concurrency {}...", target, port_list.len(), concurrency);
            println!("PORT     STATE    SERVICE    BANNER");
            println!("---------------------------------------------");

            let scanner = PortScanner::new(core.config.scanner.default_timeout_ms, concurrency);
            let core_intel = core.intelligence.clone();

            scanner.scan_ports(target, port_list, move |rec| {
                if rec.state == netra_common::PortState::Open {
                    let svc = rec.service_name.as_deref().unwrap_or("unknown");
                    let banner = rec.banner.as_deref().unwrap_or("");
                    println!("{:<8} {:<8} {:<10} {}", rec.port, rec.state, svc, banner);
                    let _ = core_intel.record_service(target, rec);
                }
            }).await;

            println!("---------------------------------------------");
            println!("[+] Scan completed.");
        }

        Commands::Analyze { file, filter, limit } => {
            println!("[*] Analyzing capture file: {}", file.display());
            if let Some(ref f) = filter {
                println!("[*] Applying filter expression: {}", f);
            }
            println!("--------------------------------------------------------------------------------");
            println!("{:<6} {:<12} {:<21} {:<21} {:<6} {}", "INDEX", "PROTOCOL", "SOURCE", "DESTINATION", "LEN", "SUMMARY");
            println!("--------------------------------------------------------------------------------");

            let mut count = 0;
            let result = core.analyze_file(&file, filter.as_deref(), |pkt| {
                count += 1;
                let src = pkt.source_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string());
                let dst = pkt.destination_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string());
                println!("{:<6} {:<12} {:<21} {:<21} {:<6} {}", pkt.index, pkt.protocol, src, dst, pkt.length, pkt.summary);
                count < limit
            });

            match result {
                Ok(total) => {
                    println!("--------------------------------------------------------------------------------");
                    println!("[+] Parsed {} packets (displayed {}).", total, count.min(limit));
                }
                Err(e) => {
                    eprintln!("[-] Error analyzing file: {}", e);
                }
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

        Commands::Benchmark { file } => {
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
