use netra_capture::CaptureManager;
use netra_common::NetworkProtocol;
use netra_core::NetraCore;

#[test]
fn test_synthetic_pcap_generation_and_streaming_analysis() {
    let temp_dir = std::env::temp_dir();
    let pcap_path = temp_dir.join("netra_test_synthetic.pcap");

    // Packet 1: ARP Request
    let arp_pkt = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dst MAC: Broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
        0x08, 0x06,                         // EtherType: ARP
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // ARP Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 192, 168, 1, 50, // Sender MAC & IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,  // Target MAC & IP
    ];

    // Packet 2: IPv4 + UDP + DNS Query
    let dns_pkt = vec![
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, // Dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
        0x08, 0x00,                         // EtherType: IPv4
        0x45, 0x00, 0x00, 0x37, 0x1a, 0x2b, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, // IPv4 header
        192, 168, 1, 50, 8, 8, 8, 8,        // 192.168.1.50 -> 8.8.8.8
        0xc0, 0x01, 0x00, 0x35, 0x00, 0x23, 0x00, 0x00, // UDP: 49153 -> 53
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DNS header
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // google.com
        0x00, 0x01, 0x00, 0x01,             // Type A, Class IN
    ];

    let packets = vec![arp_pkt, dns_pkt];
    CaptureManager::export_to_pcap(&packets, &pcap_path).expect("Failed to export test PCAP");
    assert!(pcap_path.exists());

    let core = NetraCore::initialize().expect("Core initialization failed");
    let mut observed_protocols = Vec::new();

    let count = core.analyze_file(&pcap_path, None, |pkt| {
        observed_protocols.push(pkt.protocol);
        true
    }).expect("PCAP analysis failed");

    assert_eq!(count, 2);
    assert_eq!(observed_protocols.len(), 2);
    assert_eq!(observed_protocols[0], NetworkProtocol::Arp);
    assert_eq!(observed_protocols[1], NetworkProtocol::Dns);

    // Test with filter
    let mut filtered_count = 0;
    let _ = core.analyze_file(&pcap_path, Some("dns"), |pkt| {
        filtered_count += 1;
        assert_eq!(pkt.protocol, NetworkProtocol::Dns);
        true
    });
    assert_eq!(filtered_count, 1);

    let _ = std::fs::remove_file(pcap_path);
}
