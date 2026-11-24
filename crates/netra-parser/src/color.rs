use netra_common::{NetworkProtocol, PacketMetadata};

pub struct ColorEngine;

impl ColorEngine {
    /// Returns (background_hex, foreground_hex) matching Wireshark standard coloring rules
    pub fn get_packet_colors(pkt: &PacketMetadata) -> (&'static str, &'static str) {
        // Bad TCP check: RST or Zero Window
        if let Some(flags) = &pkt.flags {
            if flags.rst {
                return ("#3b1212", "#ff7b72"); // Dark Red bg, Light Red fg
            }
        }

        match pkt.protocol {
            NetworkProtocol::Http => ("#132e1b", "#7ee787"),   // Dark Green bg, Light Green fg
            NetworkProtocol::Tls => ("#24153b", "#d2a8ff"),    // Deep Purple bg, Light Purple fg
            NetworkProtocol::Dns | NetworkProtocol::Mdns => ("#0f283d", "#79c0ff"), // Navy Blue bg, Cyan fg
            NetworkProtocol::Arp => ("#383216", "#e3b341"),    // Olive/Brown bg, Yellow fg
            NetworkProtocol::Icmp | NetworkProtocol::Icmpv6 => ("#36162a", "#f778ba"), // Wine bg, Pink fg
            NetworkProtocol::Smb | NetworkProtocol::Ssh | NetworkProtocol::Ntp => ("#16283b", "#a5d6ff"),
            NetworkProtocol::Tcp => ("#161b22", "#f0f6fc"),
            NetworkProtocol::Udp => ("#161b22", "#f0f6fc"),
            _ => ("#161b22", "#c9d1d9"),
        }
    }
}
