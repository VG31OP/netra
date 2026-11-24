use netra_common::OsMatch;
use crate::service_probe::ServiceInfo;

pub struct OsFingerprinter;

impl OsFingerprinter {
    pub fn fingerprint(
        ttl: Option<u8>,
        window_size: Option<u16>,
        services: &[ServiceInfo],
        banners: &[String],
    ) -> OsMatch {
        // 1. Direct banner and service evidence (highest confidence)
        for s in services {
            if let Some(ref ext) = s.extra_info {
                let lower = ext.to_lowercase();
                if lower.contains("ubuntu") {
                    return OsMatch {
                        name: "Linux (Ubuntu Linux)".to_string(),
                        accuracy: 96,
                        family: "Linux".to_string(),
                        cpe: Some("cpe:/o:canonical:ubuntu_linux".to_string()),
                    };
                }
                if lower.contains("debian") {
                    return OsMatch {
                        name: "Linux (Debian)".to_string(),
                        accuracy: 95,
                        family: "Linux".to_string(),
                        cpe: Some("cpe:/o:debian:debian_linux".to_string()),
                    };
                }
                if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
                    return OsMatch {
                        name: "Linux (CentOS / Red Hat Enterprise Linux)".to_string(),
                        accuracy: 94,
                        family: "Linux".to_string(),
                        cpe: Some("cpe:/o:redhat:enterprise_linux".to_string()),
                    };
                }
            }

            if let Some(ref prod) = s.product {
                let lower = prod.to_lowercase();
                if lower.contains("microsoft iis") || lower.contains("exchange") {
                    return OsMatch {
                        name: "Microsoft Windows Server 2016 - 2022 / Windows 10/11".to_string(),
                        accuracy: 95,
                        family: "Windows".to_string(),
                        cpe: Some("cpe:/o:microsoft:windows".to_string()),
                    };
                }
            }
        }

        for b in banners {
            let lower = b.to_lowercase();
            if lower.contains("ubuntu") {
                return OsMatch {
                    name: "Linux (Ubuntu Linux)".to_string(),
                    accuracy: 95,
                    family: "Linux".to_string(),
                    cpe: Some("cpe:/o:canonical:ubuntu_linux".to_string()),
                };
            }
            if lower.contains("windows") || lower.contains("microsoft") {
                return OsMatch {
                    name: "Microsoft Windows".to_string(),
                    accuracy: 92,
                    family: "Windows".to_string(),
                    cpe: Some("cpe:/o:microsoft:windows".to_string()),
                };
            }
        }

        // 2. TCP/IP Stack characteristics (TTL and Window Size)
        if let Some(t) = ttl {
            match t {
                45..=64 => {
                    // Typical Linux, Android, or macOS
                    if let Some(win) = window_size {
                        if win == 65535 {
                            return OsMatch {
                                name: "Apple macOS / iOS (Darwin) or FreeBSD".to_string(),
                                accuracy: 82,
                                family: "macOS / BSD".to_string(),
                                cpe: Some("cpe:/o:apple:mac_os_x".to_string()),
                            };
                        }
                    }
                    return OsMatch {
                        name: "Linux 3.X - 6.X (Android / Linux kernel)".to_string(),
                        accuracy: 85,
                        family: "Linux".to_string(),
                        cpe: Some("cpe:/o:linux:linux_kernel".to_string()),
                    };
                }
                100..=128 => {
                    // Typical Windows
                    return OsMatch {
                        name: "Microsoft Windows 10 / 11 / Server 2019-2022".to_string(),
                        accuracy: 90,
                        family: "Windows".to_string(),
                        cpe: Some("cpe:/o:microsoft:windows".to_string()),
                    };
                }
                220..=255 => {
                    // Typical network equipment (Cisco, Juniper, Solaris)
                    return OsMatch {
                        name: "Cisco IOS / Network Router / Solaris".to_string(),
                        accuracy: 78,
                        family: "Embedded / Network".to_string(),
                        cpe: Some("cpe:/o:cisco:ios".to_string()),
                    };
                }
                _ => {}
            }
        }

        // 3. Fallback generic match
        OsMatch {
            name: "Generic IP Device / Standard TCP/IP Stack".to_string(),
            accuracy: 50,
            family: "General Purpose".to_string(),
            cpe: None,
        }
    }
}
