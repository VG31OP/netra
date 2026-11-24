use netra_common::{NetraError, Result};

#[derive(Debug, Clone)]
pub struct SsdpMessage {
    pub is_notify: bool,
    pub location: Option<String>,
    pub server: Option<String>,
    pub usn: Option<String>,
    pub search_target: Option<String>,
}

impl SsdpMessage {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| NetraError::Parser("Non-UTF8 SSDP payload".into()))?;

        let mut lines = text.lines();
        let first_line = lines.next().ok_or_else(|| NetraError::Parser("Empty SSDP payload".into()))?;

        let is_notify = first_line.starts_with("NOTIFY");
        let mut location = None;
        let mut server = None;
        let mut usn = None;
        let mut search_target = None;

        for line in lines {
            if line.is_empty() { break; }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().to_string();
                match key.as_str() {
                    "location" => location = Some(val),
                    "server" => server = Some(val),
                    "usn" => usn = Some(val),
                    "st" | "nt" => search_target = Some(val),
                    _ => {}
                }
            }
        }

        Ok(Self {
            is_notify,
            location,
            server,
            usn,
            search_target,
        })
    }
}
