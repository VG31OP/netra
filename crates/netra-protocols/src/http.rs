use netra_common::{NetraError, Result};

#[derive(Debug, Clone)]
pub struct HttpMetadata {
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub status_code: Option<u16>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

impl HttpMetadata {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| NetraError::Parser("Non-UTF8 HTTP payload".into()))?;

        let mut lines = text.lines();
        let first_line = lines.next().ok_or_else(|| NetraError::Parser("Empty HTTP payload".into()))?;

        let mut is_request = false;
        let mut method = None;
        let mut uri = None;
        let mut status_code = None;

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0].starts_with("HTTP/") {
            status_code = parts[1].parse::<u16>().ok();
        } else if parts.len() >= 2 {
            is_request = true;
            method = Some(parts[0].to_string());
            uri = Some(parts[1].to_string());
        } else {
            return Err(NetraError::Parser("Not a recognized HTTP header line".into()));
        }

        let mut host = None;
        let mut user_agent = None;

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k_trim = k.trim().to_ascii_lowercase();
                let v_trim = v.trim().to_string();
                if k_trim == "host" {
                    host = Some(v_trim);
                } else if k_trim == "user-agent" {
                    user_agent = Some(v_trim);
                }
            }
        }

        Ok(Self {
            is_request,
            method,
            uri,
            status_code,
            host,
            user_agent,
        })
    }
}
