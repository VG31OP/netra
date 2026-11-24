#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    pub proto_version: String,
    pub software_version: String,
    pub comments: Option<String>,
}

impl SshBanner {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?.trim();

        if !first_line.starts_with("SSH-") {
            return None;
        }

        let parts: Vec<&str> = first_line.splitn(3, '-').collect();
        if parts.len() < 3 {
            return None;
        }

        let proto_version = parts[1].to_string();
        let sw_and_comments = parts[2];

        let (sw, comm) = if let Some((s, c)) = sw_and_comments.split_once(' ') {
            (s.to_string(), Some(c.to_string()))
        } else {
            (sw_and_comments.to_string(), None)
        };

        Some(Self {
            proto_version,
            software_version: sw,
            comments: comm,
        })
    }
}
