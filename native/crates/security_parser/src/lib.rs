use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityArtifact {
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub origin: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSecurityArtifact {
    pub normalized_filename: String,
    pub extension: String,
    pub mime_type: String,
    pub origin_host: Option<String>,
    pub flags: Vec<String>,
}

pub fn parse_security_artifact(input: SecurityArtifact) -> ParsedSecurityArtifact {
    let filename = input.filename.unwrap_or_else(|| "artifact.bin".to_string());
    let normalized_filename = filename
        .replace(['/', '\\'], "-")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_");

    let extension = normalized_filename
        .rfind('.')
        .map(|index| normalized_filename[index..].to_lowercase())
        .unwrap_or_default();

    let mut flags = Vec::new();
    if normalized_filename.split('.').count() > 3 {
        flags.push("double-extension".to_string());
    }
    if normalized_filename.contains("..") {
        flags.push("path-traversal-sequence".to_string());
    }

    let origin_host = input
        .origin
        .as_deref()
        .and_then(|origin| Url::parse(origin).ok())
        .and_then(|url| url.host_str().map(|host| host.to_string()));

    if let Some(host) = &origin_host {
        if host == "localhost" || host.starts_with("127.") || host.starts_with("169.254.") {
            flags.push("internal-origin".to_string());
        }
    }

    ParsedSecurityArtifact {
        normalized_filename,
        extension,
        mime_type: input
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        origin_host,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_internal_origins() {
        let artifact = SecurityArtifact {
            filename: Some("../report.pdf".to_string()),
            mime_type: Some("application/pdf".to_string()),
            origin: Some("http://localhost:3000/upload".to_string()),
            content_length: Some(42),
        };

        let parsed = parse_security_artifact(artifact);
        assert!(parsed.flags.contains(&"internal-origin".to_string()));
    }
}

