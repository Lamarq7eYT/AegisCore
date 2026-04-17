use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInput {
    pub method: String,
    pub path: String,
    pub route_key: String,
    pub source_ip: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<HeaderPair>,
    pub query: Value,
    pub raw_body: Option<String>,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub method: String,
    pub path: String,
    pub route_key: String,
    pub source_ip: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<HeaderPair>,
    pub query: Value,
    pub raw_body: Option<String>,
    pub body_kind: String,
    pub anomalies: Vec<String>,
    pub received_at: String,
}

fn decode_repeatedly(path: &str, anomalies: &mut Vec<String>) -> String {
    let mut current = path.to_string();

    for _ in 0..2 {
        let decoded = percent_decode_str(&current).decode_utf8_lossy().to_string();
        if decoded != current {
            anomalies.push("percent-decoded".to_string());
            current = decoded;
        }
    }

    current
}

fn normalize_query_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let normalized = map
                .into_iter()
                .map(|(key, value)| (key, normalize_query_value(value)))
                .collect::<Map<String, Value>>();
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_query_value).collect()),
        Value::String(value) => Value::String(value.trim().to_string()),
        other => other,
    }
}

fn infer_body_kind(content_type: &Option<String>, raw_body: &Option<String>) -> String {
    if raw_body.is_none() {
        return "empty".to_string();
    }

    match content_type.as_deref() {
        Some(value) if value.contains("application/json") => "json".to_string(),
        Some(value) if value.contains("application/x-www-form-urlencoded") => "form".to_string(),
        Some(value) if value.contains("multipart/form-data") => "binary".to_string(),
        Some(value) if value.starts_with("text/") => "text".to_string(),
        Some(_) => "unknown".to_string(),
        None => "text".to_string(),
    }
}

pub fn normalize_request(input: RequestInput) -> NormalizedRequest {
    let mut anomalies = Vec::new();
    let mut normalized_path = decode_repeatedly(&input.path, &mut anomalies);
    let body_kind = infer_body_kind(&input.content_type, &input.raw_body);
    let content_type = input
        .content_type
        .map(|value| value.trim().to_lowercase());
    let raw_body = input
        .raw_body
        .map(|value| value.chars().take(32768).collect());

    if normalized_path.contains('\\') {
        anomalies.push("backslash-separator".to_string());
        normalized_path = normalized_path.replace('\\', "/");
    }

    if normalized_path.contains('\0') {
        anomalies.push("null-byte".to_string());
        normalized_path = normalized_path.replace('\0', "");
    }

    if normalized_path.contains("..") {
        anomalies.push("path-traversal-sequence".to_string());
    }

    if normalized_path.chars().any(|char| char.is_control() && char != '\n' && char != '\r') {
        anomalies.push("control-character".to_string());
        normalized_path = normalized_path
            .chars()
            .filter(|char| !char.is_control() || *char == '\n' || *char == '\r')
            .collect();
    }

    while normalized_path.contains("//") {
        normalized_path = normalized_path.replace("//", "/");
    }

    if !normalized_path.starts_with('/') {
        normalized_path = format!("/{}", normalized_path);
    }

    let headers = input
        .headers
        .into_iter()
        .map(|header| HeaderPair {
            name: header.name.trim().to_lowercase(),
            value: header.value.trim().chars().take(8192).collect(),
        })
        .collect::<Vec<_>>();

    let query = normalize_query_value(input.query);

    NormalizedRequest {
        method: input.method.trim().to_uppercase(),
        path: normalized_path,
        route_key: input.route_key.trim().to_string(),
        source_ip: input.source_ip.trim().to_string(),
        content_type,
        user_agent: input.user_agent.map(|value| value.trim().to_string()),
        headers,
        query,
        raw_body,
        body_kind,
        anomalies,
        received_at: input.received_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_encoded_traversal_sequences() {
        let request = RequestInput {
            method: "get".to_string(),
            path: "/foo/%2e%2e/bar".to_string(),
            route_key: "GET /foo".to_string(),
            source_ip: "127.0.0.1".to_string(),
            content_type: Some("application/json".to_string()),
            user_agent: Some("curl/8".to_string()),
            headers: vec![HeaderPair {
                name: "X-Test".to_string(),
                value: "  value  ".to_string(),
            }],
            query: json!({"search": " test "}),
            raw_body: Some("{\"hello\":true}".to_string()),
            received_at: "2026-01-01T00:00:00.000Z".to_string(),
        };

        let normalized = normalize_request(request);
        assert!(normalized.path.contains("../"));
        assert!(normalized.anomalies.contains(&"percent-decoded".to_string()));
    }
}
