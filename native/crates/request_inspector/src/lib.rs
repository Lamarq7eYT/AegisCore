use payload_normalizer::NormalizedRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub category: String,
    pub severity: String,
    pub detail: String,
    pub matched_value: Option<String>,
    pub confidence: f64,
}

fn add_finding(
    findings: &mut Vec<Finding>,
    code: &str,
    category: &str,
    severity: &str,
    detail: &str,
    matched_value: Option<String>,
    confidence: f64,
) {
    findings.push(Finding {
        code: code.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        detail: detail.to_string(),
        matched_value,
        confidence,
    });
}

pub fn inspect_request(request: &NormalizedRequest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let haystack = format!(
        "{} {} {}",
        request.path,
        request.query,
        request.raw_body.clone().unwrap_or_default()
    )
    .to_lowercase();

    for anomaly in &request.anomalies {
        add_finding(
            &mut findings,
            anomaly,
            "syntax",
            "medium",
            "Normalizer observed an anomalous request shape.",
            Some(anomaly.clone()),
            0.7,
        );
    }

    if haystack.contains("union select")
        || haystack.contains("or 1=1")
        || haystack.contains("drop table")
    {
        add_finding(
            &mut findings,
            "sqli-pattern",
            "payload",
            "high",
            "Potential SQL injection payload pattern detected.",
            None,
            0.85,
        );
    }

    if haystack.contains("<script") || haystack.contains("javascript:") || haystack.contains("onerror=")
    {
        add_finding(
            &mut findings,
            "xss-pattern",
            "payload",
            "high",
            "Potential cross-site scripting payload pattern detected.",
            None,
            0.9,
        );
    }

    if haystack.contains("../") || haystack.contains("..\\") {
        add_finding(
            &mut findings,
            "traversal-pattern",
            "payload",
            "high",
            "Potential path traversal payload detected.",
            None,
            0.92,
        );
    }

    if haystack.contains("169.254.169.254")
        || haystack.contains("localhost")
        || haystack.contains("file://")
        || haystack.contains("gopher://")
    {
        add_finding(
            &mut findings,
            "ssrf-pattern",
            "network",
            "high",
            "Potential SSRF target pattern detected.",
            None,
            0.8,
        );
    }

    if haystack.contains("|bash") || haystack.contains(";curl") || haystack.contains("powershell") {
        add_finding(
            &mut findings,
            "command-injection-pattern",
            "payload",
            "critical",
            "Potential command injection pattern detected.",
            None,
            0.83,
        );
    }

    let user_agent = request.user_agent.clone().unwrap_or_default().to_lowercase();
    if user_agent.is_empty()
        || user_agent.contains("curl/")
        || user_agent.contains("python-requests")
        || user_agent.contains("headless")
    {
        add_finding(
            &mut findings,
            "automation-signal",
            "automation",
            "medium",
            "Request resembles automated traffic or provides no browser fingerprint.",
            request.user_agent.clone(),
            0.65,
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use payload_normalizer::{HeaderPair, NormalizedRequest};
    use serde_json::json;

    #[test]
    fn flags_suspicious_payloads() {
        let request = NormalizedRequest {
            method: "POST".to_string(),
            path: "/admin/report".to_string(),
            route_key: "POST /admin/report".to_string(),
            source_ip: "127.0.0.1".to_string(),
            content_type: Some("application/json".to_string()),
            user_agent: Some("curl/8".to_string()),
            headers: vec![HeaderPair {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            query: json!({}),
            raw_body: Some("<script>alert(1)</script>".to_string()),
            body_kind: "json".to_string(),
            anomalies: vec![],
            received_at: "2026-01-01T00:00:00.000Z".to_string(),
        };

        let findings = inspect_request(&request);
        assert!(findings.iter().any(|finding| finding.code == "xss-pattern"));
    }
}

