use payload_normalizer::NormalizedRequest;
use request_inspector::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u8,
    pub level: String,
    pub reasons: Vec<String>,
    pub flags: Vec<String>,
}

fn severity_weight(severity: &str) -> u32 {
    match severity {
        "critical" => 55,
        "high" => 32,
        "medium" => 15,
        "low" => 6,
        _ => 4,
    }
}

pub fn score_request_risk(
    request: &NormalizedRequest,
    findings: &[Finding],
    sensitive_route: bool,
) -> RiskScore {
    let mut score = (request.anomalies.len() as u32) * 8;
    let mut reasons = request.anomalies.clone();
    let mut flags = request.anomalies.clone();

    if sensitive_route {
        score += 15;
        reasons.push("sensitive-route".to_string());
        flags.push("sensitive-route".to_string());
    }

    for finding in findings {
        score += severity_weight(&finding.severity);
        reasons.push(finding.code.clone());
        flags.push(finding.category.clone());
    }

    if request.method == "POST" && request.body_kind == "binary" {
        score += 5;
        reasons.push("binary-body".to_string());
        flags.push("upload".to_string());
    }

    let bounded = score.min(100) as u8;
    let level = if bounded >= 85 {
        "critical"
    } else if bounded >= 60 {
        "high"
    } else if bounded >= 30 {
        "medium"
    } else {
        "low"
    };

    RiskScore {
        score: bounded,
        level: level.to_string(),
        reasons,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use payload_normalizer::{HeaderPair, NormalizedRequest};
    use serde_json::json;

    #[test]
    fn raises_scores_for_sensitive_routes() {
        let request = NormalizedRequest {
            method: "POST".to_string(),
            path: "/admin/policy".to_string(),
            route_key: "POST /admin/policy".to_string(),
            source_ip: "127.0.0.1".to_string(),
            content_type: Some("application/json".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            headers: vec![HeaderPair {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            query: json!({}),
            raw_body: Some("{\"ok\":true}".to_string()),
            body_kind: "json".to_string(),
            anomalies: vec!["percent-decoded".to_string()],
            received_at: "2026-01-01T00:00:00.000Z".to_string(),
        };

        let findings = vec![Finding {
            code: "automation-signal".to_string(),
            category: "automation".to_string(),
            severity: "medium".to_string(),
            detail: "Automated traffic".to_string(),
            matched_value: None,
            confidence: 0.7,
        }];

        let risk = score_request_risk(&request, &findings, true);
        assert!(risk.score >= 30);
    }
}

