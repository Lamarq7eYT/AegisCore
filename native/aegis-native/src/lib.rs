use napi::bindgen_prelude::Error;
use napi_derive::napi;
use payload_normalizer::{normalize_request, HeaderPair, NormalizedRequest, RequestInput};
use request_inspector::{inspect_request, Finding};
use risk_scoring_core::score_request_risk;
use security_parser::{parse_security_artifact, SecurityArtifact};
use serde_json::Value;

#[napi(object)]
pub struct NativeRequestInput {
    pub method: String,
    pub path: String,
    pub route_key: String,
    pub source_ip: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers_json: String,
    pub query_json: String,
    pub raw_body: Option<String>,
    pub received_at: String,
}

#[napi(object)]
pub struct NativeNormalizedRequest {
    pub method: String,
    pub path: String,
    pub route_key: String,
    pub source_ip: String,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub headers_json: String,
    pub query_json: String,
    pub raw_body: Option<String>,
    pub body_kind: String,
    pub anomalies_json: String,
    pub received_at: String,
}

#[napi(object)]
pub struct NativeFinding {
    pub code: String,
    pub category: String,
    pub severity: String,
    pub detail: String,
    pub matched_value: Option<String>,
    pub confidence: f64,
}

#[napi(object)]
pub struct NativeRiskScore {
    pub score: u32,
    pub level: String,
    pub reasons_json: String,
    pub flags_json: String,
}

#[napi(object)]
pub struct NativeSecurityArtifact {
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub origin: Option<String>,
    pub content_length: Option<u32>,
}

#[napi(object)]
pub struct NativeParsedSecurityArtifact {
    pub normalized_filename: String,
    pub extension: String,
    pub mime_type: String,
    pub origin_host: Option<String>,
    pub flags: Vec<String>,
}

fn parse_headers(headers_json: &str) -> Result<Vec<HeaderPair>, Error> {
    serde_json::from_str::<Vec<HeaderPair>>(headers_json)
        .map_err(|error| Error::from_reason(format!("invalid headers_json: {error}")))
}

fn parse_query(query_json: &str) -> Result<Value, Error> {
    serde_json::from_str::<Value>(query_json)
        .map_err(|error| Error::from_reason(format!("invalid query_json: {error}")))
}

fn to_request_input(input: NativeRequestInput) -> Result<RequestInput, Error> {
    Ok(RequestInput {
        method: input.method,
        path: input.path,
        route_key: input.route_key,
        source_ip: input.source_ip,
        content_type: input.content_type,
        user_agent: input.user_agent,
        headers: parse_headers(&input.headers_json)?,
        query: parse_query(&input.query_json)?,
        raw_body: input.raw_body,
        received_at: input.received_at,
    })
}

fn to_native_normalized(request: NormalizedRequest) -> Result<NativeNormalizedRequest, Error> {
    Ok(NativeNormalizedRequest {
        method: request.method,
        path: request.path,
        route_key: request.route_key,
        source_ip: request.source_ip,
        content_type: request.content_type,
        user_agent: request.user_agent,
        headers_json: serde_json::to_string(&request.headers)
            .map_err(|error| Error::from_reason(format!("serialize headers: {error}")))?,
        query_json: serde_json::to_string(&request.query)
            .map_err(|error| Error::from_reason(format!("serialize query: {error}")))?,
        raw_body: request.raw_body,
        body_kind: request.body_kind,
        anomalies_json: serde_json::to_string(&request.anomalies)
            .map_err(|error| Error::from_reason(format!("serialize anomalies: {error}")))?,
        received_at: request.received_at,
    })
}

fn from_native_normalized(input: NativeNormalizedRequest) -> Result<NormalizedRequest, Error> {
    Ok(NormalizedRequest {
        method: input.method,
        path: input.path,
        route_key: input.route_key,
        source_ip: input.source_ip,
        content_type: input.content_type,
        user_agent: input.user_agent,
        headers: parse_headers(&input.headers_json)?,
        query: parse_query(&input.query_json)?,
        raw_body: input.raw_body,
        body_kind: input.body_kind,
        anomalies: serde_json::from_str(&input.anomalies_json)
            .map_err(|error| Error::from_reason(format!("invalid anomalies_json: {error}")))?,
        received_at: input.received_at,
    })
}

fn finding_to_native(finding: Finding) -> NativeFinding {
    NativeFinding {
        code: finding.code,
        category: finding.category,
        severity: finding.severity,
        detail: finding.detail,
        matched_value: finding.matched_value,
        confidence: finding.confidence,
    }
}

#[napi(js_name = "normalizeRequest")]
pub fn normalize_request_js(input: NativeRequestInput) -> napi::Result<NativeNormalizedRequest> {
    let normalized = normalize_request(to_request_input(input)?);
    to_native_normalized(normalized)
}

#[napi(js_name = "inspectRequest")]
pub fn inspect_request_js(input: NativeNormalizedRequest) -> napi::Result<Vec<NativeFinding>> {
    let request = from_native_normalized(input)?;
    Ok(inspect_request(&request)
        .into_iter()
        .map(finding_to_native)
        .collect())
}

#[napi(js_name = "scoreRequestRisk")]
pub fn score_request_risk_js(
    input: NativeNormalizedRequest,
    findings_json: String,
    sensitive_route: bool,
) -> napi::Result<NativeRiskScore> {
    let request = from_native_normalized(input)?;
    let findings = serde_json::from_str::<Vec<Finding>>(&findings_json)
        .map_err(|error| Error::from_reason(format!("invalid findings_json: {error}")))?;
    let risk = score_request_risk(&request, &findings, sensitive_route);

    Ok(NativeRiskScore {
        score: risk.score as u32,
        level: risk.level,
        reasons_json: serde_json::to_string(&risk.reasons)
            .map_err(|error| Error::from_reason(format!("serialize reasons: {error}")))?,
        flags_json: serde_json::to_string(&risk.flags)
            .map_err(|error| Error::from_reason(format!("serialize flags: {error}")))?,
    })
}

#[napi(js_name = "parseSecurityArtifact")]
pub fn parse_security_artifact_js(
    input: NativeSecurityArtifact,
) -> napi::Result<NativeParsedSecurityArtifact> {
    let parsed = parse_security_artifact(SecurityArtifact {
        filename: input.filename,
        mime_type: input.mime_type,
        origin: input.origin,
        content_length: input.content_length.map(|value| value as u64),
    });

    Ok(NativeParsedSecurityArtifact {
        normalized_filename: parsed.normalized_filename,
        extension: parsed.extension,
        mime_type: parsed.mime_type,
        origin_host: parsed.origin_host,
        flags: parsed.flags,
    })
}
