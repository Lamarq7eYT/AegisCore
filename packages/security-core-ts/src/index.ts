import { createRequire } from "node:module";
import {
  inspectionFindingSchema,
  normalizedRequestSchema,
  parsedSecurityArtifactSchema,
  riskScoreSchema,
  securityArtifactSchema,
  securityContextSchema,
  type InspectionFinding,
  type NormalizedRequest,
  type ParsedSecurityArtifact,
  type RiskScore,
  type SecurityArtifact,
  type SecurityContext
} from "@aegis/contracts";

const require = createRequire(import.meta.url);

type NativeRequestInput = {
  method: string;
  path: string;
  routeKey: string;
  sourceIp: string;
  contentType?: string;
  userAgent?: string;
  headersJson: string;
  queryJson: string;
  rawBody?: string;
  receivedAt: string;
};

type NativeNormalizedRequest = NativeRequestInput & {
  bodyKind: NormalizedRequest["bodyKind"];
  anomaliesJson: string;
};

type NativeRiskScore = {
  score: number;
  level: RiskScore["level"];
  reasonsJson: string;
  flagsJson: string;
};

type NativeBindings = {
  normalizeRequest(input: NativeRequestInput): NativeNormalizedRequest;
  inspectRequest(input: NativeNormalizedRequest): InspectionFinding[];
  scoreRequestRisk(
    input: NativeNormalizedRequest,
    findingsJson: string,
    sensitiveRoute: boolean
  ): NativeRiskScore;
  parseSecurityArtifact(input: SecurityArtifact): ParsedSecurityArtifact;
};

let bindingsCache: NativeBindings | null = null;

function loadBindings(allowFallback: boolean): NativeBindings | null {
  if (bindingsCache) {
    return bindingsCache;
  }

  try {
    bindingsCache = require("@aegis/native") as NativeBindings;
    return bindingsCache;
  } catch (error) {
    if (!allowFallback) {
      throw error;
    }

    return null;
  }
}

function parseNativeRequest(input: NativeNormalizedRequest): NormalizedRequest {
  return normalizedRequestSchema.parse({
    method: input.method,
    path: input.path,
    routeKey: input.routeKey,
    sourceIp: input.sourceIp,
    contentType: input.contentType ?? null,
    userAgent: input.userAgent ?? null,
    headers: JSON.parse(input.headersJson),
    query: JSON.parse(input.queryJson),
    rawBody: input.rawBody ?? null,
    bodyKind: input.bodyKind,
    anomalies: JSON.parse(input.anomaliesJson),
    receivedAt: input.receivedAt
  });
}

function tsFallbackNormalize(input: NativeRequestInput): NormalizedRequest {
  const path = input.path.replace(/\/{2,}/g, "/");
  const anomalies: string[] = [];
  if (/%00|\\x00|\u0000/.test(input.path)) anomalies.push("null-byte");
  if (path.includes("..")) anomalies.push("path-traversal-sequence");
  const contentType = input.contentType ?? null;
  const bodyKind: NormalizedRequest["bodyKind"] =
    !input.rawBody
      ? "empty"
      : contentType?.includes("application/json")
        ? "json"
        : contentType?.includes("multipart/form-data")
          ? "binary"
          : contentType?.includes("application/x-www-form-urlencoded")
            ? "form"
            : "text";

  return normalizedRequestSchema.parse({
    method: input.method.toUpperCase(),
    path,
    routeKey: input.routeKey,
    sourceIp: input.sourceIp,
    contentType,
    userAgent: input.userAgent ?? null,
    headers: JSON.parse(input.headersJson),
    query: JSON.parse(input.queryJson),
    rawBody: input.rawBody ?? null,
    bodyKind,
    anomalies,
    receivedAt: input.receivedAt
  });
}

function tsFallbackInspect(request: NormalizedRequest): InspectionFinding[] {
  const haystack = `${request.path} ${JSON.stringify(request.query)} ${request.rawBody ?? ""}`.toLowerCase();
  const findings: InspectionFinding[] = [];

  const addFinding = (finding: InspectionFinding) => {
    findings.push(inspectionFindingSchema.parse(finding));
  };

  if (haystack.includes("<script") || haystack.includes("javascript:")) {
    addFinding({
      code: "xss-pattern",
      category: "payload",
      severity: "high",
      detail: "Potential XSS payload pattern detected.",
      confidence: 0.85
    });
  }

  if (haystack.includes("../")) {
    addFinding({
      code: "traversal-pattern",
      category: "payload",
      severity: "high",
      detail: "Potential traversal sequence detected.",
      confidence: 0.9
    });
  }

  if (haystack.includes("union select") || haystack.includes("or 1=1")) {
    addFinding({
      code: "sqli-pattern",
      category: "payload",
      severity: "high",
      detail: "Potential SQL injection pattern detected.",
      confidence: 0.8
    });
  }

  if ((request.userAgent ?? "").trim() === "") {
    addFinding({
      code: "missing-user-agent",
      category: "automation",
      severity: "medium",
      detail: "Request is missing a user agent string.",
      confidence: 0.6
    });
  }

  return findings;
}

function tsFallbackScore(
  request: NormalizedRequest,
  findings: InspectionFinding[],
  sensitiveRoute: boolean
): RiskScore {
  let score = request.anomalies.length * 8 + (sensitiveRoute ? 12 : 0);
  const reasons = [...request.anomalies];
  const flags = [...request.anomalies];

  for (const finding of findings) {
    if (finding.severity === "critical") score += 45;
    if (finding.severity === "high") score += 30;
    if (finding.severity === "medium") score += 15;
    if (finding.severity === "low") score += 5;
    reasons.push(finding.code);
    flags.push(finding.category);
  }

  const bounded = Math.min(100, score);
  const level =
    bounded >= 85 ? "critical" : bounded >= 60 ? "high" : bounded >= 30 ? "medium" : "low";

  return riskScoreSchema.parse({
    score: bounded,
    level,
    reasons,
    flags
  });
}

function toNativeInput(input: {
  method: string;
  path: string;
  routeKey: string;
  sourceIp: string;
  contentType?: string | null;
  userAgent?: string | null;
  headers: Array<{ name: string; value: string }>;
  query: Record<string, string | string[]>;
  rawBody?: string | null;
  receivedAt?: string;
}): NativeRequestInput {
  return {
    method: input.method,
    path: input.path,
    routeKey: input.routeKey,
    sourceIp: input.sourceIp,
    contentType: input.contentType ?? undefined,
    userAgent: input.userAgent ?? undefined,
    headersJson: JSON.stringify(input.headers),
    queryJson: JSON.stringify(input.query),
    rawBody: input.rawBody ?? undefined,
    receivedAt: input.receivedAt ?? new Date().toISOString()
  };
}

export function normalizeRequest(
  input: Parameters<typeof toNativeInput>[0],
  options: { allowFallback?: boolean } = {}
): NormalizedRequest {
  const nativeInput = toNativeInput(input);
  const bindings = loadBindings(options.allowFallback ?? false);
  if (!bindings) {
    return tsFallbackNormalize(nativeInput);
  }

  return parseNativeRequest(bindings.normalizeRequest(nativeInput));
}

export function inspectRequest(
  request: NormalizedRequest,
  options: { allowFallback?: boolean } = {}
): InspectionFinding[] {
  const bindings = loadBindings(options.allowFallback ?? false);
  if (!bindings) {
    return tsFallbackInspect(request);
  }

  return bindings.inspectRequest({
    method: request.method,
    path: request.path,
    routeKey: request.routeKey,
    sourceIp: request.sourceIp,
    contentType: request.contentType ?? undefined,
    userAgent: request.userAgent ?? undefined,
    headersJson: JSON.stringify(request.headers),
    queryJson: JSON.stringify(request.query),
    rawBody: request.rawBody ?? undefined,
    bodyKind: request.bodyKind,
    anomaliesJson: JSON.stringify(request.anomalies),
    receivedAt: request.receivedAt
  }).map((finding) => inspectionFindingSchema.parse(finding));
}

export function scoreRequestRisk(
  request: NormalizedRequest,
  findings: InspectionFinding[],
  options: { sensitiveRoute?: boolean; allowFallback?: boolean } = {}
): RiskScore {
  const sensitiveRoute = options.sensitiveRoute ?? false;
  const bindings = loadBindings(options.allowFallback ?? false);
  if (!bindings) {
    return tsFallbackScore(request, findings, sensitiveRoute);
  }

  const result = bindings.scoreRequestRisk(
    {
      method: request.method,
      path: request.path,
      routeKey: request.routeKey,
      sourceIp: request.sourceIp,
      contentType: request.contentType ?? undefined,
      userAgent: request.userAgent ?? undefined,
      headersJson: JSON.stringify(request.headers),
      queryJson: JSON.stringify(request.query),
      rawBody: request.rawBody ?? undefined,
      bodyKind: request.bodyKind,
      anomaliesJson: JSON.stringify(request.anomalies),
      receivedAt: request.receivedAt
    },
    JSON.stringify(findings),
    sensitiveRoute
  );

  return riskScoreSchema.parse({
    score: result.score,
    level: result.level,
    reasons: JSON.parse(result.reasonsJson),
    flags: JSON.parse(result.flagsJson)
  });
}

export function parseSecurityArtifact(
  input: SecurityArtifact,
  options: { allowFallback?: boolean } = {}
): ParsedSecurityArtifact {
  const artifact = securityArtifactSchema.parse(input);
  const bindings = loadBindings(options.allowFallback ?? false);
  if (!bindings) {
    const filename = artifact.filename ?? "artifact.bin";
    const normalizedFilename = filename.replace(/[/\\]+/g, "-").replace(/\s+/g, "_");
    const extension = normalizedFilename.includes(".")
      ? normalizedFilename.slice(normalizedFilename.lastIndexOf(".")).toLowerCase()
      : "";
    let originHost: string | null = null;
    if (artifact.origin) {
      try {
        originHost = new URL(artifact.origin).host;
      } catch {
        originHost = null;
      }
    }

    return parsedSecurityArtifactSchema.parse({
      normalizedFilename,
      extension,
      mimeType: artifact.mimeType ?? "application/octet-stream",
      originHost,
      flags: normalizedFilename.includes("..") ? ["path-traversal-sequence"] : []
    });
  }

  return parsedSecurityArtifactSchema.parse(bindings.parseSecurityArtifact(artifact));
}

export function buildSecurityContext(
  input: Parameters<typeof normalizeRequest>[0],
  options: { sensitiveRoute?: boolean; allowFallback?: boolean } = {}
): SecurityContext {
  const normalizedRequest = normalizeRequest(input, options);
  const findings = inspectRequest(normalizedRequest, options);
  const riskScore = scoreRequestRisk(normalizedRequest, findings, options);

  return securityContextSchema.parse({
    normalizedRequest,
    findings,
    riskScore
  });
}
