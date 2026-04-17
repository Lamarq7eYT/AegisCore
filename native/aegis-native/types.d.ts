export type NativeRequestInput = {
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

export type NativeNormalizedRequest = NativeRequestInput & {
  bodyKind: "empty" | "json" | "text" | "form" | "binary" | "unknown";
  anomaliesJson: string;
};

export type NativeFinding = {
  code: string;
  category: "syntax" | "payload" | "automation" | "session" | "upload" | "auth" | "network" | "policy";
  severity: "low" | "medium" | "high" | "critical";
  detail: string;
  matchedValue?: string;
  confidence: number;
};

export type NativeRiskScore = {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  reasonsJson: string;
  flagsJson: string;
};

export type SecurityArtifact = {
  filename?: string;
  mimeType?: string;
  origin?: string;
  contentLength?: number;
};

export type ParsedSecurityArtifact = {
  normalizedFilename: string;
  extension: string;
  mimeType: string;
  originHost: string | null;
  flags: string[];
};

export function normalizeRequest(input: NativeRequestInput): NativeNormalizedRequest;
export function inspectRequest(input: NativeNormalizedRequest): NativeFinding[];
export function scoreRequestRisk(
  input: NativeNormalizedRequest,
  findingsJson: string,
  sensitiveRoute: boolean
): NativeRiskScore;
export function parseSecurityArtifact(input: SecurityArtifact): ParsedSecurityArtifact;
