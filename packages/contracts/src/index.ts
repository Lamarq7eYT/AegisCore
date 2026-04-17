import { z } from "zod";

export const severitySchema = z.enum(["low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof severitySchema>;

export const decisionSchema = z.enum(["allow", "challenge", "deny"]);
export type Decision = z.infer<typeof decisionSchema>;

export const riskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof riskLevelSchema>;

export const normalizedHeaderSchema = z.object({
  name: z.string().min(1).max(128),
  value: z.string().max(8_192)
});
export type NormalizedHeader = z.infer<typeof normalizedHeaderSchema>;

export const normalizedRequestSchema = z.object({
  method: z.string().min(1).max(16),
  path: z.string().min(1).max(2_048),
  routeKey: z.string().min(1).max(256),
  sourceIp: z.string().max(128),
  contentType: z.string().max(256).nullable(),
  userAgent: z.string().max(512).nullable(),
  headers: z.array(normalizedHeaderSchema).max(128),
  query: z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  rawBody: z.string().max(32_768).nullable(),
  bodyKind: z.enum(["empty", "json", "text", "form", "binary", "unknown"]),
  anomalies: z.array(z.string().max(256)).max(32),
  receivedAt: z.string().datetime()
});
export type NormalizedRequest = z.infer<typeof normalizedRequestSchema>;

export const inspectionFindingSchema = z.object({
  code: z.string().min(1).max(128),
  category: z.enum([
    "syntax",
    "payload",
    "automation",
    "session",
    "upload",
    "auth",
    "network",
    "policy"
  ]),
  severity: severitySchema,
  detail: z.string().min(1).max(512),
  matchedValue: z.string().max(512).optional(),
  confidence: z.number().min(0).max(1)
});
export type InspectionFinding = z.infer<typeof inspectionFindingSchema>;

export const riskScoreSchema = z.object({
  score: z.number().min(0).max(100),
  level: riskLevelSchema,
  reasons: z.array(z.string().max(256)).max(32),
  flags: z.array(z.string().max(128)).max(32)
});
export type RiskScore = z.infer<typeof riskScoreSchema>;

export const securityEventSchema = z.object({
  id: z.string().min(1),
  kind: z.string().min(1).max(128),
  severity: severitySchema,
  correlationId: z.string().min(1),
  route: z.string().min(1).max(256),
  actorId: z.string().max(128).nullable(),
  sessionId: z.string().max(128).nullable(),
  ipHash: z.string().max(128).nullable(),
  riskScore: z.number().min(0).max(100),
  findings: z.array(inspectionFindingSchema),
  metadata: z.record(z.string(), z.unknown()),
  createdAt: z.string().datetime()
});
export type SecurityEvent = z.infer<typeof securityEventSchema>;

export const auditEntrySchema = z.object({
  id: z.string().min(1),
  actorId: z.string().max(128).nullable(),
  action: z.string().min(1).max(128),
  targetType: z.string().min(1).max(128),
  targetId: z.string().max(128).nullable(),
  decision: decisionSchema,
  reason: z.string().max(512),
  correlationId: z.string().min(1),
  metadata: z.record(z.string(), z.unknown()),
  createdAt: z.string().datetime()
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export const policyRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(128),
  effect: decisionSchema,
  resource: z.string().min(1).max(128),
  action: z.string().min(1).max(128),
  conditions: z.record(z.string(), z.unknown()),
  enabled: z.boolean().default(true)
});
export type PolicyRule = z.infer<typeof policyRuleSchema>;

export const policyDecisionSchema = z.object({
  allowed: z.boolean(),
  effect: decisionSchema,
  reason: z.string().min(1).max(512),
  matchedRules: z.array(z.string().min(1).max(128)).max(16),
  residualRisk: z.array(z.string().max(256)).max(16)
});
export type PolicyDecision = z.infer<typeof policyDecisionSchema>;

export const authenticatedPrincipalSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().min(1),
  roles: z.array(z.string().min(1).max(64)).max(16),
  permissions: z.array(z.string().min(1).max(128)).max(64),
  mfaVerified: z.boolean(),
  authTime: z.string().datetime(),
  riskLevel: riskLevelSchema,
  email: z.email(),
  displayName: z.string().max(128)
});
export type AuthenticatedPrincipal = z.infer<typeof authenticatedPrincipalSchema>;

export const uploadVerdictSchema = z.object({
  accepted: z.boolean(),
  reason: z.string().min(1).max(512),
  normalizedFilename: z.string().max(256),
  detectedMime: z.string().max(256),
  size: z.number().min(0),
  sha256: z.string().max(128).optional(),
  flags: z.array(z.string().max(128)).max(16)
});
export type UploadVerdict = z.infer<typeof uploadVerdictSchema>;

export const abuseSignalSchema = z.object({
  dimension: z.enum(["ip", "account", "session", "route", "global"]),
  key: z.string().min(1).max(256),
  score: z.number().min(0).max(100),
  ttlMs: z.number().min(0),
  blocked: z.boolean()
});
export type AbuseSignal = z.infer<typeof abuseSignalSchema>;

export const sessionRecordSchema = z.object({
  id: z.string().min(1),
  userId: z.string().min(1),
  csrfSecret: z.string().min(1),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  lastSeenAt: z.string().datetime(),
  rotatedFromId: z.string().nullable(),
  riskLevel: riskLevelSchema,
  mfaVerified: z.boolean(),
  ipHash: z.string().max(128).nullable(),
  userAgentHash: z.string().max(128).nullable(),
  revokedAt: z.string().datetime().nullable()
});
export type SessionRecord = z.infer<typeof sessionRecordSchema>;

export const loginRequestSchema = z.object({
  email: z.email().max(320),
  password: z.string().min(12).max(256),
  otpCode: z.string().length(6).optional()
});
export type LoginRequest = z.infer<typeof loginRequestSchema>;

export const loginResponseSchema = z.object({
  principal: authenticatedPrincipalSchema,
  csrfToken: z.string().min(32),
  riskScore: riskScoreSchema
});
export type LoginResponse = z.infer<typeof loginResponseSchema>;

export const passwordResetRequestSchema = z.object({
  email: z.email().max(320)
});
export type PasswordResetRequest = z.infer<typeof passwordResetRequestSchema>;

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(24).max(256),
  newPassword: z.string().min(12).max(256)
});
export type PasswordResetConfirm = z.infer<typeof passwordResetConfirmSchema>;

export const policyEvaluationInputSchema = z.object({
  resource: z.string().min(1).max(128),
  action: z.string().min(1).max(128),
  resourceOwnerId: z.string().max(128).optional(),
  resourceAttributes: z.record(z.string(), z.unknown()).default({}),
  requestAttributes: z.record(z.string(), z.unknown()).default({})
});
export type PolicyEvaluationInput = z.infer<typeof policyEvaluationInputSchema>;

export const mfaEnrollmentSchema = z.object({
  secret: z.string().min(16),
  otpauthUrl: z.string().min(16)
});
export type MfaEnrollment = z.infer<typeof mfaEnrollmentSchema>;

export const riskSummarySchema = z.object({
  requestsAnalyzed: z.number().min(0),
  blockedRequests: z.number().min(0),
  activeCooldowns: z.number().min(0),
  highRiskEvents: z.number().min(0),
  topSignals: z.array(abuseSignalSchema).max(16)
});
export type RiskSummary = z.infer<typeof riskSummarySchema>;

export const securityContextSchema = z.object({
  normalizedRequest: normalizedRequestSchema,
  findings: z.array(inspectionFindingSchema),
  riskScore: riskScoreSchema
});
export type SecurityContext = z.infer<typeof securityContextSchema>;

export const securityArtifactSchema = z.object({
  filename: z.string().max(256).optional(),
  mimeType: z.string().max(256).optional(),
  origin: z.string().max(512).optional(),
  contentLength: z.number().min(0).optional()
});
export type SecurityArtifact = z.infer<typeof securityArtifactSchema>;

export const parsedSecurityArtifactSchema = z.object({
  normalizedFilename: z.string().max(256),
  extension: z.string().max(32),
  mimeType: z.string().max(256),
  originHost: z.string().max(256).nullable(),
  flags: z.array(z.string().max(128)).max(16)
});
export type ParsedSecurityArtifact = z.infer<typeof parsedSecurityArtifactSchema>;

