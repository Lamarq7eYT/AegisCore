import { randomUUID } from "node:crypto";
import type {
  AuditEntry,
  Decision,
  InspectionFinding,
  SecurityEvent,
  Severity
} from "@aegis/contracts";
import type { InMemoryMetrics } from "@aegis/observability";
import type { Logger } from "pino";

export interface AuditSink {
  saveAudit(entry: AuditEntry): Promise<void>;
  saveSecurityEvent(event: SecurityEvent): Promise<void>;
  listAudit(): Promise<AuditEntry[]>;
  listSecurityEvents(): Promise<SecurityEvent[]>;
}

export class InMemoryAuditSink implements AuditSink {
  private readonly auditEntries: AuditEntry[] = [];
  private readonly securityEvents: SecurityEvent[] = [];

  async saveAudit(entry: AuditEntry): Promise<void> {
    this.auditEntries.unshift(entry);
  }

  async saveSecurityEvent(event: SecurityEvent): Promise<void> {
    this.securityEvents.unshift(event);
  }

  async listAudit(): Promise<AuditEntry[]> {
    return [...this.auditEntries];
  }

  async listSecurityEvents(): Promise<SecurityEvent[]> {
    return [...this.securityEvents];
  }
}

export class AuditService {
  constructor(
    private readonly sink: AuditSink,
    private readonly logger: Logger,
    private readonly metrics?: InMemoryMetrics
  ) {}

  async recordAudit(input: {
    actorId?: string | null;
    action: string;
    targetType: string;
    targetId?: string | null;
    decision: Decision;
    reason: string;
    correlationId: string;
    metadata?: Record<string, unknown>;
  }): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: randomUUID(),
      actorId: input.actorId ?? null,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId ?? null,
      decision: input.decision,
      reason: input.reason,
      correlationId: input.correlationId,
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString()
    };

    await this.sink.saveAudit(entry);
    this.metrics?.increment("audit.entries");
    this.logger.info({ audit: entry }, "Audit entry recorded.");
    return entry;
  }

  async recordSecurityEvent(input: {
    kind: string;
    severity: Severity;
    correlationId: string;
    route: string;
    actorId?: string | null;
    sessionId?: string | null;
    ipHash?: string | null;
    riskScore: number;
    findings: InspectionFinding[];
    metadata?: Record<string, unknown>;
  }): Promise<SecurityEvent> {
    const event: SecurityEvent = {
      id: randomUUID(),
      kind: input.kind,
      severity: input.severity,
      correlationId: input.correlationId,
      route: input.route,
      actorId: input.actorId ?? null,
      sessionId: input.sessionId ?? null,
      ipHash: input.ipHash ?? null,
      riskScore: input.riskScore,
      findings: input.findings,
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString()
    };

    await this.sink.saveSecurityEvent(event);
    this.metrics?.increment("security.events");
    this.logger.warn({ securityEvent: event }, "Security event recorded.");
    return event;
  }
}

