import { randomUUID } from "node:crypto";
import type { AuditEntry, PolicyRule, SecurityEvent, SessionRecord, UploadVerdict } from "@aegis/contracts";
import type { AuditSink } from "@aegis/audit";
import { hashPassword, type PasswordHashOptions, type UserIdentity } from "@aegis/auth";
import { hashSessionSignal } from "@aegis/session";
import { Prisma, PrismaClient } from "@prisma/client";

export type UserRecord = UserIdentity & {
  failedLoginAttempts: number;
  lastLoginIpHash?: string | null;
  lastLoginUserAgentHash?: string | null;
  mfaSecret?: string | null;
};

export type PasswordResetRecord = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
};

export type UploadRecord = {
  id: string;
  ownerId?: string | null;
  originalName: string;
  storedName: string;
  mimeType: string;
  extension: string;
  size: number;
  status: string;
  sha256: string;
  flags: string[];
  createdAt: string;
};

export interface PersistenceAdapter {
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  updateUser(user: UserRecord): Promise<void>;
  listPolicies(): Promise<PolicyRule[]>;
  savePolicy(rule: PolicyRule): Promise<void>;
  savePasswordReset(record: PasswordResetRecord): Promise<void>;
  consumePasswordReset(tokenHash: string): Promise<PasswordResetRecord | null>;
  saveUpload(record: UploadRecord): Promise<void>;
  saveSessionAudit(session: SessionRecord): Promise<void>;
}

type DemoSeedInput = {
  passwordOptions: PasswordHashOptions;
};

export async function buildDemoUsers(input: DemoSeedInput): Promise<UserRecord[]> {
  const adminPasswordHash = await hashPassword("Admin!234567", input.passwordOptions);
  const analystPasswordHash = await hashPassword("Analyst!234567", input.passwordOptions);

  return [
    {
      id: "user_admin",
      email: "admin@aegis.local",
      displayName: "Aegis Admin",
      roles: ["admin"],
      permissions: [
        "admin:read",
        "admin:write",
        "profile:read:any",
        "profile:read:self",
        "uploads:create"
      ],
      passwordHash: adminPasswordHash,
      mfaSecret: null,
      mfaEnabled: false,
      failedLoginAttempts: 0,
      lastLoginIpHash: null,
      lastLoginUserAgentHash: null
    },
    {
      id: "user_analyst",
      email: "analyst@aegis.local",
      displayName: "Aegis Analyst",
      roles: ["analyst"],
      permissions: ["profile:read:self", "uploads:create"],
      passwordHash: analystPasswordHash,
      mfaSecret: null,
      mfaEnabled: false,
      failedLoginAttempts: 0,
      lastLoginIpHash: null,
      lastLoginUserAgentHash: null
    }
  ];
}

export class InMemoryPersistenceAdapter implements PersistenceAdapter {
  readonly users = new Map<string, UserRecord>();
  readonly policies = new Map<string, PolicyRule>();
  readonly passwordResets = new Map<string, PasswordResetRecord>();
  readonly uploads = new Map<string, UploadRecord>();
  readonly sessionAudits = new Map<string, SessionRecord>();

  constructor(seedUsers: UserRecord[]) {
    for (const user of seedUsers) {
      this.users.set(user.id, user);
    }

    const defaultPolicies: PolicyRule[] = [
      {
        id: "policy-admin-read",
        name: "Admin can access security console",
        effect: "allow",
        resource: "admin",
        action: "read",
        conditions: { roles: ["admin"] },
        enabled: true
      },
      {
        id: "policy-admin-write",
        name: "Admin write operations require admin role",
        effect: "allow",
        resource: "admin",
        action: "write",
        conditions: { roles: ["admin"] },
        enabled: true
      },
      {
        id: "policy-step-up-risk",
        name: "High risk admin actions require MFA",
        effect: "challenge",
        resource: "admin",
        action: "write",
        conditions: { riskLevel: "high" },
        enabled: true
      }
    ];

    for (const policy of defaultPolicies) {
      this.policies.set(policy.id, policy);
    }
  }

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const normalized = email.toLowerCase();
    return [...this.users.values()].find((user) => user.email === normalized) ?? null;
  }

  async findUserById(id: string): Promise<UserRecord | null> {
    return this.users.get(id) ?? null;
  }

  async updateUser(user: UserRecord): Promise<void> {
    this.users.set(user.id, user);
  }

  async listPolicies(): Promise<PolicyRule[]> {
    return [...this.policies.values()];
  }

  async savePolicy(rule: PolicyRule): Promise<void> {
    this.policies.set(rule.id, rule);
  }

  async savePasswordReset(record: PasswordResetRecord): Promise<void> {
    this.passwordResets.set(record.tokenHash, record);
  }

  async consumePasswordReset(tokenHash: string): Promise<PasswordResetRecord | null> {
    const record = this.passwordResets.get(tokenHash);
    if (!record || record.usedAt) {
      return null;
    }

    if (new Date(record.expiresAt).getTime() < Date.now()) {
      return null;
    }

    const consumed = { ...record, usedAt: new Date().toISOString() };
    this.passwordResets.set(tokenHash, consumed);
    return consumed;
  }

  async saveUpload(record: UploadRecord): Promise<void> {
    this.uploads.set(record.id, record);
  }

  async saveSessionAudit(session: SessionRecord): Promise<void> {
    this.sessionAudits.set(session.id, session);
  }
}

export class PrismaPersistenceAdapter implements PersistenceAdapter {
  constructor(private readonly prisma: PrismaClient) {}

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const record = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    return record
      ? {
          id: record.id,
          email: record.email,
          displayName: record.displayName,
          roles: record.roles,
          permissions: record.permissions,
          passwordHash: record.passwordHash,
          mfaEnabled: false,
          mfaSecret: null,
          failedLoginAttempts: record.failedLoginAttempts,
          lastLoginIpHash: record.lastLoginIpHash,
          lastLoginUserAgentHash: record.lastLoginUserAgentHash
        }
      : null;
  }

  async findUserById(id: string): Promise<UserRecord | null> {
    const record = await this.prisma.user.findUnique({ where: { id } });
    return record
      ? {
          id: record.id,
          email: record.email,
          displayName: record.displayName,
          roles: record.roles,
          permissions: record.permissions,
          passwordHash: record.passwordHash,
          mfaEnabled: false,
          mfaSecret: null,
          failedLoginAttempts: record.failedLoginAttempts,
          lastLoginIpHash: record.lastLoginIpHash,
          lastLoginUserAgentHash: record.lastLoginUserAgentHash
        }
      : null;
  }

  async updateUser(user: UserRecord): Promise<void> {
    await this.prisma.user.upsert({
      where: { id: user.id },
      create: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        passwordHash: user.passwordHash,
        roles: user.roles,
        permissions: user.permissions,
        failedLoginAttempts: user.failedLoginAttempts,
        lastLoginIpHash: user.lastLoginIpHash,
        lastLoginUserAgentHash: user.lastLoginUserAgentHash
      },
      update: {
        email: user.email,
        displayName: user.displayName,
        passwordHash: user.passwordHash,
        roles: user.roles,
        permissions: user.permissions,
        failedLoginAttempts: user.failedLoginAttempts,
        lastLoginIpHash: user.lastLoginIpHash,
        lastLoginUserAgentHash: user.lastLoginUserAgentHash
      }
    });
  }

  async listPolicies(): Promise<PolicyRule[]> {
    const records = await this.prisma.policyRule.findMany({
      orderBy: { createdAt: "asc" }
    });

    return records.map((record) => ({
      id: record.id,
      name: record.name,
      effect: record.effect as PolicyRule["effect"],
      resource: record.resource,
      action: record.action,
      conditions: (record.conditions as Record<string, unknown>) ?? {},
      enabled: record.enabled
    }));
  }

  async savePolicy(rule: PolicyRule): Promise<void> {
    await this.prisma.policyRule.upsert({
      where: { id: rule.id },
      create: {
        id: rule.id,
        name: rule.name,
        effect: rule.effect,
        resource: rule.resource,
        action: rule.action,
        conditions: rule.conditions as Prisma.InputJsonValue,
        enabled: rule.enabled
      },
      update: {
        name: rule.name,
        effect: rule.effect,
        resource: rule.resource,
        action: rule.action,
        conditions: rule.conditions as Prisma.InputJsonValue,
        enabled: rule.enabled
      }
    });
  }

  async savePasswordReset(record: PasswordResetRecord): Promise<void> {
    await this.prisma.passwordResetToken.create({
      data: {
        id: record.id,
        userId: record.userId,
        tokenHash: record.tokenHash,
        expiresAt: new Date(record.expiresAt),
        usedAt: record.usedAt ? new Date(record.usedAt) : null
      }
    });
  }

  async consumePasswordReset(tokenHash: string): Promise<PasswordResetRecord | null> {
    const record = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash }
    });

    if (!record || record.usedAt || record.expiresAt.getTime() < Date.now()) {
      return null;
    }

    const updated = await this.prisma.passwordResetToken.update({
      where: { tokenHash },
      data: { usedAt: new Date() }
    });

    return {
      id: updated.id,
      userId: updated.userId,
      tokenHash: updated.tokenHash,
      expiresAt: updated.expiresAt.toISOString(),
      usedAt: updated.usedAt?.toISOString() ?? null
    };
  }

  async saveUpload(record: UploadRecord): Promise<void> {
    await this.prisma.uploadArtifact.create({
      data: {
        id: record.id,
        ownerId: record.ownerId ?? null,
        originalName: record.originalName,
        storedName: record.storedName,
        mimeType: record.mimeType,
        extension: record.extension,
        size: record.size,
        status: record.status,
        sha256: record.sha256,
        flags: record.flags
      }
    });
  }

  async saveSessionAudit(session: SessionRecord): Promise<void> {
    await this.prisma.sessionAudit.upsert({
      where: { id: session.id },
      create: {
        id: session.id,
        userId: session.userId,
        createdAt: new Date(session.createdAt),
        expiresAt: new Date(session.expiresAt),
        lastSeenAt: new Date(session.lastSeenAt),
        revokedAt: session.revokedAt ? new Date(session.revokedAt) : null,
        riskLevel: session.riskLevel,
        mfaVerified: session.mfaVerified,
        ipHash: session.ipHash,
        userAgentHash: session.userAgentHash,
        rotatedFromId: session.rotatedFromId
      },
      update: {
        expiresAt: new Date(session.expiresAt),
        lastSeenAt: new Date(session.lastSeenAt),
        revokedAt: session.revokedAt ? new Date(session.revokedAt) : null,
        riskLevel: session.riskLevel,
        mfaVerified: session.mfaVerified,
        ipHash: session.ipHash,
        userAgentHash: session.userAgentHash,
        rotatedFromId: session.rotatedFromId
      }
    });
  }
}

export class CompositeAuditSink implements AuditSink {
  constructor(private readonly prisma?: PrismaClient) {}

  private readonly auditEntries: AuditEntry[] = [];
  private readonly securityEvents: SecurityEvent[] = [];

  async saveAudit(entry: AuditEntry): Promise<void> {
    this.auditEntries.unshift(entry);
    if (this.prisma) {
      await this.prisma.auditEntry.create({
        data: {
          id: entry.id,
          actorId: entry.actorId,
          action: entry.action,
          targetType: entry.targetType,
          targetId: entry.targetId,
          decision: entry.decision,
          reason: entry.reason,
          correlationId: entry.correlationId,
          metadata: entry.metadata as Prisma.InputJsonValue,
          createdAt: new Date(entry.createdAt)
        }
      });
    }
  }

  async saveSecurityEvent(event: SecurityEvent): Promise<void> {
    this.securityEvents.unshift(event);
    if (this.prisma) {
      await this.prisma.securityEvent.create({
        data: {
          id: event.id,
          kind: event.kind,
          severity: event.severity,
          correlationId: event.correlationId,
          route: event.route,
          actorId: event.actorId,
          sessionId: event.sessionId,
          ipHash: event.ipHash,
          riskScore: event.riskScore,
          findings: event.findings as Prisma.InputJsonValue,
          metadata: event.metadata as Prisma.InputJsonValue,
          createdAt: new Date(event.createdAt)
        }
      });
    }
  }

  async listAudit(): Promise<AuditEntry[]> {
    if (this.prisma) {
      const records = await this.prisma.auditEntry.findMany({ orderBy: { createdAt: "desc" } });
      return records.map((record) => ({
        id: record.id,
        actorId: record.actorId,
        action: record.action,
        targetType: record.targetType,
        targetId: record.targetId,
        decision: record.decision as AuditEntry["decision"],
        reason: record.reason,
        correlationId: record.correlationId,
        metadata: (record.metadata as Record<string, unknown>) ?? {},
        createdAt: record.createdAt.toISOString()
      }));
    }

    return [...this.auditEntries];
  }

  async listSecurityEvents(): Promise<SecurityEvent[]> {
    if (this.prisma) {
      const records = await this.prisma.securityEvent.findMany({
        orderBy: { createdAt: "desc" }
      });
      return records.map((record) => ({
        id: record.id,
        kind: record.kind,
        severity: record.severity as SecurityEvent["severity"],
        correlationId: record.correlationId,
        route: record.route,
        actorId: record.actorId,
        sessionId: record.sessionId,
        ipHash: record.ipHash,
        riskScore: record.riskScore,
        findings: (record.findings as SecurityEvent["findings"]) ?? [],
        metadata: (record.metadata as Record<string, unknown>) ?? {},
        createdAt: record.createdAt.toISOString()
      }));
    }

    return [...this.securityEvents];
  }
}

export function buildUploadRecord(input: {
  ownerId?: string | null;
  originalName: string;
  verdict: UploadVerdict;
}): UploadRecord {
  const extension = input.verdict.normalizedFilename.includes(".")
    ? input.verdict.normalizedFilename.slice(input.verdict.normalizedFilename.lastIndexOf("."))
    : "";

  return {
    id: randomUUID(),
    ownerId: input.ownerId ?? null,
    originalName: input.originalName,
    storedName: input.verdict.normalizedFilename,
    mimeType: input.verdict.detectedMime,
    extension,
    size: input.verdict.size,
    status: input.verdict.accepted ? "quarantined" : "rejected",
    sha256: input.verdict.sha256 ?? hashSessionSignal(input.verdict.normalizedFilename) ?? "",
    flags: input.verdict.flags,
    createdAt: new Date().toISOString()
  };
}
