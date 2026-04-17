import { createHash, randomBytes } from "node:crypto";
import type { SessionRecord } from "@aegis/contracts";
import type { Redis } from "ioredis";

export type SessionManagerOptions = {
  ttlMinutes: number;
  idleTimeoutMinutes: number;
};

export type SessionStore = {
  save(session: SessionRecord): Promise<void>;
  get(sessionId: string): Promise<SessionRecord | null>;
  delete(sessionId: string): Promise<void>;
  listActiveByUser(userId: string): Promise<SessionRecord[]>;
};

export function hashSessionSignal(input: string | null | undefined): string | null {
  if (!input) {
    return null;
  }

  return createHash("sha256").update(input).digest("base64url");
}

export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, SessionRecord>();

  async save(session: SessionRecord): Promise<void> {
    this.sessions.set(session.id, session);
  }

  async get(sessionId: string): Promise<SessionRecord | null> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    if (new Date(session.expiresAt).getTime() < Date.now() || session.revokedAt) {
      this.sessions.delete(sessionId);
      return null;
    }

    return session;
  }

  async delete(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async listActiveByUser(userId: string): Promise<SessionRecord[]> {
    return [...this.sessions.values()].filter(
      (session) => session.userId === userId && !session.revokedAt
    );
  }
}

export class RedisSessionStore implements SessionStore {
  constructor(private readonly redis: Redis, private readonly namespace = "aegis:sessions") {}

  private key(sessionId: string): string {
    return `${this.namespace}:${sessionId}`;
  }

  async save(session: SessionRecord): Promise<void> {
    const ttlSeconds = Math.max(
      1,
      Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1_000)
    );
    await this.redis.set(this.key(session.id), JSON.stringify(session), "EX", ttlSeconds);
  }

  async get(sessionId: string): Promise<SessionRecord | null> {
    const payload = await this.redis.get(this.key(sessionId));
    return payload ? (JSON.parse(payload) as SessionRecord) : null;
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(this.key(sessionId));
  }

  async listActiveByUser(userId: string): Promise<SessionRecord[]> {
    const keys = await this.redis.keys(`${this.namespace}:*`);
    const records = await Promise.all(keys.map((key) => this.redis.get(key)));
    return records
      .filter((value): value is string => Boolean(value))
      .map((value) => JSON.parse(value) as SessionRecord)
      .filter((session) => session.userId === userId && !session.revokedAt);
  }
}

export class SessionManager {
  constructor(
    private readonly store: SessionStore,
    private readonly options: SessionManagerOptions
  ) {}

  async issueSession(input: {
    userId: string;
    riskLevel: SessionRecord["riskLevel"];
    mfaVerified: boolean;
    ipHash?: string | null;
    userAgentHash?: string | null;
    rotatedFromId?: string | null;
  }): Promise<SessionRecord> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.options.ttlMinutes * 60_000);
    const session: SessionRecord = {
      id: randomBytes(24).toString("base64url"),
      userId: input.userId,
      csrfSecret: randomBytes(32).toString("base64url"),
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      lastSeenAt: now.toISOString(),
      rotatedFromId: input.rotatedFromId ?? null,
      riskLevel: input.riskLevel,
      mfaVerified: input.mfaVerified,
      ipHash: input.ipHash ?? null,
      userAgentHash: input.userAgentHash ?? null,
      revokedAt: null
    };

    await this.store.save(session);
    return session;
  }

  async load(sessionId: string): Promise<SessionRecord | null> {
    return this.store.get(sessionId);
  }

  async touch(sessionId: string): Promise<SessionRecord | null> {
    const session = await this.store.get(sessionId);
    if (!session) {
      return null;
    }

    const now = new Date();
    const idleDeadline =
      new Date(session.lastSeenAt).getTime() + this.options.idleTimeoutMinutes * 60_000;
    if (idleDeadline < now.getTime()) {
      await this.store.delete(sessionId);
      return null;
    }

    const updated: SessionRecord = {
      ...session,
      lastSeenAt: now.toISOString()
    };
    await this.store.save(updated);
    return updated;
  }

  async rotate(
    sessionId: string,
    patch: {
      riskLevel?: SessionRecord["riskLevel"];
      mfaVerified?: boolean;
      ipHash?: string | null;
      userAgentHash?: string | null;
    } = {}
  ): Promise<SessionRecord | null> {
    const session = await this.store.get(sessionId);
    if (!session) {
      return null;
    }

    await this.revoke(sessionId);
    return this.issueSession({
      userId: session.userId,
      riskLevel: patch.riskLevel ?? session.riskLevel,
      mfaVerified: patch.mfaVerified ?? session.mfaVerified,
      ipHash: patch.ipHash ?? session.ipHash,
      userAgentHash: patch.userAgentHash ?? session.userAgentHash,
      rotatedFromId: session.id
    });
  }

  async revoke(sessionId: string): Promise<void> {
    const session = await this.store.get(sessionId);
    if (!session) {
      return;
    }

    await this.store.save({
      ...session,
      revokedAt: new Date().toISOString()
    });
    await this.store.delete(sessionId);
  }
}

