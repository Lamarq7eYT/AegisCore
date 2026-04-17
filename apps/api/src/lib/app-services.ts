import { AuditService } from "@aegis/audit";
import type { AppConfig } from "@aegis/config";
import { createLogger, InMemoryMetrics } from "@aegis/observability";
import {
  InMemoryCounterStore,
  RateLimitEngine,
  RedisCounterStore
} from "@aegis/rate-limit";
import {
  InMemorySessionStore,
  RedisSessionStore,
  SessionManager
} from "@aegis/session";
import { PrismaClient } from "@prisma/client";
import Redis from "ioredis";
import {
  CompositeAuditSink,
  InMemoryPersistenceAdapter,
  PrismaPersistenceAdapter,
  buildDemoUsers,
  type PersistenceAdapter
} from "./persistence.js";

export type AppServices = {
  config: AppConfig;
  logger: ReturnType<typeof createLogger>;
  metrics: InMemoryMetrics;
  persistence: PersistenceAdapter;
  auditSink: CompositeAuditSink;
  audit: AuditService;
  sessionManager: SessionManager;
  rateLimitEngine: RateLimitEngine;
  prisma?: PrismaClient;
  redis?: Redis;
  close(): Promise<void>;
};

export async function createAppServices(config: AppConfig): Promise<AppServices> {
  const logger = createLogger(config.logging.level);
  const metrics = new InMemoryMetrics();

  const prisma =
    config.persistence.storageDriver === "prisma" && config.persistence.databaseUrl
      ? new PrismaClient({ datasourceUrl: config.persistence.databaseUrl, log: ["warn", "error"] })
      : undefined;

  const redis =
    config.persistence.sessionDriver === "redis" && config.persistence.redisUrl
      ? new Redis(config.persistence.redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 })
      : undefined;

  if (redis) {
    await redis.connect();
  }

  const seedUsers = config.featureFlags.enableDemoSeed
    ? await buildDemoUsers({
        passwordOptions: {
          cost: config.auth.passwordScryptCost,
          blockSize: config.auth.passwordScryptBlockSize,
          parallelization: config.auth.passwordScryptParallelization
        }
      })
    : [];

  const persistence =
    prisma && config.persistence.storageDriver === "prisma"
      ? new PrismaPersistenceAdapter(prisma)
      : new InMemoryPersistenceAdapter(seedUsers);

  if (prisma && config.featureFlags.enableDemoSeed) {
    for (const user of seedUsers) {
      await persistence.updateUser(user);
    }
  }

  const auditSink = new CompositeAuditSink(prisma);
  const audit = new AuditService(auditSink, logger, metrics);

  const sessionManager = new SessionManager(
    redis ? new RedisSessionStore(redis) : new InMemorySessionStore(),
    {
      ttlMinutes: config.security.sessionTtlMinutes,
      idleTimeoutMinutes: config.security.sessionIdleTimeoutMinutes
    }
  );

  const rateLimitEngine = new RateLimitEngine(
    redis ? new RedisCounterStore(redis) : new InMemoryCounterStore(),
    {
      windowMs: config.abuse.rateLimitWindowMs,
      ipMax: config.abuse.rateLimitIpMax,
      accountMax: config.abuse.rateLimitAccountMax
    },
    logger
  );

  return {
    config,
    logger,
    metrics,
    persistence,
    auditSink,
    audit,
    sessionManager,
    rateLimitEngine,
    prisma,
    redis,
    async close() {
      await prisma?.$disconnect();
      if (redis) {
        await redis.quit();
      }
    }
  };
}

