import { randomUUID } from "node:crypto";
import pino, { type Logger, type LoggerOptions } from "pino";

type MetricValue = {
  count: number;
  lastUpdatedAt: string;
};

export class InMemoryMetrics {
  readonly counters = new Map<string, MetricValue>();

  increment(name: string, value = 1): void {
    const current = this.counters.get(name);
    this.counters.set(name, {
      count: (current?.count ?? 0) + value,
      lastUpdatedAt: new Date().toISOString()
    });
  }

  snapshot(): Record<string, MetricValue> {
    return Object.fromEntries(this.counters.entries());
  }
}

export function createLogger(level: LoggerOptions["level"] = "info"): Logger {
  return pino({
    level,
    redact: {
      paths: [
        "req.headers.authorization",
        "req.headers.cookie",
        "password",
        "newPassword",
        "*.password",
        "*.token",
        "*.secret"
      ],
      censor: "[REDACTED]"
    },
    formatters: {
      level(label) {
        return { level: label };
      }
    },
    timestamp: pino.stdTimeFunctions.isoTime
  });
}

export function createCorrelationId(seed?: string): string {
  return seed ?? randomUUID();
}

export function hashForLog(value: string | undefined | null): string | null {
  if (!value) {
    return null;
  }

  return Buffer.from(value).toString("base64url").slice(0, 32);
}

export type RequestLogger = ReturnType<typeof createRequestLogger>;

export function createRequestLogger(base: Logger, correlationId: string): Logger {
  return base.child({ correlationId });
}

