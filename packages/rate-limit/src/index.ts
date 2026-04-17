import type { AbuseSignal } from "@aegis/contracts";
import type { Redis } from "ioredis";
import type { Logger } from "pino";

export type RateLimitDecision = {
  allowed: boolean;
  retryAfterMs: number;
  challenge: boolean;
  reason: string;
  signals: AbuseSignal[];
};

export type RateLimitInput = {
  routeKey: string;
  sourceIp: string;
  sessionId?: string | null;
  accountId?: string | null;
  riskScore: number;
};

export type CounterStore = {
  increment(key: string, windowMs: number): Promise<number>;
  get(key: string): Promise<number>;
};

type InMemoryCounter = {
  count: number;
  expiresAt: number;
};

export class InMemoryCounterStore implements CounterStore {
  private readonly counters = new Map<string, InMemoryCounter>();

  async increment(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const current = this.counters.get(key);
    if (!current || current.expiresAt < now) {
      this.counters.set(key, { count: 1, expiresAt: now + windowMs });
      return 1;
    }

    current.count += 1;
    return current.count;
  }

  async get(key: string): Promise<number> {
    const current = this.counters.get(key);
    if (!current || current.expiresAt < Date.now()) {
      return 0;
    }

    return current.count;
  }
}

export class RedisCounterStore implements CounterStore {
  constructor(private readonly redis: Redis, private readonly namespace = "aegis:rate") {}

  private key(key: string): string {
    return `${this.namespace}:${key}`;
  }

  async increment(key: string, windowMs: number): Promise<number> {
    const namespaced = this.key(key);
    const pipeline = this.redis.multi();
    pipeline.incr(namespaced);
    pipeline.pexpire(namespaced, windowMs, "NX");
    const result = await pipeline.exec();
    return Number(result?.[0]?.[1] ?? 0);
  }

  async get(key: string): Promise<number> {
    return Number((await this.redis.get(this.key(key))) ?? 0);
  }
}

export class RateLimitEngine {
  constructor(
    private readonly store: CounterStore,
    private readonly options: {
      windowMs: number;
      ipMax: number;
      accountMax: number;
    },
    private readonly logger?: Logger
  ) {}

  async evaluate(input: RateLimitInput): Promise<RateLimitDecision> {
    const signals: AbuseSignal[] = [];
    const ipKey = `ip:${input.sourceIp}`;
    const routeKey = `route:${input.routeKey}:${input.sourceIp}`;
    const accountKey = input.accountId ? `account:${input.accountId}` : null;

    const [ipCount, routeCount, accountCount] = await Promise.all([
      this.store.increment(ipKey, this.options.windowMs),
      this.store.increment(routeKey, this.options.windowMs),
      accountKey ? this.store.increment(accountKey, this.options.windowMs) : Promise.resolve(0)
    ]);

    const registerSignal = (
      dimension: AbuseSignal["dimension"],
      key: string,
      count: number,
      threshold: number
    ) => {
      if (count <= threshold) {
        return;
      }

      signals.push({
        dimension,
        key,
        score: Math.min(100, Math.round((count / threshold) * 45)),
        ttlMs: this.options.windowMs,
        blocked: true
      });
    };

    registerSignal("ip", ipKey, ipCount, this.options.ipMax);
    registerSignal("route", routeKey, routeCount, Math.max(10, Math.floor(this.options.ipMax / 2)));
    if (accountKey) {
      registerSignal("account", accountKey, accountCount, this.options.accountMax);
    }

    const elevatedRisk = input.riskScore >= 55;
    const blocked =
      signals.some((signal) => signal.blocked) ||
      (elevatedRisk && ipCount > Math.floor(this.options.ipMax / 2));
    const challenge = !blocked && elevatedRisk;
    const retryAfterMs = blocked ? this.options.windowMs : 0;

    if (blocked) {
      this.logger?.warn({ input, signals }, "Rate limit blocked a request.");
    }

    return {
      allowed: !blocked,
      retryAfterMs,
      challenge,
      reason: blocked
        ? "adaptive-throttle-blocked"
        : challenge
          ? "adaptive-challenge"
          : "allowed",
      signals
    };
  }
}

