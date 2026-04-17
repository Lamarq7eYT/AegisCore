import { z } from "zod";

const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    HOST: z.string().default("0.0.0.0"),
    APP_ORIGIN: z.url().default("http://localhost:3001"),
    API_ORIGIN: z.url().default("http://localhost:3000"),
    DATABASE_URL: z.string().optional(),
    REDIS_URL: z.string().optional(),
    SESSION_COOKIE_NAME: z.string().default("aegis_session"),
    SESSION_TTL_MINUTES: z.coerce.number().int().min(5).max(1_440).default(120),
    SESSION_IDLE_TIMEOUT_MINUTES: z.coerce.number().int().min(5).max(1_440).default(30),
    CSRF_COOKIE_NAME: z.string().default("aegis_csrf"),
    COOKIE_DOMAIN: z.string().optional(),
    SECURE_COOKIES: z.coerce.boolean().optional(),
    STORAGE_DRIVER: z.enum(["memory", "prisma"]).optional(),
    SESSION_DRIVER: z.enum(["memory", "redis"]).optional(),
    ALLOW_NATIVE_FALLBACK: z.coerce.boolean().default(false),
    ENABLE_DEMO_SEED: z.coerce.boolean().default(true),
    TRUST_PROXY: z.coerce.boolean().default(true),
    RISK_BLOCK_THRESHOLD: z.coerce.number().min(1).max(100).default(80),
    RISK_CHALLENGE_THRESHOLD: z.coerce.number().min(1).max(100).default(55),
    RATE_LIMIT_WINDOW_MS: z.coerce.number().min(1_000).default(60_000),
    RATE_LIMIT_IP_MAX: z.coerce.number().min(1).default(100),
    RATE_LIMIT_ACCOUNT_MAX: z.coerce.number().min(1).default(20),
    MAX_JSON_BODY_BYTES: z.coerce.number().min(1_024).default(16_384),
    MAX_UPLOAD_BYTES: z.coerce.number().min(1_024).default(5_000_000),
    PASSWORD_SCRYPT_COST: z.coerce.number().min(1_024).default(16_384),
    PASSWORD_SCRYPT_BLOCK_SIZE: z.coerce.number().min(1).default(8),
    PASSWORD_SCRYPT_PARALLELIZATION: z.coerce.number().min(1).default(1),
    PASSWORD_RESET_TTL_MINUTES: z.coerce.number().int().min(5).default(30),
    LOG_LEVEL: z
      .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
      .default("info")
  })
  .transform((raw) => {
    const secureCookies =
      raw.SECURE_COOKIES ?? (raw.NODE_ENV === "production" ? true : false);
    const storageDriver =
      raw.STORAGE_DRIVER ?? (raw.NODE_ENV === "production" ? "prisma" : "memory");
    const sessionDriver =
      raw.SESSION_DRIVER ?? (raw.NODE_ENV === "production" ? "redis" : "memory");

    if (raw.NODE_ENV === "production" && !raw.DATABASE_URL && storageDriver === "prisma") {
      throw new Error("DATABASE_URL is required when STORAGE_DRIVER=prisma in production.");
    }

    if (raw.NODE_ENV === "production" && !raw.REDIS_URL && sessionDriver === "redis") {
      throw new Error("REDIS_URL is required when SESSION_DRIVER=redis in production.");
    }

    return {
      ...raw,
      SECURE_COOKIES: secureCookies,
      STORAGE_DRIVER: storageDriver,
      SESSION_DRIVER: sessionDriver
    };
  });

export type AppEnv = z.infer<typeof envSchema>;

export type AppConfig = {
  env: AppEnv["NODE_ENV"];
  server: {
    host: string;
    port: number;
    trustProxy: boolean;
    apiOrigin: string;
    appOrigin: string;
  };
  persistence: {
    databaseUrl: string | undefined;
    redisUrl: string | undefined;
    storageDriver: AppEnv["STORAGE_DRIVER"];
    sessionDriver: AppEnv["SESSION_DRIVER"];
  };
  security: {
    sessionCookieName: string;
    csrfCookieName: string;
    sessionTtlMinutes: number;
    sessionIdleTimeoutMinutes: number;
    cookieDomain: string | undefined;
    secureCookies: boolean;
    sameSite: "lax";
    allowNativeFallback: boolean;
    riskBlockThreshold: number;
    riskChallengeThreshold: number;
    maxJsonBodyBytes: number;
    maxUploadBytes: number;
  };
  auth: {
    passwordScryptCost: number;
    passwordScryptBlockSize: number;
    passwordScryptParallelization: number;
    passwordResetTtlMinutes: number;
  };
  abuse: {
    rateLimitWindowMs: number;
    rateLimitIpMax: number;
    rateLimitAccountMax: number;
  };
  logging: {
    level: AppEnv["LOG_LEVEL"];
  };
  featureFlags: {
    enableDemoSeed: boolean;
  };
};

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const env = envSchema.parse(source);

  return {
    env: env.NODE_ENV,
    server: {
      host: env.HOST,
      port: env.PORT,
      trustProxy: env.TRUST_PROXY,
      apiOrigin: env.API_ORIGIN,
      appOrigin: env.APP_ORIGIN
    },
    persistence: {
      databaseUrl: env.DATABASE_URL,
      redisUrl: env.REDIS_URL,
      storageDriver: env.STORAGE_DRIVER,
      sessionDriver: env.SESSION_DRIVER
    },
    security: {
      sessionCookieName: env.SESSION_COOKIE_NAME,
      csrfCookieName: env.CSRF_COOKIE_NAME,
      sessionTtlMinutes: env.SESSION_TTL_MINUTES,
      sessionIdleTimeoutMinutes: env.SESSION_IDLE_TIMEOUT_MINUTES,
      cookieDomain: env.COOKIE_DOMAIN,
      secureCookies: env.SECURE_COOKIES,
      sameSite: "lax",
      allowNativeFallback: env.ALLOW_NATIVE_FALLBACK,
      riskBlockThreshold: env.RISK_BLOCK_THRESHOLD,
      riskChallengeThreshold: env.RISK_CHALLENGE_THRESHOLD,
      maxJsonBodyBytes: env.MAX_JSON_BODY_BYTES,
      maxUploadBytes: env.MAX_UPLOAD_BYTES
    },
    auth: {
      passwordScryptCost: env.PASSWORD_SCRYPT_COST,
      passwordScryptBlockSize: env.PASSWORD_SCRYPT_BLOCK_SIZE,
      passwordScryptParallelization: env.PASSWORD_SCRYPT_PARALLELIZATION,
      passwordResetTtlMinutes: env.PASSWORD_RESET_TTL_MINUTES
    },
    abuse: {
      rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
      rateLimitIpMax: env.RATE_LIMIT_IP_MAX,
      rateLimitAccountMax: env.RATE_LIMIT_ACCOUNT_MAX
    },
    logging: {
      level: env.LOG_LEVEL
    },
    featureFlags: {
      enableDemoSeed: env.ENABLE_DEMO_SEED
    }
  };
}

export function isProduction(config: AppConfig): boolean {
  return config.env === "production";
}

export const DEFAULT_SECURITY_HEADERS = {
  frameAncestors: "'none'",
  scriptSrc: "'self'",
  styleSrc: "'self' 'unsafe-inline'",
  imgSrc: "'self' data:",
  connectSrc: "'self'",
  baseUri: "'self'",
  objectSrc: "'none'"
} as const;
