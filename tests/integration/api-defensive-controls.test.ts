import { afterEach, describe, expect, test } from "vitest";
import { loadConfig } from "../../packages/config/src/index.js";
import { createApp } from "../../apps/api/src/index.js";

const apps: Array<Awaited<ReturnType<typeof createApp>>> = [];

afterEach(async () => {
  while (apps.length > 0) {
    const app = apps.pop();
    if (app) {
      await app.close();
      await app.aegis.close();
    }
  }
});

async function bootstrap(overrides: Record<string, string> = {}) {
  const config = loadConfig({
    NODE_ENV: "test",
    APP_ORIGIN: "http://localhost:3001",
    API_ORIGIN: "http://localhost:3000",
    STORAGE_DRIVER: "memory",
    SESSION_DRIVER: "memory",
    ALLOW_NATIVE_FALLBACK: "true",
    ENABLE_DEMO_SEED: "true",
    RATE_LIMIT_IP_MAX: "2",
    RATE_LIMIT_ACCOUNT_MAX: "2",
    ...overrides
  });
  const app = await createApp({ config });
  apps.push(app);
  return app;
}

describe("api defensive controls", () => {
  test("throttles repeated login attempts", async () => {
    const app = await bootstrap();

    await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "admin@aegis.local", password: "wrong-password-1" }
    });
    await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "admin@aegis.local", password: "wrong-password-1" }
    });
    const blocked = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: { email: "admin@aegis.local", password: "wrong-password-1" }
    });

    expect(blocked.statusCode).toBe(429);
  });

  test("blocks obviously malicious payloads by risk score", async () => {
    const app = await bootstrap({
      RISK_BLOCK_THRESHOLD: "70"
    });

    const response = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "nobody@example.com",
        password: "<script>alert(1)</script>12345"
      },
      headers: {
        "user-agent": "curl/8.0"
      }
    });

    expect([401, 403]).toContain(response.statusCode);
  });
});
