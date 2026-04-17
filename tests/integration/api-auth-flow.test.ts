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
    ...overrides
  });
  const app = await createApp({ config });
  apps.push(app);
  return app;
}

describe("api auth flow", () => {
  test("logs in, reads session and enforces csrf on logout", async () => {
    const app = await bootstrap();
    const login = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "admin@aegis.local",
        password: "Admin!234567"
      }
    });

    expect(login.statusCode).toBe(200);
    const loginBody = login.json();
    const cookieHeader = login.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: {
        cookie: cookieHeader
      }
    });
    expect(me.statusCode).toBe(200);

    const logoutWithoutCsrf = await app.inject({
      method: "POST",
      url: "/auth/logout",
      headers: {
        cookie: cookieHeader,
        origin: "http://localhost:3001"
      },
      payload: {}
    });
    expect(logoutWithoutCsrf.statusCode).toBe(403);

    const logout = await app.inject({
      method: "POST",
      url: "/auth/logout",
      headers: {
        cookie: cookieHeader,
        origin: "http://localhost:3001",
        "x-csrf-token": loginBody.csrfToken
      },
      payload: {}
    });
    expect(logout.statusCode).toBe(200);
  });

  test("allows self profile access and rejects cross-account access for analyst", async () => {
    const app = await bootstrap();
    const login = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "analyst@aegis.local",
        password: "Analyst!234567"
      }
    });

    const cookieHeader = login.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

    const ownProfile = await app.inject({
      method: "GET",
      url: "/protected/users/user_analyst/profile",
      headers: {
        cookie: cookieHeader
      }
    });
    const foreignProfile = await app.inject({
      method: "GET",
      url: "/protected/users/user_admin/profile",
      headers: {
        cookie: cookieHeader
      }
    });

    expect(ownProfile.statusCode).toBe(200);
    expect(foreignProfile.statusCode).toBe(403);
  });
});

