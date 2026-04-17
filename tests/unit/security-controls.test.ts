import { describe, expect, test } from "vitest";
import { authorize } from "../../packages/authorization/src/index.js";
import { issueCsrfToken, verifyCsrfToken } from "../../packages/csrf/src/index.js";
import {
  InMemoryCounterStore,
  RateLimitEngine
} from "../../packages/rate-limit/src/index.js";
import {
  InMemorySessionStore,
  SessionManager
} from "../../packages/session/src/index.js";
import { evaluateUpload } from "../../packages/upload-guard/src/index.js";

describe("session and csrf", () => {
  test("issues sessions and validates csrf tokens", async () => {
    const manager = new SessionManager(new InMemorySessionStore(), {
      ttlMinutes: 30,
      idleTimeoutMinutes: 10
    });
    const session = await manager.issueSession({
      userId: "user_1",
      riskLevel: "medium",
      mfaVerified: false
    });
    const csrfToken = issueCsrfToken(session.id, session.csrfSecret);

    const validation = verifyCsrfToken({
      sessionId: session.id,
      csrfSecret: session.csrfSecret,
      token: csrfToken,
      cookieToken: csrfToken,
      origin: "http://localhost:3001",
      allowedOrigin: "http://localhost:3001"
    });

    expect(validation.valid).toBe(true);
    expect(await manager.load(session.id)).not.toBeNull();
  });
});

describe("authorization, throttling and upload guard", () => {
  test("allows self access and rejects foreign access without permission", () => {
    const principal = {
      userId: "user_1",
      sessionId: "session_1",
      roles: ["analyst"],
      permissions: ["profile:read:self"],
      mfaVerified: false,
      authTime: new Date().toISOString(),
      riskLevel: "low" as const,
      email: "analyst@aegis.local",
      displayName: "Analyst"
    };

    const selfDecision = authorize({
      principal,
      resource: "profile",
      action: "read",
      allowSelf: true,
      resourceOwnerId: "user_1"
    });
    const otherDecision = authorize({
      principal,
      resource: "profile",
      action: "read",
      allowSelf: true,
      resourceOwnerId: "user_2"
    });

    expect(selfDecision.allowed).toBe(true);
    expect(otherDecision.allowed).toBe(false);
  });

  test("blocks requests after adaptive throttle threshold", async () => {
    const engine = new RateLimitEngine(new InMemoryCounterStore(), {
      windowMs: 60_000,
      ipMax: 2,
      accountMax: 2
    });

    await engine.evaluate({
      routeKey: "POST /auth/login",
      sourceIp: "127.0.0.1",
      riskScore: 10
    });
    await engine.evaluate({
      routeKey: "POST /auth/login",
      sourceIp: "127.0.0.1",
      riskScore: 10
    });
    const blocked = await engine.evaluate({
      routeKey: "POST /auth/login",
      sourceIp: "127.0.0.1",
      riskScore: 10
    });

    expect(blocked.allowed).toBe(false);
    expect(blocked.signals.length).toBeGreaterThan(0);
  });

  test("rejects suspicious uploads with double extension and mime mismatch", () => {
    const verdict = evaluateUpload({
      filename: "invoice.pdf.exe",
      declaredMime: "application/pdf",
      content: Buffer.from("MZ suspicious payload"),
      maxBytes: 2048
    });

    expect(verdict.accepted).toBe(false);
  });
});

