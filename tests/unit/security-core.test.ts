import { describe, expect, test } from "vitest";
import { buildSecurityContext } from "../../packages/security-core-ts/src/index.js";

describe("security-core facade", () => {
  test("scores suspicious payloads when native fallback is enabled", () => {
    const context = buildSecurityContext(
      {
        method: "POST",
        path: "/search",
        routeKey: "POST /search",
        sourceIp: "127.0.0.1",
        contentType: "application/json",
        userAgent: "curl/8.0",
        headers: [{ name: "content-type", value: "application/json" }],
        query: {},
        rawBody: "{\"q\":\"<script>alert(1)</script> union select\"}"
      },
      { sensitiveRoute: true, allowFallback: true }
    );

    expect(context.findings.length).toBeGreaterThan(0);
    expect(context.riskScore.score).toBeGreaterThanOrEqual(60);
  });
});

