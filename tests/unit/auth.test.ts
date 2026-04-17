import { describe, expect, test } from "vitest";
import {
  buildOtpAuthUrl,
  generateOtpSecret,
  hashPassword,
  passwordPolicyFeedback,
  verifyPassword,
  verifyTotp
} from "../../packages/auth/src/index.js";

describe("auth helpers", () => {
  test("hashes and verifies strong passwords", async () => {
    const password = "Sup3rSecure!Pass";
    const hash = await hashPassword(password, {
      cost: 16_384,
      blockSize: 8,
      parallelization: 1
    });

    await expect(verifyPassword(password, hash)).resolves.toBe(true);
    await expect(verifyPassword("wrong-password", hash)).resolves.toBe(false);
  });

  test("flags weak passwords and generates TOTP enrollment URLs", () => {
    const feedback = passwordPolicyFeedback("short");
    expect(feedback.length).toBeGreaterThan(0);

    const secret = generateOtpSecret();
    const url = buildOtpAuthUrl({
      issuer: "AegisCore",
      accountName: "demo@aegis.local",
      secret
    });

    expect(secret.length).toBeGreaterThan(16);
    expect(url).toContain("otpauth://totp/");
    expect(verifyTotp(secret, "000000")).toBe(false);
  });
});

