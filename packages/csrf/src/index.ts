import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export function issueCsrfToken(sessionId: string, csrfSecret: string): string {
  const nonce = randomBytes(16).toString("base64url");
  const signature = createHmac("sha256", csrfSecret)
    .update(`${sessionId}:${nonce}`)
    .digest("base64url");
  return `${nonce}.${signature}`;
}

export function verifyCsrfToken(input: {
  sessionId: string;
  csrfSecret: string;
  token?: string | null;
  cookieToken?: string | null;
  origin?: string | null;
  allowedOrigin: string;
}): { valid: boolean; reason?: string } {
  const token = input.token;
  if (!token) {
    return { valid: false, reason: "missing-token" };
  }

  const [nonce, signature] = token.split(".");
  if (!nonce || !signature) {
    return { valid: false, reason: "malformed-token" };
  }

  const expected = createHmac("sha256", input.csrfSecret)
    .update(`${input.sessionId}:${nonce}`)
    .digest("base64url");

  const isValid = timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  if (!isValid) {
    return { valid: false, reason: "invalid-signature" };
  }

  if (input.cookieToken && input.cookieToken !== token) {
    return { valid: false, reason: "double-submit-mismatch" };
  }

  if (input.origin) {
    try {
      const requestOrigin = new URL(input.origin).origin;
      const allowedOrigin = new URL(input.allowedOrigin).origin;
      if (requestOrigin !== allowedOrigin) {
        return { valid: false, reason: "origin-mismatch" };
      }
    } catch {
      return { valid: false, reason: "origin-invalid" };
    }
  }

  return { valid: true };
}
