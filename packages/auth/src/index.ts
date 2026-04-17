import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";
import type { AuthenticatedPrincipal, RiskLevel, SessionRecord } from "@aegis/contracts";
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type PasswordHashOptions = {
  cost: number;
  blockSize: number;
  parallelization: number;
};

export type UserIdentity = {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
  permissions: string[];
  passwordHash: string;
  mfaSecret?: string | null;
  mfaEnabled: boolean;
};

export function passwordPolicyFeedback(password: string): string[] {
  const feedback: string[] = [];

  if (password.length < 12) feedback.push("Password must be at least 12 characters.");
  if (!/[A-Z]/.test(password)) feedback.push("Password should include an uppercase letter.");
  if (!/[a-z]/.test(password)) feedback.push("Password should include a lowercase letter.");
  if (!/[0-9]/.test(password)) feedback.push("Password should include a digit.");
  if (!/[^A-Za-z0-9]/.test(password)) feedback.push("Password should include a symbol.");

  return feedback;
}

export async function hashPassword(
  password: string,
  options: PasswordHashOptions
): Promise<string> {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, 64, {
    N: options.cost,
    r: options.blockSize,
    p: options.parallelization
  }) as Buffer;

  return [
    "scrypt",
    options.cost,
    options.blockSize,
    options.parallelization,
    salt.toString("base64url"),
    derived.toString("base64url")
  ].join("$");
}

export async function verifyPassword(password: string, encodedHash: string): Promise<boolean> {
  const [algorithm, cost, blockSize, parallelization, salt, expected] = encodedHash.split("$");

  if (
    algorithm !== "scrypt" ||
    !cost ||
    !blockSize ||
    !parallelization ||
    !salt ||
    !expected
  ) {
    return false;
  }

  const derived = scryptSync(password, Buffer.from(salt, "base64url"), 64, {
    N: Number(cost),
    r: Number(blockSize),
    p: Number(parallelization)
  }) as Buffer;

  return timingSafeEqual(derived, Buffer.from(expected, "base64url"));
}

export function hashOpaqueToken(token: string): string {
  return createHmac("sha256", "aegis-token-pepper").update(token).digest("base64url");
}

export function generateResetToken(): { token: string; tokenHash: string } {
  const token = randomBytes(24).toString("base64url");
  return { token, tokenHash: hashOpaqueToken(token) };
}

function base32Encode(input: Buffer): string {
  let bits = "";
  for (const byte of input) {
    bits += byte.toString(2).padStart(8, "0");
  }

  const output: string[] = [];
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5).padEnd(5, "0");
    output.push(BASE32_ALPHABET[Number.parseInt(chunk, 2)] ?? "A");
  }

  return output.join("");
}

function base32Decode(input: string): Buffer {
  const sanitized = input.replace(/=+$/g, "").toUpperCase();
  let bits = "";

  for (const char of sanitized) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error("Invalid base32 secret.");
    }

    bits += value.toString(2).padStart(5, "0");
  }

  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  return Buffer.from(bytes);
}

export function generateOtpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function buildOtpAuthUrl(input: {
  issuer: string;
  accountName: string;
  secret: string;
}): string {
  const label = encodeURIComponent(`${input.issuer}:${input.accountName}`);
  const issuer = encodeURIComponent(input.issuer);
  return `otpauth://totp/${label}?secret=${input.secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

function hotp(secret: string, counter: number, digits = 6): string {
  const key = base32Decode(secret);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", key).update(buffer).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary = (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return binary.toString().padStart(digits, "0");
}

export function verifyTotp(secret: string, token: string, window = 1): boolean {
  const currentCounter = Math.floor(Date.now() / 30_000);
  for (let offset = -window; offset <= window; offset += 1) {
    if (hotp(secret, currentCounter + offset) === token) {
      return true;
    }
  }

  return false;
}

export function assessLoginRisk(input: {
  knownIpHash?: string | null;
  knownUserAgentHash?: string | null;
  currentIpHash?: string | null;
  currentUserAgentHash?: string | null;
  failedAttempts: number;
}): { riskLevel: RiskLevel; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  if (
    input.knownIpHash &&
    input.currentIpHash &&
    input.knownIpHash !== input.currentIpHash
  ) {
    score += 25;
    reasons.push("ip-changed");
  }

  if (
    input.knownUserAgentHash &&
    input.currentUserAgentHash &&
    input.knownUserAgentHash !== input.currentUserAgentHash
  ) {
    score += 20;
    reasons.push("user-agent-changed");
  }

  if (input.failedAttempts >= 5) {
    score += 35;
    reasons.push("recent-failures");
  }

  if (score >= 70) return { riskLevel: "critical", reasons };
  if (score >= 45) return { riskLevel: "high", reasons };
  if (score >= 20) return { riskLevel: "medium", reasons };
  return { riskLevel: "low", reasons };
}

export function createPrincipal(input: {
  user: UserIdentity;
  session: SessionRecord;
}): AuthenticatedPrincipal {
  return {
    userId: input.user.id,
    sessionId: input.session.id,
    roles: input.user.roles,
    permissions: input.user.permissions,
    mfaVerified: input.session.mfaVerified,
    authTime: input.session.createdAt,
    riskLevel: input.session.riskLevel,
    email: input.user.email,
    displayName: input.user.displayName
  };
}
