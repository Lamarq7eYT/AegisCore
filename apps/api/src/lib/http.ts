import type { AppConfig } from "@aegis/config";
import type { FastifyReply, FastifyRequest } from "fastify";

export function toHeaderPairs(headers: FastifyRequest["headers"]): Array<{ name: string; value: string }> {
  const pairs: Array<{ name: string; value: string }> = [];

  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      pairs.push({ name, value });
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        pairs.push({ name, value: item });
      }
    }
  }

  return pairs;
}

export function toQueryRecord(
  query: Record<string, unknown>
): Record<string, string | string[]> {
  const normalized: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      normalized[key] = value.map((item) => String(item));
      continue;
    }

    if (value === undefined || value === null) {
      continue;
    }

    normalized[key] = String(value);
  }

  return normalized;
}

export function bodyToString(body: unknown): string | null {
  if (body === undefined || body === null) {
    return null;
  }

  if (typeof body === "string") {
    return body;
  }

  if (Buffer.isBuffer(body)) {
    return body.toString("utf8");
  }

  try {
    return JSON.stringify(body);
  } catch {
    return "[unserializable-body]";
  }
}

export function setSessionCookies(
  reply: FastifyReply,
  config: AppConfig,
  input: { sessionId: string; csrfToken: string }
): void {
  const baseOptions = {
    path: "/",
    secure: config.security.secureCookies,
    sameSite: config.security.sameSite,
    domain: config.security.cookieDomain,
    maxAge: config.security.sessionTtlMinutes * 60
  } as const;

  reply.setCookie(config.security.sessionCookieName, input.sessionId, {
    ...baseOptions,
    httpOnly: true
  });

  reply.setCookie(config.security.csrfCookieName, input.csrfToken, {
    ...baseOptions,
    httpOnly: false
  });
}

export function clearSessionCookies(reply: FastifyReply, config: AppConfig): void {
  const options = {
    path: "/",
    secure: config.security.secureCookies,
    sameSite: config.security.sameSite,
    domain: config.security.cookieDomain
  } as const;

  reply.clearCookie(config.security.sessionCookieName, options);
  reply.clearCookie(config.security.csrfCookieName, options);
}

export function isUnsafeMethod(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

