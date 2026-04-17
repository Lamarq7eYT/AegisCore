export type HeaderOptions = {
  appOrigin: string;
  apiOrigin: string;
  enableHsts: boolean;
};

export function buildCsp(options: HeaderOptions): string {
  const connectSrc = [`'self'`, options.appOrigin, options.apiOrigin].join(" ");
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `connect-src ${connectSrc}`,
    "img-src 'self' data:",
    "font-src 'self' data:",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "object-src 'none'",
    "upgrade-insecure-requests"
  ].join("; ");
}

export function getSecurityHeaders(options: HeaderOptions): Record<string, string> {
  return {
    "content-security-policy": buildCsp(options),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    ...(options.enableHsts
      ? { "strict-transport-security": "max-age=63072000; includeSubDomains; preload" }
      : {})
  };
}

