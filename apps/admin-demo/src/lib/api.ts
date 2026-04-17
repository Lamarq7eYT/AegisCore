const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:3000";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const csrfToken = document.cookie
    .split("; ")
    .find((cookie) => cookie.startsWith("aegis_csrf="))
    ?.split("=")[1];

  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(csrfToken ? { "x-csrf-token": decodeURIComponent(csrfToken) } : {}),
      ...(init.headers ?? {})
    },
    ...init
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({ error: "request-failed" }));
    throw new Error(errorPayload.error ?? errorPayload.message ?? "request-failed");
  }

  return response.json() as Promise<T>;
}

export type LoginPayload = {
  email: string;
  password: string;
  otpCode?: string;
};

export const api = {
  login(payload: LoginPayload) {
    return request<{ principal: { email: string; displayName: string; roles: string[]; mfaVerified: boolean } }>(
      "/auth/login",
      {
        method: "POST",
        body: JSON.stringify(payload)
      }
    );
  },
  logout() {
    return request<{ ok: boolean }>("/auth/logout", {
      method: "POST",
      body: JSON.stringify({})
    });
  },
  me() {
    return request<{ principal: unknown }>("/auth/me");
  },
  currentSession() {
    return request<{ session: unknown; principal: unknown }>("/sessions/current");
  },
  securityEvents() {
    return request<{ events: Array<Record<string, unknown>> }>("/admin/security-events");
  },
  audit() {
    return request<{ entries: Array<Record<string, unknown>> }>("/admin/audit");
  },
  policies() {
    return request<{ policies: Array<Record<string, unknown>> }>("/admin/policies");
  },
  riskSummary() {
    return request<Record<string, unknown>>("/admin/risk/summary");
  },
  evaluatePolicy(payload: Record<string, unknown>) {
    return request<{ decision: Record<string, unknown> }>("/admin/policies/evaluate", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  }
};

