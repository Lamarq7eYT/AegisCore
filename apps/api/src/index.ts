import fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyCors from "@fastify/cors";
import fastifyMultipart from "@fastify/multipart";
import { authorize } from "@aegis/authorization";
import { loadConfig, type AppConfig } from "@aegis/config";
import { verifyCsrfToken } from "@aegis/csrf";
import { getSecurityHeaders } from "@aegis/headers";
import { buildSecurityContext } from "@aegis/security-core-ts";
import { createPrincipal } from "@aegis/auth";
import { createAppServices, type AppServices } from "./lib/app-services.js";
import { bodyToString, isUnsafeMethod, toHeaderPairs, toQueryRecord } from "./lib/http.js";
import { authRoutes } from "./routes/auth.js";
import { adminRoutes } from "./routes/admin.js";
import { healthRoutes } from "./routes/health.js";
import { protectedRoutes } from "./routes/protected.js";
import { uploadRoutes } from "./routes/uploads.js";

type CreateAppOptions = {
  config?: AppConfig;
  services?: AppServices;
};

async function registerSecurityHooks(app: any): Promise<void> {
  const { config } = app.aegis;

  app.decorateRequest("correlationId", "");
  app.decorateRequest("securityContext", null as never);
  app.decorateRequest("session", null as never);
  app.decorateRequest("principal", null as never);
  app.decorateRequest("rateLimitDecision", null as never);

  app.addHook("onRequest", async (request: any) => {
    request.correlationId = request.id;
  });

  app.addHook("preValidation", async (request: any, reply: any) => {
    const securityConfig = request.routeOptions.config?.security ?? {};
    try {
      request.securityContext = buildSecurityContext(
        {
          method: request.method,
          path: request.url.split("?")[0] ?? request.url,
          routeKey: `${request.method} ${request.routeOptions.url}`,
          sourceIp: request.ip,
          contentType: request.headers["content-type"] as string | undefined,
          userAgent: request.headers["user-agent"] as string | undefined,
          headers: toHeaderPairs(request.headers),
          query: toQueryRecord((request.query as Record<string, unknown>) ?? {}),
          rawBody: bodyToString(request.body)
        },
        {
          sensitiveRoute: securityConfig.sensitive ?? false,
          allowFallback: config.security.allowNativeFallback
        }
      );
      app.aegis.metrics.increment("security.requests");
    } catch (error) {
      request.log.error({ err: error }, "Failed to build security context.");
      return reply.code(400).send({ error: "malformed-request" });
    }
  });

  app.addHook("preHandler", async (request: any, reply: any) => {
    const securityConfig = request.routeOptions.config?.security ?? {};
    const routePath = request.routeOptions.url ?? request.url;
    const sessionId = request.cookies[config.security.sessionCookieName];
    if (sessionId) {
      request.session = await app.aegis.sessionManager.touch(sessionId);
      if (request.session) {
        await app.aegis.persistence.saveSessionAudit(request.session);
        const user = await app.aegis.persistence.findUserById(request.session.userId);
        if (user) {
          request.principal = createPrincipal({ user, session: request.session });
        }
      }
    }

    const loginEmail =
      typeof request.body === "object" &&
      request.body !== null &&
      "email" in (request.body as Record<string, unknown>)
        ? String((request.body as Record<string, unknown>).email).toLowerCase()
        : undefined;

    request.rateLimitDecision = await app.aegis.rateLimitEngine.evaluate({
      routeKey: routePath,
      sourceIp: request.ip,
      sessionId: request.session?.id,
      accountId: request.principal?.userId ?? loginEmail,
      riskScore: request.securityContext.riskScore.score
    });

    if (!request.rateLimitDecision.allowed) {
      await app.aegis.audit.recordSecurityEvent({
          kind: "request.blocked.rate_limit",
          severity: "high",
          correlationId: request.correlationId,
          route: routePath,
        actorId: request.principal?.userId ?? null,
        sessionId: request.session?.id ?? null,
        ipHash: request.session?.ipHash ?? null,
        riskScore: request.securityContext.riskScore.score,
        findings: request.securityContext.findings,
        metadata: { signals: request.rateLimitDecision.signals }
      });
      return reply
        .code(429)
        .header(
          "retry-after",
          Math.ceil(request.rateLimitDecision.retryAfterMs / 1_000).toString()
        )
        .send({ error: "rate-limit-blocked" });
    }

    if (request.securityContext.riskScore.score >= config.security.riskBlockThreshold) {
      await app.aegis.audit.recordSecurityEvent({
          kind: "request.blocked.risk_score",
          severity: "critical",
          correlationId: request.correlationId,
          route: routePath,
        actorId: request.principal?.userId ?? null,
        sessionId: request.session?.id ?? null,
        ipHash: request.session?.ipHash ?? null,
        riskScore: request.securityContext.riskScore.score,
        findings: request.securityContext.findings,
        metadata: { reason: "risk-threshold-exceeded" }
      });
      return reply.code(403).send({ error: "risk-threshold-exceeded" });
    }

    if (request.session && isUnsafeMethod(request.method) && securityConfig.csrf !== false) {
      const csrfResult = verifyCsrfToken({
        sessionId: request.session.id,
        csrfSecret: request.session.csrfSecret,
        token: request.headers["x-csrf-token"] as string | undefined,
        cookieToken: request.cookies[config.security.csrfCookieName],
        origin: request.headers.origin as string | undefined,
        allowedOrigin: config.server.appOrigin
      });

      if (!csrfResult.valid) {
        await app.aegis.audit.recordSecurityEvent({
          kind: "request.blocked.csrf",
          severity: "high",
          correlationId: request.correlationId,
          route: routePath,
          actorId: request.principal?.userId ?? null,
          sessionId: request.session.id,
          ipHash: request.session.ipHash,
          riskScore: request.securityContext.riskScore.score,
          findings: request.securityContext.findings,
          metadata: { reason: csrfResult.reason }
        });
        return reply.code(403).send({ error: "csrf-validation-failed", reason: csrfResult.reason });
      }
    }

    if (securityConfig.auth && !request.principal) {
      return reply.code(401).send({ error: "auth-required" });
    }

    if (
      request.principal &&
      securityConfig.resource &&
      securityConfig.action
    ) {
      const params = (request.params as Record<string, unknown> | undefined) ?? {};
      const ownerId = securityConfig.ownerParam
        ? String(params[securityConfig.ownerParam] ?? "")
        : undefined;
      const policies =
        securityConfig.policyOverrides ?? (await app.aegis.persistence.listPolicies());
      const decision = authorize({
        principal: request.principal,
        resource: securityConfig.resource,
        action: securityConfig.action,
        requiredPermissions: securityConfig.permissions,
        allowSelf: securityConfig.allowSelf,
        resourceOwnerId: ownerId,
        requestAttributes: {
          riskLevel: request.securityContext.riskScore.level,
          route: routePath
        },
        policies,
        routeTags: securityConfig.routeTags
      });

      if (!decision.allowed) {
        await app.aegis.audit.recordAudit({
          actorId: request.principal.userId,
          action: `${securityConfig.resource}.${securityConfig.action}`,
          targetType: securityConfig.resource,
          targetId: ownerId ?? null,
          decision: decision.effect,
          reason: decision.reason,
          correlationId: request.correlationId,
          metadata: { residualRisk: decision.residualRisk }
        });
        return reply.code(403).send({ error: "forbidden", reason: decision.reason });
      }
    }
  });

  app.addHook("onSend", async (_request: any, reply: any, payload: any) => {
    const headers = getSecurityHeaders({
      appOrigin: config.server.appOrigin,
      apiOrigin: config.server.apiOrigin,
      enableHsts: config.env === "production"
    });

    for (const [name, value] of Object.entries(headers)) {
      reply.header(name, value);
    }

    return payload;
  });
}

export async function createApp(options: CreateAppOptions = {}) {
  const config = options.config ?? loadConfig();
  const services = options.services ?? (await createAppServices(config));

  const app = fastify({
    loggerInstance: services.logger,
    trustProxy: config.server.trustProxy,
    bodyLimit: config.security.maxJsonBodyBytes
  });

  app.decorate("aegis", services);

  await app.register(fastifyCookie);
  await app.register(fastifyCors, {
    origin: config.server.appOrigin,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
  });
  await app.register(fastifyMultipart, {
    limits: {
      fileSize: config.security.maxUploadBytes,
      files: 1
    }
  });

  await registerSecurityHooks(app);

  app.setErrorHandler(async (error, request, reply) => {
    request.log.error({ err: error }, "Unhandled API error.");
    return reply.code(500).send({ error: "internal-error" });
  });

  await app.register(healthRoutes);
  await app.register(authRoutes);
  await app.register(adminRoutes);
  await app.register(uploadRoutes);
  await app.register(protectedRoutes);

  return app;
}

export default createApp;
