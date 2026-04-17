import { randomUUID } from "node:crypto";
import {
  buildOtpAuthUrl,
  createPrincipal,
  generateOtpSecret,
  generateResetToken,
  hashOpaqueToken,
  hashPassword,
  passwordPolicyFeedback,
  verifyPassword,
  verifyTotp
} from "@aegis/auth";
import {
  loginRequestSchema,
  loginResponseSchema,
  passwordResetConfirmSchema,
  passwordResetRequestSchema
} from "@aegis/contracts";
import { issueCsrfToken } from "@aegis/csrf";
import { hashSessionSignal } from "@aegis/session";
import type { FastifyPluginAsync } from "fastify";
import { clearSessionCookies, setSessionCookies } from "../lib/http.js";

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    "/auth/login",
    { config: { security: { sensitive: true, csrf: false } } },
    async (request, reply) => {
      const routePath = request.routeOptions.url ?? request.url;
      const parsed = loginRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "invalid-request",
          details: parsed.error.flatten()
        });
      }

      const payload = parsed.data;
      const user = await app.aegis.persistence.findUserByEmail(payload.email.toLowerCase());
      const genericError = {
        error: "invalid-credentials",
        message: "Invalid credentials or second factor."
      };

      if (!user) {
        await app.aegis.audit.recordSecurityEvent({
          kind: "auth.login.failed",
          severity: "medium",
          correlationId: request.correlationId,
          route: routePath,
          riskScore: request.securityContext.riskScore.score,
          findings: request.securityContext.findings,
          metadata: { email: payload.email.toLowerCase(), reason: "unknown-user" }
        });
        return reply.code(401).send(genericError);
      }

      const validPassword = await verifyPassword(payload.password, user.passwordHash);
      if (!validPassword) {
        user.failedLoginAttempts += 1;
        await app.aegis.persistence.updateUser(user);
        await app.aegis.audit.recordSecurityEvent({
          kind: "auth.login.failed",
          severity: "medium",
          correlationId: request.correlationId,
          route: routePath,
          actorId: user.id,
          riskScore: request.securityContext.riskScore.score,
          findings: request.securityContext.findings,
          metadata: { reason: "bad-password" }
        });
        return reply.code(401).send(genericError);
      }

      if (user.mfaEnabled) {
        if (!payload.otpCode || !user.mfaSecret || !verifyTotp(user.mfaSecret, payload.otpCode)) {
          user.failedLoginAttempts += 1;
          await app.aegis.persistence.updateUser(user);
          await app.aegis.audit.recordSecurityEvent({
            kind: "auth.login.mfa_failed",
            severity: "high",
            correlationId: request.correlationId,
            route: routePath,
            actorId: user.id,
            riskScore: request.securityContext.riskScore.score,
            findings: request.securityContext.findings,
            metadata: { reason: "mfa-invalid" }
          });
          return reply.code(401).send(genericError);
        }
      }

      user.failedLoginAttempts = 0;
      user.lastLoginIpHash = hashSessionSignal(request.ip);
      user.lastLoginUserAgentHash = hashSessionSignal(request.headers["user-agent"] as string | undefined);
      await app.aegis.persistence.updateUser(user);

      const session = await app.aegis.sessionManager.issueSession({
        userId: user.id,
        riskLevel: request.securityContext.riskScore.level,
        mfaVerified: user.mfaEnabled,
        ipHash: user.lastLoginIpHash,
        userAgentHash: user.lastLoginUserAgentHash
      });
      await app.aegis.persistence.saveSessionAudit(session);

      const principal = createPrincipal({ user, session });
      const csrfToken = issueCsrfToken(session.id, session.csrfSecret);
      setSessionCookies(reply, app.aegis.config, { sessionId: session.id, csrfToken });

      await app.aegis.audit.recordAudit({
        actorId: user.id,
        action: "auth.login",
        targetType: "session",
        targetId: session.id,
        decision: "allow",
        reason: "User authenticated successfully.",
        correlationId: request.correlationId,
        metadata: { mfaVerified: session.mfaVerified, riskLevel: session.riskLevel }
      });

      return reply.send(
        loginResponseSchema.parse({
          principal,
          csrfToken,
          riskScore: request.securityContext.riskScore
        })
      );
    }
  );

  app.post(
    "/auth/logout",
    { config: { security: { auth: true, sensitive: true } } },
    async (request, reply) => {
      if (request.session) {
        await app.aegis.sessionManager.revoke(request.session.id);
      }
      clearSessionCookies(reply, app.aegis.config);

      if (request.principal) {
        await app.aegis.audit.recordAudit({
          actorId: request.principal.userId,
          action: "auth.logout",
          targetType: "session",
          targetId: request.session?.id ?? null,
          decision: "allow",
          reason: "User signed out.",
          correlationId: request.correlationId
        });
      }

      return reply.send({ ok: true });
    }
  );

  app.get(
    "/auth/me",
    { config: { security: { auth: true, csrf: false } } },
    async (request) => ({
      principal: request.principal
    })
  );

  app.get(
    "/sessions/current",
    { config: { security: { auth: true, csrf: false } } },
    async (request) => ({
      session: request.session,
      principal: request.principal
    })
  );

  app.post(
    "/auth/reset/request",
    { config: { security: { sensitive: true, csrf: false } } },
    async (request) => {
      const parsed = passwordResetRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        return { ok: true };
      }

      const user = await app.aegis.persistence.findUserByEmail(parsed.data.email.toLowerCase());
      let demoToken: string | undefined;
      if (user) {
        const { token, tokenHash } = generateResetToken();
        demoToken = app.aegis.config.env === "production" ? undefined : token;
        await app.aegis.persistence.savePasswordReset({
          id: randomUUID(),
          userId: user.id,
          tokenHash,
          expiresAt: new Date(
            Date.now() + app.aegis.config.auth.passwordResetTtlMinutes * 60_000
          ).toISOString(),
          usedAt: null
        });
        await app.aegis.audit.recordAudit({
          actorId: user.id,
          action: "auth.reset.request",
          targetType: "user",
          targetId: user.id,
          decision: "allow",
          reason: "Password reset requested.",
          correlationId: request.correlationId
        });
      }

      return {
        ok: true,
        message: "If the account exists, a reset workflow has been initiated.",
        ...(demoToken ? { demoToken } : {})
      };
    }
  );

  app.post(
    "/auth/reset/confirm",
    { config: { security: { sensitive: true, csrf: false } } },
    async (request, reply) => {
      const parsed = passwordResetConfirmSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "invalid-request",
          details: parsed.error.flatten()
        });
      }

      const passwordFeedback = passwordPolicyFeedback(parsed.data.newPassword);
      if (passwordFeedback.length > 0) {
        return reply.code(400).send({
          error: "weak-password",
          feedback: passwordFeedback
        });
      }

      const tokenHash = hashOpaqueToken(parsed.data.token);
      const reset = await app.aegis.persistence.consumePasswordReset(tokenHash);
      if (!reset) {
        return reply.code(400).send({ error: "invalid-or-expired-token" });
      }

      const user = await app.aegis.persistence.findUserById(reset.userId);
      if (!user) {
        return reply.code(404).send({ error: "user-not-found" });
      }

      user.passwordHash = await hashPassword(parsed.data.newPassword, {
        cost: app.aegis.config.auth.passwordScryptCost,
        blockSize: app.aegis.config.auth.passwordScryptBlockSize,
        parallelization: app.aegis.config.auth.passwordScryptParallelization
      });
      await app.aegis.persistence.updateUser(user);

      await app.aegis.audit.recordAudit({
        actorId: user.id,
        action: "auth.reset.confirm",
        targetType: "user",
        targetId: user.id,
        decision: "allow",
        reason: "Password reset completed.",
        correlationId: request.correlationId
      });

      return { ok: true };
    }
  );

  app.post(
    "/auth/mfa/enroll",
    { config: { security: { auth: true, sensitive: true } } },
    async (request, reply) => {
      if (!request.principal) {
        return reply.code(401).send({ error: "auth-required" });
      }

      const user = await app.aegis.persistence.findUserById(request.principal.userId);
      if (!user) {
        return reply.code(404).send({ error: "user-not-found" });
      }

      user.mfaSecret = generateOtpSecret();
      user.mfaEnabled = false;
      await app.aegis.persistence.updateUser(user);

      const otpauthUrl = buildOtpAuthUrl({
        issuer: "AegisCore",
        accountName: user.email,
        secret: user.mfaSecret
      });

      await app.aegis.audit.recordAudit({
        actorId: user.id,
        action: "auth.mfa.enroll",
        targetType: "user",
        targetId: user.id,
        decision: "allow",
        reason: "TOTP secret generated for enrollment.",
        correlationId: request.correlationId
      });

      return {
        secret: user.mfaSecret,
        otpauthUrl
      };
    }
  );

  app.post(
    "/auth/mfa/verify",
    { config: { security: { auth: true, sensitive: true } } },
    async (request, reply) => {
      if (!request.principal || !request.session) {
        return reply.code(401).send({ error: "auth-required" });
      }

      const body = request.body as { otpCode?: string };
      if (!body?.otpCode) {
        return reply.code(400).send({ error: "otp-required" });
      }

      const user = await app.aegis.persistence.findUserById(request.principal.userId);
      if (!user || !user.mfaSecret || !verifyTotp(user.mfaSecret, body.otpCode)) {
        return reply.code(400).send({ error: "invalid-otp" });
      }

      user.mfaEnabled = true;
      await app.aegis.persistence.updateUser(user);

      const rotated = await app.aegis.sessionManager.rotate(request.session.id, {
        mfaVerified: true
      });

      if (!rotated) {
        return reply.code(401).send({ error: "session-expired" });
      }

      await app.aegis.persistence.saveSessionAudit(rotated);
      const csrfToken = issueCsrfToken(rotated.id, rotated.csrfSecret);
      setSessionCookies(reply, app.aegis.config, { sessionId: rotated.id, csrfToken });

      await app.aegis.audit.recordAudit({
        actorId: user.id,
        action: "auth.mfa.verify",
        targetType: "session",
        targetId: rotated.id,
        decision: "allow",
        reason: "TOTP verified and session rotated.",
        correlationId: request.correlationId
      });

      return {
        ok: true,
        sessionId: rotated.id,
        csrfToken
      };
    }
  );
};
