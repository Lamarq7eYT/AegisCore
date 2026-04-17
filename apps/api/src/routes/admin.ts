import { authorize } from "@aegis/authorization";
import {
  policyEvaluationInputSchema,
  policyRuleSchema,
  riskSummarySchema
} from "@aegis/contracts";
import type { FastifyPluginAsync } from "fastify";

export const adminRoutes: FastifyPluginAsync = async (app) => {
  app.get(
    "/admin/security-events",
    {
      config: {
        security: {
          auth: true,
          csrf: false,
          sensitive: true,
          resource: "admin",
          action: "read",
          permissions: ["admin:read"]
        }
      }
    },
    async () => ({
      events: await app.aegis.auditSink.listSecurityEvents()
    })
  );

  app.get(
    "/admin/audit",
    {
      config: {
        security: {
          auth: true,
          csrf: false,
          sensitive: true,
          resource: "admin",
          action: "read",
          permissions: ["admin:read"]
        }
      }
    },
    async () => ({
      entries: await app.aegis.auditSink.listAudit()
    })
  );

  app.get(
    "/admin/policies",
    {
      config: {
        security: {
          auth: true,
          csrf: false,
          sensitive: true,
          resource: "admin",
          action: "read",
          permissions: ["admin:read"]
        }
      }
    },
    async () => ({
      policies: (await app.aegis.persistence.listPolicies()).map((policy) =>
        policyRuleSchema.parse(policy)
      )
    })
  );

  app.post(
    "/admin/policies/evaluate",
    {
      config: {
        security: {
          auth: true,
          sensitive: true,
          resource: "admin",
          action: "write",
          permissions: ["admin:write"]
        }
      }
    },
    async (request, reply) => {
      if (!request.principal) {
        return reply.code(401).send({ error: "auth-required" });
      }

      const parsed = policyEvaluationInputSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "invalid-request",
          details: parsed.error.flatten()
        });
      }

      const policies = await app.aegis.persistence.listPolicies();
      const decision = authorize({
        principal: request.principal,
        resource: parsed.data.resource,
        action: parsed.data.action,
        resourceOwnerId: parsed.data.resourceOwnerId,
        resourceAttributes: parsed.data.resourceAttributes,
        requestAttributes: {
          ...parsed.data.requestAttributes,
          riskLevel: request.securityContext.riskScore.level
        },
        policies
      });

      return {
        decision
      };
    }
  );

  app.get(
    "/admin/risk/summary",
    {
      config: {
        security: {
          auth: true,
          csrf: false,
          sensitive: true,
          resource: "admin",
          action: "read",
          permissions: ["admin:read"]
        }
      }
    },
    async () => {
      const metrics = app.aegis.metrics.snapshot();
      const events = await app.aegis.auditSink.listSecurityEvents();
      const highRiskEvents = events.filter((event) => event.riskScore >= 60).length;
      const blockedRequests = events.filter((event) => event.kind.includes("blocked")).length;
      const topSignals = events.slice(0, 5).map((event, index) => ({
        dimension: "route" as const,
        key: `${index}:${event.route}`,
        score: Math.min(100, event.riskScore),
        ttlMs: app.aegis.config.abuse.rateLimitWindowMs,
        blocked: event.riskScore >= app.aegis.config.security.riskBlockThreshold
      }));

      return riskSummarySchema.parse({
        requestsAnalyzed: metrics["security.requests"]?.count ?? 0,
        blockedRequests,
        activeCooldowns: topSignals.filter((signal) => signal.blocked).length,
        highRiskEvents,
        topSignals
      });
    }
  );
};

