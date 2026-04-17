import type {
  AuthenticatedPrincipal,
  PolicyRule,
  SecurityContext,
  SessionRecord
} from "@aegis/contracts";
import type { RateLimitDecision } from "@aegis/rate-limit";
import type { AppServices } from "./lib/app-services.js";

declare module "fastify" {
  interface FastifyContextConfig {
    security?: {
      auth?: boolean;
      csrf?: boolean;
      sensitive?: boolean;
      resource?: string;
      action?: string;
      permissions?: string[];
      allowSelf?: boolean;
      ownerParam?: string;
      routeTags?: string[];
      policyOverrides?: PolicyRule[];
    };
  }

  interface FastifyRequest {
    correlationId: string;
    securityContext: SecurityContext;
    session: SessionRecord | null;
    principal: AuthenticatedPrincipal | null;
    rateLimitDecision: RateLimitDecision | null;
  }

  interface FastifyInstance {
    aegis: AppServices;
  }
}

export {};

