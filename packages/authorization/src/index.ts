import type {
  AuthenticatedPrincipal,
  PolicyDecision,
  PolicyEvaluationInput,
  PolicyRule
} from "@aegis/contracts";
import { evaluatePolicies } from "@aegis/policy-engine";

export type AuthorizationRequest = {
  principal: AuthenticatedPrincipal;
  resource: string;
  action: string;
  requiredPermissions?: string[];
  allowSelf?: boolean;
  resourceOwnerId?: string;
  resourceAttributes?: PolicyEvaluationInput["resourceAttributes"];
  requestAttributes?: PolicyEvaluationInput["requestAttributes"];
  policies?: PolicyRule[];
  routeTags?: string[];
};

function hasRequiredPermissions(
  principal: AuthenticatedPrincipal,
  requiredPermissions: string[] = []
): boolean {
  return requiredPermissions.every((permission) => principal.permissions.includes(permission));
}

export function authorize(request: AuthorizationRequest): PolicyDecision {
  const isSelf = request.allowSelf && request.resourceOwnerId === request.principal.userId;
  const requiredPermissions = request.requiredPermissions ?? [];
  const hasPermission =
    requiredPermissions.length > 0 &&
    hasRequiredPermissions(request.principal, requiredPermissions);
  const isAdmin = request.principal.roles.includes("admin");
  const baseGranted = Boolean(isSelf || hasPermission || isAdmin);

  if (!baseGranted) {
    return {
      allowed: false,
      effect: "deny",
      reason: "Principal lacks the required permission or ownership context.",
      matchedRules: [],
      residualRisk: ["permission-missing"]
    };
  }

  const applicablePolicies =
    request.policies?.filter(
      (policy) =>
        (policy.resource === "*" || policy.resource === request.resource) &&
        (policy.action === "*" || policy.action === request.action)
    ) ?? [];

  if (applicablePolicies.length === 0) {
    return {
      allowed: true,
      effect: "allow",
      reason: isSelf
        ? "Ownership rule granted access."
        : isAdmin
          ? "Administrative role granted access."
          : "Required permissions granted access.",
      matchedRules: [],
      residualRisk: []
    };
  }

  return evaluatePolicies(applicablePolicies, {
    principal: request.principal,
    input: {
      resource: request.resource,
      action: request.action,
      resourceOwnerId: request.resourceOwnerId,
      resourceAttributes: request.resourceAttributes ?? {},
      requestAttributes: request.requestAttributes ?? {}
    },
    routeTags: request.routeTags
  });
}
