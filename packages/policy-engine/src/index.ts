import type {
  AuthenticatedPrincipal,
  PolicyDecision,
  PolicyEvaluationInput,
  PolicyRule
} from "@aegis/contracts";

export type PolicyContext = {
  principal: AuthenticatedPrincipal;
  input: PolicyEvaluationInput;
  routeTags?: string[];
};

function matchesCondition(value: unknown, expected: unknown): boolean {
  if (Array.isArray(value) && Array.isArray(expected)) {
    return expected.every((item) => value.includes(item));
  }

  if (Array.isArray(value)) {
    return value.includes(expected);
  }

  if (Array.isArray(expected)) {
    return expected.includes(value as never);
  }

  if (typeof expected === "object" && expected !== null && typeof value === "object") {
    return Object.entries(expected).every(([key, nestedExpected]) =>
      matchesCondition((value as Record<string, unknown>)[key], nestedExpected)
    );
  }

  return value === expected;
}

function ruleMatches(rule: PolicyRule, context: PolicyContext): boolean {
  if (!rule.enabled) {
    return false;
  }

  if (rule.resource !== "*" && rule.resource !== context.input.resource) {
    return false;
  }

  if (rule.action !== "*" && rule.action !== context.input.action) {
    return false;
  }

  return Object.entries(rule.conditions).every(([key, expected]) => {
    const principalValue = (context.principal as Record<string, unknown>)[key];
    const requestValue = context.input.requestAttributes[key];
    const resourceValue = context.input.resourceAttributes[key];
    const routeValue = context.routeTags?.includes(String(expected));

    return (
      matchesCondition(principalValue, expected) ||
      matchesCondition(requestValue, expected) ||
      matchesCondition(resourceValue, expected) ||
      routeValue === true
    );
  });
}

export function evaluatePolicies(rules: PolicyRule[], context: PolicyContext): PolicyDecision {
  const matchedRules = rules.filter((rule) => ruleMatches(rule, context));
  const denyRules = matchedRules.filter((rule) => rule.effect === "deny");
  const challengeRules = matchedRules.filter((rule) => rule.effect === "challenge");
  const allowRules = matchedRules.filter((rule) => rule.effect === "allow");

  if (denyRules.length > 0) {
    return {
      allowed: false,
      effect: "deny",
      reason: `Denied by policy rules: ${denyRules.map((rule) => rule.name).join(", ")}`,
      matchedRules: denyRules.map((rule) => rule.id),
      residualRisk: ["manual-review"]
    };
  }

  if (challengeRules.length > 0 && !context.principal.mfaVerified) {
    return {
      allowed: false,
      effect: "challenge",
      reason: "Action requires a stepped-up authentication context.",
      matchedRules: challengeRules.map((rule) => rule.id),
      residualRisk: ["step-up-required"]
    };
  }

  if (allowRules.length > 0) {
    return {
      allowed: true,
      effect: "allow",
      reason: `Allowed by policy rules: ${allowRules.map((rule) => rule.name).join(", ")}`,
      matchedRules: allowRules.map((rule) => rule.id),
      residualRisk: []
    };
  }

  return {
    allowed: false,
    effect: "deny",
    reason: "Deny-by-default: no policy rule granted this action.",
    matchedRules: [],
    residualRisk: ["implicit-deny"]
  };
}
