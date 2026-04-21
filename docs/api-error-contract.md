# API Error Response Contract

AegisCore API errors should be consistent, safe to expose, and easy to connect to logs. This document defines the baseline response shape for validation, authentication, authorization, rate-limit, and server errors.

## Canonical Shape

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests. Try again later.",
    "requestId": "req_01HXAMPLE",
    "details": {
      "retryAfterSeconds": 60
    }
  }
}
```

## Fields

| Field | Required | Notes |
| --- | --- | --- |
| `error.code` | yes | Stable machine-readable code. |
| `error.message` | yes | Safe human-readable message. |
| `error.requestId` | yes | Correlates client response with structured logs. |
| `error.details` | no | Sanitized metadata useful for recovery. |

## Error Families

- `VALIDATION_FAILED`: invalid input, failed schema parsing, missing required field.
- `UNAUTHENTICATED`: no valid identity signal.
- `FORBIDDEN`: identity exists but lacks permission for the action.
- `RATE_LIMITED`: request exceeded configured limit.
- `CONFLICT`: state conflict, duplicate action, or stale resource version.
- `INTERNAL_ERROR`: unexpected server failure.

## Safety Rules

- Do not expose stack traces, SQL fragments, tokens, secrets, or internal service addresses.
- Prefer stable codes over highly specific implementation names.
- Include `requestId` on every error path so operators can find the matching log entry.
- Keep validation details field-level and short.

Refs #5.
