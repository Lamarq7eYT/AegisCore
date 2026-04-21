# Validation Fixture Plan

This document lists the malformed inputs AegisCore should keep as regression
fixtures for API validation and risk scoring.

## Authentication Fixtures

- Missing authorization header.
- Empty bearer token.
- Token with an unsupported prefix.
- Expired token with otherwise valid shape.
- Valid token paired with a role that cannot access the route.

## Risk Payload Fixtures

- Missing severity field.
- Severity outside the accepted enum.
- Score lower than the minimum.
- Score higher than the maximum.
- Oversized description body.
- Unknown fields that should be ignored or rejected consistently.

## Expected Assertions

Each fixture should assert the status code, stable error code, human readable
message, and whether the event is written to audit logs. Keeping these checks
together makes the defensive boundary easier to maintain while the API grows.
