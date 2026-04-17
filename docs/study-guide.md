# Guia de Estudo

## Ordem ideal

1. `README.md`
2. `docs/architecture.md`
3. `docs/threat-model.md`
4. `packages/contracts`
5. `packages/security-core-ts`
6. `apps/api/src/index.ts`
7. `packages/auth`, `packages/session`, `packages/csrf`
8. `packages/authorization`, `packages/policy-engine`
9. `packages/rate-limit`, `packages/upload-guard`, `packages/audit`
10. `native/crates/*` e `native/aegis-native`

## O que observar

- qual ameaça cada módulo cobre;
- onde ficam as fronteiras de confiança;
- como decisões de bloqueio viram evidência auditável;
- quais trade-offs foram escolhidos por clareza e manutenção.

