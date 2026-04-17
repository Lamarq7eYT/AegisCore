# Arquitetura

## Justificativa da arquitetura híbrida

TypeScript foi escolhido para a plataforma principal porque:

- acelera entrega e manutenção no ecossistema web;
- integra naturalmente com Fastify, Prisma, Zod, Redis, Vitest e observabilidade;
- facilita evolução de contratos REST, plugins e fluxos de middleware;
- reduz custo de onboarding para devs de produto, plataforma e AppSec.

Rust foi escolhido para módulos críticos porque:

- oferece segurança de memória e reduz classes inteiras de falha;
- é adequado para normalização defensiva, parsing sensível e heurísticas rápidas;
- permite um núcleo pequeno, auditável e explicitamente isolado via `N-API`.

C++ e Assembly não são a base certa aqui porque:

- elevam muito o custo de manutenção;
- aumentam o atrito de build e revisão;
- não resolvem, por si só, broken access control, CSRF, validação insuficiente, misconfiguration ou observabilidade pobre.

Segurança web real depende mais de:

- fronteiras de confiança explícitas;
- validação estrita;
- autenticação e sessão corretas;
- autorização deny-by-default;
- trilhas de auditoria;
- defaults seguros;
- capacidade de detectar e responder.

## Camadas do sistema

1. Configuração segura: valida ambiente, escolhe drivers, impõe defaults.
2. Normalização de request: remove ambiguidades e produz representação auditável.
3. Inspeção defensiva: procura sinais suspeitos e combinações perigosas.
4. Score de risco: agrega risco por requisição.
5. Anti-abuse: rate limit e throttling adaptativo.
6. Sessão e autenticação: cookies opacos, rotação, revogação e MFA opcional.
7. CSRF: double-submit token + origem.
8. Autorização: RBAC de base + regras contextuais com deny-by-default.
9. Upload guard: extensão allowlist, MIME real, quarentena e trilha.
10. Auditoria/observabilidade: logs estruturados, eventos de segurança, métricas e trilha de decisão.

## Fronteiras de confiança

- Navegador/cliente → API
- API TypeScript → binding nativo
- API → PostgreSQL
- API → Redis
- Painel admin → endpoints administrativos
- Uploads externos → área de quarentena

## Contratos principais

- `NormalizedRequest`
- `InspectionFinding`
- `RiskScore`
- `PolicyDecision`
- `AuthenticatedPrincipal`
- `UploadVerdict`
- `SecurityEvent`
- `AuditEntry`

## Estratégia de fallback

- Produção: binding nativo ativo como baseline.
- Dev/teste: `ALLOW_NATIVE_FALLBACK=true` permite heurística TS para onboarding e validação parcial.
- O fallback existe para não paralisar o aprendizado ou o DX, não como substituto permanente do núcleo nativo.

