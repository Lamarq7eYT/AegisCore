# Configuração

## Perfis de ambiente

- `development`: memória por padrão, fallback nativo permitido, seed demo habilitado.
- `test`: memória por padrão, ideal para `inject` e testes unitários.
- `production`: exige PostgreSQL/Redis quando drivers correspondentes são usados, cookies seguros e fallback nativo desabilitado por padrão.

## Variáveis principais

- `STORAGE_DRIVER`: `memory` ou `prisma`
- `SESSION_DRIVER`: `memory` ou `redis`
- `ALLOW_NATIVE_FALLBACK`: `true` apenas para dev/teste
- `RISK_BLOCK_THRESHOLD`: score para bloqueio duro
- `RISK_CHALLENGE_THRESHOLD`: score para resposta mais rígida/step-up
- `RATE_LIMIT_*`: tuning por ambiente
- `SECURE_COOKIES`: `true` em produção

## Defaults seguros

- validação estrita com Zod;
- body limit reduzido;
- cookies `HttpOnly + Secure + SameSite=lax`;
- headers de navegador seguros;
- deny-by-default na authz contextual.

