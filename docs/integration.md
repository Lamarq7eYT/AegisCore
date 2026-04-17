# Integração

## SPA consumindo API

- autentique via `/auth/login`;
- preserve cookies com `credentials: "include"`;
- leia o token CSRF do cookie dedicado e envie em `x-csrf-token` nos métodos state-changing;
- trate `403` e `429` como sinais de política/abuso, não como erros genéricos.

## SSR e sites tradicionais

- centralize autenticação server-side quando possível;
- não replique lógica de autorização apenas no frontend;
- sanitize saída por contexto e mantenha CSP alinhada à aplicação real.

## Painel administrativo

- use permissões específicas, nunca reaproveite papéis genéricos;
- separe trilhas de auditoria e monitore eventos de policy deny/challenge;
- proteja rotas administrativas com step-up quando o contexto exigir.

