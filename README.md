# AegisCore

**AegisCore** é uma plataforma híbrida TypeScript + Rust para defesa web aplicada, criada para proteger, observar e estudar aplicações web modernas com uma arquitetura séria, modular e auditável.

> Feito por **Llew**, com bastante esforço, cuidado técnico e foco em transformar segurança web em algo estudável, reutilizável e mais fácil de evoluir.

Este projeto não promete segurança absoluta, invulnerabilidade ou proteção perfeita. Segurança real é um processo contínuo: arquitetura defensiva, validação consistente, autorização bem aplicada, observabilidade, resposta a incidentes, testes, revisão e melhoria constante.

## Visão geral

AegisCore foi desenhado como um baseline enterprise-grade para sites, APIs e painéis administrativos. Ele combina uma plataforma principal em TypeScript, usando Node.js e Fastify, com módulos críticos em Rust para normalização, inspeção defensiva, parsing seguro e cálculo de risco.

O objetivo é impedir, dificultar, detectar, conter e registrar tentativas de abuso como credential stuffing, brute force, falhas de sessão, broken access control, IDOR/BOLA, upload malicioso, CSRF, XSS, SSRF, path traversal, vazamento de dados, uso indevido de APIs e automação suspeita.

O repositório também tem uma função educacional: cada módulo existe para demonstrar uma defesa concreta, explicar limites, documentar trade-offs e servir como ponto de partida para sistemas de segurança próprios.

## Autoria

- Projeto feito por **Llew**.
- Construído com bastante esforço, paciência e foco defensivo.
- A proposta do projeto é educacional e profissional: estudar segurança web moderna sem transformar o código em ferramenta ofensiva contra terceiros.

## Uso responsável

- Use apenas em ambientes próprios, autorizados ou laboratoriais.
- Não use este repositório para atacar terceiros, explorar sistemas externos, roubar credenciais, automatizar abuso ou criar tooling ofensivo.
- Os testes defensivos incluídos são locais e controlados, voltados ao próprio AegisCore.
- O motor de inspeção é heurístico e defensivo; ele ajuda a identificar risco, mas não substitui arquitetura segura, revisão humana, monitoramento e resposta a incidentes.

## Stack principal

- **TypeScript** como linguagem principal da plataforma.
- **Node.js + Fastify** para a API REST.
- **React + Vite** para o admin demo.
- **PostgreSQL + Prisma** como persistência de produção.
- **Redis** para sessão, rate limit e sinais temporários.
- **Zod** para validação estrita.
- **Pino** para logs estruturados.
- **Vitest** para testes TypeScript.
- **Rust** para módulos críticos de segurança e desempenho.
- **N-API** como ponte entre Node.js e Rust.
- **Docker** como artefato de infraestrutura local e produção.

## Por que TypeScript + Rust

TypeScript é a base certa para a plataforma principal porque conversa naturalmente com o ecossistema web: Fastify, Prisma, Redis, validação, testes, observabilidade, admin panels e integração com times de produto. Ele também reduz o custo de manutenção e onboarding.

Rust entra apenas onde existe ganho técnico real: normalização de payload, parsing sensível, inspeção de padrões suspeitos e cálculo de score de risco. Esses módulos se beneficiam de segurança de memória, performance previsível, tipos fortes e fronteiras bem definidas.

C++ e Assembly não são usados como base porque aumentariam muito o custo operacional, o risco de manutenção e a dificuldade de auditoria sem resolver o principal problema da segurança web. Na prática, a proteção de aplicações depende mais de arquitetura, validação, autorização, sessão, configuração, logs, auditoria e resposta a incidentes do que de linguagem de baixo nível.

O trade-off é assumido: o projeto ganha uma fronteira nativa robusta e performática, mas exige mais cuidado com build, distribuição e contratos entre linguagens.

## Arquitetura

```text
apps/
  api/                 API REST Fastify, segurança, auth, sessão, auditoria
  admin-demo/          SPA React para visualizar fluxos defensivos
packages/
  contracts/           DTOs e schemas compartilhados
  security-core-ts/    Fachada TypeScript para o núcleo nativo
  auth/                Senhas, login, MFA baseline e proteção contra abuso
  authorization/       RBAC, ABAC contextual, deny-by-default e IDOR/BOLA
  session/             Sessões opacas stateful
  csrf/                Tokens CSRF e validação de origem
  headers/             Headers de segurança e CSP
  rate-limit/          Rate limit multidimensional e throttling adaptativo
  upload-guard/        Validação defensiva de uploads
  audit/               Trilhas de auditoria
  observability/       Logs, correlation IDs e mascaramento
  policy-engine/       Decisões de política e risco residual
native/
  aegis-native/        Binding N-API único para Node.js
  crates/              Crates internos em Rust
docs/                  Arquitetura, threat model, operação e estudo
tests/                 Testes unitários, integração e regressão defensiva
examples/              Requisições e exemplos de uso
```

## Fluxo defensivo de request

1. A requisição entra no Fastify.
2. Um correlation ID é criado para rastrear logs, auditoria e eventos.
3. O contexto de segurança é montado com rota, origem, headers e corpo.
4. O núcleo TypeScript chama o binding Rust para normalizar, inspecionar e calcular risco.
5. Rate limit e throttling adaptativo avaliam IP, conta, sessão, rota e score.
6. Sessão, CSRF e autorização contextual são aplicados antes do handler.
7. A ação é executada apenas se a decisão permitir.
8. Eventos relevantes viram logs estruturados, auditoria e eventos de segurança.

## Módulos Rust

O Rust fica atrás de um único pacote Node chamado `@aegis/native`, evitando múltiplos pontos de ABI e simplificando distribuição.

- `payload_normalizer`: canoniza entradas ambíguas, encoding, caminhos e corpo.
- `request_inspector`: identifica sinais defensivos de payload suspeito, automação e abuso.
- `risk_scoring_core`: calcula score de risco com heurísticas explícitas e auditáveis.
- `security_parser`: faz parsing seguro de artefatos sensíveis, como URLs e origens internas.

Em produção, o binding nativo deve estar ativo. O fallback TypeScript existe somente para desenvolvimento, onboarding e testes em ambientes sem toolchain nativo.

## Controles implementados

- Validação estrita com Zod e rejeição de campos inesperados.
- Sessões opacas stateful com cookie `HttpOnly`, `Secure` e `SameSite`.
- CSRF token separado para fluxos browser.
- RBAC base com ABAC contextual no policy engine.
- Deny-by-default em rotas protegidas.
- Proteção explícita contra IDOR/BOLA em exemplos protegidos.
- Rate limit por múltiplas dimensões e throttling por risco.
- Proteção contra enumeração em fluxos de autenticação.
- Upload guard com allowlist, tamanho máximo, MIME sniffing e rejeição de double extension.
- Headers defensivos, CSP, referrer policy, frame protection e permissions policy.
- Logs estruturados com mascaramento de segredos.
- Auditoria de eventos críticos.
- Threat model, hardening checklist e baseline de resposta a incidentes.

## Threat model

O threat model prioriza os riscos com maior impacto para aplicações web:

- Prioridade máxima: autenticação, sessão, broken access control, IDOR/BOLA, credential stuffing, brute force, token theft, admin abuse e exposição sensível.
- Alta prioridade: SQL injection, XSS, CSRF, SSRF, upload abuse, path traversal, open redirect, webhook abuse, CORS incorreto, rate-limit bypass e secret leakage.
- Prioridade média: race conditions, cache abuse, dependency compromise, poisoned packages, unsafe deserialization, template injection, command injection, misconfiguration e improper logging.

Leia o detalhamento completo em [docs/threat-model.md](docs/threat-model.md).

## Como rodar localmente

Pré-requisitos:

- Node.js 24+
- pnpm 10+
- Rust 1.94+
- Windows: Build Tools/MSVC com `link.exe`; os scripts opcionais tentam localizar `vcvars64.bat` via `vswhere`
- PostgreSQL e Redis para operação com drivers reais

Instalação e validação:

```bash
pnpm install
pnpm run typecheck
pnpm run native:build:optional
pnpm test
```

Desenvolvimento:

```bash
pnpm run dev:api
pnpm run dev:admin
```

Modo de onboarding sem serviços externos:

```bash
ALLOW_NATIVE_FALLBACK=true
STORAGE_DRIVER=memory
SESSION_DRIVER=memory
ENABLE_DEMO_SEED=true
```

Em produção, não use fallback nativo como padrão.

## Scripts principais

- `pnpm run dev`: inicia API e admin demo em paralelo.
- `pnpm run dev:api`: inicia apenas a API.
- `pnpm run dev:admin`: inicia apenas o admin demo.
- `pnpm run typecheck`: valida o monorepo TypeScript.
- `pnpm run test:ts`: roda testes unitários e de integração TypeScript.
- `pnpm run native:build`: compila o binding N-API.
- `pnpm run native:build:optional`: tenta compilar o binding nativo e pula com aviso se faltar toolchain.
- `pnpm run native:test`: roda testes Rust dos crates internos.
- `pnpm test`: roda testes TypeScript e testes Rust opcionais.
- `pnpm run build`: build TypeScript e build nativo.

## Verificação atual

Este projeto foi validado localmente com:

- `pnpm run build:ts`
- `pnpm run build` usando MSVC via `vcvars64.bat`
- `pnpm test`
- Smoke test direto do binding N-API

Resultado esperado: typecheck, build da API, build do admin demo, build Rust/N-API e testes principais passando.

## Variáveis de ambiente

Veja [`.env.example`](.env.example) e [docs/configuration.md](docs/configuration.md).

Variáveis importantes:

- `NODE_ENV`
- `DATABASE_URL`
- `REDIS_URL`
- `STORAGE_DRIVER`
- `SESSION_DRIVER`
- `ALLOW_NATIVE_FALLBACK`
- `SECURE_COOKIES`
- `SESSION_SECRET`
- `CSRF_SECRET`
- `RISK_BLOCK_THRESHOLD`
- `RISK_CHALLENGE_THRESHOLD`

## Integração em sites reais

- Use a API como camada central de identidade, sessão e políticas.
- Preserve cookies com `credentials: "include"` em SPAs.
- Envie `x-csrf-token` em métodos que alteram estado.
- Não replique autorização apenas no frontend.
- Aplique autorização server-side em toda rota protegida.
- Revise CSP e CORS para o domínio real da aplicação.
- Mantenha logs sem segredos e com correlation IDs.

Detalhes em [docs/integration.md](docs/integration.md).

## Como estudar o projeto

Ordem recomendada:

1. [docs/architecture.md](docs/architecture.md)
2. [docs/threat-model.md](docs/threat-model.md)
3. [packages/contracts](packages/contracts)
4. [packages/security-core-ts](packages/security-core-ts)
5. [apps/api/src/index.ts](apps/api/src/index.ts)
6. [packages/auth](packages/auth)
7. [packages/session](packages/session)
8. [packages/authorization](packages/authorization)
9. [packages/rate-limit](packages/rate-limit)
10. [native/crates](native/crates)
11. [docs/operation.md](docs/operation.md)
12. [docs/incident-response.md](docs/incident-response.md)

## Documentação

- [Arquitetura](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Configuração](docs/configuration.md)
- [Integração](docs/integration.md)
- [Operação](docs/operation.md)
- [Checklist de hardening](docs/hardening-checklist.md)
- [Resposta a incidentes](docs/incident-response.md)
- [Guia de estudo](docs/study-guide.md)
- [FAQ técnico](docs/faq.md)

## Limitações conhecidas

- O sistema reduz risco, mas não elimina risco.
- O motor de inspeção é heurístico e não pretende ser um WAF universal.
- MFA TOTP está em baseline didático; produção deve proteger segredos com secret management adequado.
- O modo memória é útil para estudo e testes, mas produção deve usar PostgreSQL e Redis.
- Docker está presente como artefato do projeto, mas a validação depende de Docker disponível na máquina.
- Políticas, thresholds e alertas precisam de tuning conforme tráfego real.

## Checklist rápido de hardening

- HTTPS obrigatório em produção.
- Cookies seguros ativados.
- Segredos fortes, fora do código e rotacionáveis.
- Debug desativado em produção.
- CORS mínimo e explícito.
- CSP revisada para o frontend real.
- Rate limits ajustados por rota e risco.
- Painel administrativo protegido por permissões específicas.
- Logs sem senhas, tokens ou segredos.
- Auditoria ativa para ações sensíveis.
- PostgreSQL e Redis com credenciais fortes.
- Dependências auditadas.
- Testes passando antes de release.
