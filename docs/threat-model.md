# Threat Model

## Ativos protegidos

- credenciais e segredos de autenticação;
- sessões e cookies;
- dados sensíveis em APIs e painéis;
- trilhas de auditoria e evidências;
- uploads e metadados;
- políticas de autorização;
- disponibilidade operacional da API.

## Atores de ameaça

- atacantes externos oportunistas;
- operadores automatizados e credential stuffers;
- usuários autenticados abusando de permissões;
- insiders mal configurando políticas ou expondo segredos;
- cadeia de suprimentos comprometida.

## Superfícies de ataque

- rotas REST públicas e privadas;
- endpoints de login, reset e MFA;
- painel administrativo;
- upload multipart;
- CORS e cookies;
- dependências e pipeline;
- configuração por ambiente.

## Priorização por risco

| Prioridade | Ameaças | Controles planejados | Risco residual |
| --- | --- | --- | --- |
| Crítica | Broken access control, IDOR/BOLA, hijacking/fixation, credential stuffing, brute force, token theft, admin abuse | sessão opaca, rotação, authz deny-by-default, RBAC+ABAC, rate limit multidimensional, auditoria | precisa tuning contínuo e revisão de rota |
| Alta | SQLi, XSS refletido/armazenado/DOM, CSRF, SSRF, traversal, upload abuse, improper CORS, secret leakage | validação Zod, normalização, CSP, CSRF token, headers, upload guard, logs redacted | heurísticas e CSP exigem revisão por app real |
| Média | race conditions, cache abuse, dependency compromise, misconfiguration, improper logging, unsafe deserialization | defaults seguros, checklist de hardening, CI, auditoria de dependências, logs estruturados | depende da maturidade operacional |

## Cobertura de ameaças do briefing

- Injeção: SQL Injection, NoSQL Injection, command injection, template injection, unsafe deserialization
- Navegador: XSS refletido, armazenado e DOM, CSRF, clickjacking, open redirect
- Arquivos e caminhos: LFI, RFI, path traversal, file upload abuse, MIME spoofing, double extension
- Identidade e sessão: session fixation, session hijacking, credential stuffing, brute force, enumeração, token theft, JWT misuse, replay
- Acesso: broken access control, IDOR/BOLA, mass assignment
- Integração e rede: SSRF, webhook abuse, improper CORS, cache abuse
- Operação: sensitive data exposure, secret leakage, improper logging, rate-limit bypass, dependency compromise, poisoned packages, admin panel abuse, misconfiguration

## Assunções operacionais

- TLS é obrigatório em produção.
- Cookies seguros e HSTS só fazem sentido sob HTTPS.
- Banco e Redis são provisionados fora do processo da app.
- O painel admin fica atrás de identidade forte e inventário restrito de operadores.
- O binding nativo é compilado e distribuído como parte do release de produção.

