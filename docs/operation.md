# Operação

## Observabilidade

- logs estruturados via Pino;
- `correlationId` por requisição;
- métricas em memória no baseline;
- `SecurityEvent` para abuso, bloqueios e anomalias;
- `AuditEntry` para decisões e ações relevantes.

## O que monitorar

- picos de `request.blocked.rate_limit`;
- aumento de `auth.login.failed`;
- crescimento de `request.blocked.csrf`;
- uploads rejeitados;
- acessos administrativos negados ou desafiados.

## Rotina operacional mínima

1. revisar logs e eventos críticos diariamente;
2. recalibrar thresholds conforme comportamento real;
3. revisar permissões de rotas administrativas;
4. manter dependências e policies sob revisão;
5. revalidar CSP/CORS em mudanças de frontend.

