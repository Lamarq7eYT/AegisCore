# Resposta a Incidentes

## Detecção

- use `SecurityEvent` e auditoria para identificar abuso, login anômalo, bloqueios e falhas de authz.

## Contenção

- revogue sessões;
- aumente thresholds e cooldowns;
- desabilite contas/credenciais comprometidas;
- coloque uploads suspeitos em quarentena.

## Erradicação

- corrija a causa raiz;
- remova segredos expostos;
- atualize dependências ou policies comprometidas.

## Recuperação

- restaure operação com monitoramento reforçado;
- valide rotas críticas e fluxos de auth antes de reabrir tráfego.

## Pós-incidente

- preserve evidências;
- documente timeline, impacto, ações e melhorias;
- transforme achados em testes de regressão e checklist.

