# Hardening Checklist

- HTTPS obrigatório em produção
- `SECURE_COOKIES=true`
- `ALLOW_NATIVE_FALLBACK=false` em produção
- PostgreSQL e Redis protegidos por rede e credenciais fortes
- debug desativado
- CORS mínimo
- CSP revisada para o app real
- segredos fora do código
- logs sem vazamento de segredos
- painéis administrativos revisados e monitorados
- rate limits calibrados
- dependências auditadas
- typecheck e testes passando
- policies revisadas antes de release

