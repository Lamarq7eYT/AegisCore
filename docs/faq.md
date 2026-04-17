# FAQ Técnico

## O projeto é um WAF?

Não. Ele usa inspeção defensiva e score de risco para endurecer a aplicação, mas não tenta substituir um WAF dedicado.

## Posso rodar sem PostgreSQL e Redis?

Sim, para estudo e testes locais, usando `memory`. Em produção, use `prisma` + `redis`.

## Posso rodar sem o binding Rust?

Em dev/teste, sim, com `ALLOW_NATIVE_FALLBACK=true`. Em produção, o ideal é manter o binding ativo.

## O MFA está pronto para produção?

Como baseline didático, sim. Para produção real, proteja o segredo TOTP com KMS/HSM ou envelope encryption.

## Por que não usar JWT como padrão?

Sessão stateful com cookie seguro simplifica revogação, rotação, CSRF e controle fino em apps web first-party.

