# ADR 0002 — Caddy em vez de Traefik

- Status: Aceito
- Data: 2026-10-15

## Contexto

Requisito central: aceitar domínios arbitrários de lojistas com HTTPS
automático, sem cadastro prévio, mas com autorização. O Traefik só emite
certificados para hosts presentes nas regras de roteamento.

## Decisão

Caddy 2.11.x como proxy de borda, usando **On-Demand TLS** com o módulo de
permissão HTTP (`ask`) apontando para o `hangard`. Configuração exclusivamente
pela Admin API em JSON via unix socket.

## Consequências

- Domínios dinâmicos viram recurso nativo, sem gambiarra.
- Autorização centralizada no Hangar + aplicação (fail-closed).
- Perdemos a descoberta por labels do Traefik — irrelevante, porque o Hangar
  gera a configuração inteira a partir do seu banco.
- HTTP/3, OCSP stapling e renovação automática vêm de graça.
- Primeira visita de um domínio novo demora alguns segundos (emissão).

## Segurança: Caddy × Traefik

Os dois têm nível de segurança equivalente. A escolha é pelo recurso de
domínios dinâmicos, não porque um seja "mais seguro" que o outro.

| Aspecto | Caddy | Traefik |
|---|---|---|
| Linguagem | Go (memory-safe) | Go (memory-safe) |
| Maturidade / uso | Muito usado em produção, inclusive por SaaS com domínio de cliente | Muito usado, padrão em Easypanel/Coolify/Dokploy |
| Histórico de CVEs | Tem (ex.: 2.11.1 corrigiu mTLS fail-open e bypass de path matcher) | Tem (vários ao longo das versões 2.x/3.x) |
| HTTPS por padrão | Sim, sempre; TLS moderno, OCSP stapling | Precisa configurar resolver e routers |
| Domínio desconhecido | On-Demand TLS **com autorização** (`ask`) | Não emite; cai no certificado autoassinado |
| Superfície administrativa | Admin API (por padrão em `localhost:2019`); **no Hangar fica num unix socket** | Dashboard/API; perigoso se exposto. Com provider Docker costuma montar `docker.sock` |
| Configuração | JSON único gerado pelo Hangar (fonte da verdade no banco) | Labels/arquivos espalhados |

O risco específico do Caddy é o On-Demand TLS sem `ask`. Esse risco é tratado
de forma explícita em [03](../03-dominios-customizados-tls.md): autorização pela
aplicação, fail-closed e limite de emissões.

Em qualquer um dos dois, a regra é a mesma: ficar sempre na última versão de
correção (patch).
