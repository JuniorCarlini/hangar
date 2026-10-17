# 11 — API

A interface usa os mesmos handlers (HTMX pede HTML; clientes pedem JSON via
`Accept: application/json`). Tokens de API (pós-MVP) com escopo e expiração,
guardados como hash.

## Convenções

- Prefixo `/api/v1`. JSON em `snake_case`.
- Erros: `{"error": {"code": "service_not_found", "message": "..."}}` +
  status HTTP coerente. Nunca vazar stack trace ou SQL.
- Toda rota de escrita: autenticada, CSRF (para cookie), auditada.
- 🔒 = exige modo sudo.

## Rotas

```
POST   /auth/login                      senha → pede 2º fator
POST   /auth/2fa                        TOTP/recuperação
POST   /auth/webauthn/{begin,finish}
POST   /auth/sudo                       reautenticação
POST   /auth/logout
GET    /auth/sessions | DELETE /auth/sessions/{id}

GET    /api/v1/server                   info do host, versões, uso
GET    /api/v1/projects | POST
GET    /api/v1/projects/{id} | PATCH | DELETE 🔒

GET    /api/v1/projects/{id}/services | POST
GET    /api/v1/services/{id} | PATCH | DELETE 🔒
POST   /api/v1/services/{id}/{start,stop,restart}
GET    /api/v1/services/{id}/env | PUT          (segredos mascarados)
GET    /api/v1/services/{id}/env/{key}/reveal 🔒
POST   /api/v1/services/{id}/deployments        novo deploy
GET    /api/v1/services/{id}/deployments
POST   /api/v1/deployments/{id}/rollback
GET    /api/v1/deployments/{id}/log             (SSE se em andamento)
GET    /api/v1/services/{id}/logs?tail=&since=&q=   (SSE com follow=1)
GET    /api/v1/services/{id}/metrics?range=1h|24h|7d|90d
GET    /api/v1/services/{id}/terminal 🔒       WebSocket (docker exec)

GET    /api/v1/services/{id}/domains | POST | DELETE /api/v1/domains/{id}
GET    /api/v1/tls/dynamic               certificados emitidos + negações recentes
POST   /api/v1/tls/blocklist | DELETE 🔒

GET    /api/v1/templates
GET    /api/v1/backups/... (targets, policies, runs) | POST /api/v1/backup-runs/{id}/restore 🔒
GET    /api/v1/audit?user=&action=&from=&to=
GET    /api/v1/users | POST 🔒 | DELETE 🔒

GET    /api/v1/updates?project=&severity=   pendências de atualização/vulnerabilidade
POST   /api/v1/updates/{id}/ignore
POST   /api/v1/updates/scan                 força uma varredura
GET    /api/v1/notify/channels | POST | DELETE   (Telegram, e-mail, webhook)
POST   /api/v1/notify/channels/{id}/test
GET    /api/v1/status-links | POST | DELETE /api/v1/status-links/{id} 🔒
GET    /api/v1/projects/{id}/links | POST | DELETE   conectar projetos
GET    /api/v1/services/{id}/ports | POST | DELETE   portas expostas
GET    /api/v1/ports                        todas as portas abertas no servidor
GET    /api/v1/services/{id}/backup/download 🔒   pg_dump direto pelo navegador

POST   /hooks/git/{token}                webhook (sem sessão; assinatura obrigatória)
```

## Painel (HTML) — alertas e modo trancado (Etapa 8)

As telas usam rotas próprias, com a mesma política (papel, auditoria, sudo):

```
GET    /alerts                              histórico, canais, regras, entregas (Leitor+)
POST   /alerts/seen                         marca os alertas como vistos (sino)
POST   /alerts/channels                     novo canal (Admin+)
POST   /alerts/channels/{id}/test           mensagem de teste (Admin+)
POST   /alerts/channels/{id}/reveal 🔒      token/senha/segredo em claro (Admin+)
POST   /alerts/channels/{id}/toggle 🔒      pausar/retomar (Admin+)
POST   /alerts/channels/{id}/delete 🔒      remover (Admin+)
POST   /alerts/rules                        regras do servidor (Admin+)
POST   /alerts/mute                         silenciar alertas do servidor (Admin+)
POST   /lock                                trancar o painel (Dono)
```

## Listener público de status (rotas isoladas, somente leitura)

```
GET    /s/{token}                        HTML (?tv=1 para modo quiosque)
GET    /s/{token}.json
GET    /s/{token}/metrics                Prometheus
```

## Listener interno (não passa pelo Caddy público)

```
GET    /internal/tls/ask?domain=X        200 = pode emitir; qualquer outro = não
```
