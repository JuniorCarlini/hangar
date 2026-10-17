# 01 — Arquitetura

## Visão de componentes

```
                Internet
                   │  :80 / :443 (únicas portas públicas além do SSH)
                   ▼
        ┌─────────────────────┐
        │  Caddy (container)  │  TLS automático + on-demand TLS
        │  rede: hangar-edge  │  config via Admin API (unix socket)
        └──────┬───────┬──────┘
               │       │  "posso emitir cert para X?"  ──►  hangard /internal/tls/ask
   ┌───────────┘       └───────────┐
   ▼                               ▼
 painel.seudominio.com        lojas (qualquer domínio)
   │                               │
   ▼                               ▼
┌──────────────┐          ┌───────────────────────┐
│   hangard    │          │ projeto "lojas"       │
│ (systemd,    │          │  app-django  ◄─┐      │  rede: proj-lojas (interna)
│  host)       │──Docker──►  postgres     │      │
│ 127.0.0.1    │  socket  │  redis        ┘      │
│ :7700        │          └───────────────────────┘
│ SQLite       │          ┌───────────────────────┐
└──────────────┘          │ projeto "outro"       │  rede: proj-outro (interna)
                          │  app, postgres, redis │
                          └───────────────────────┘
```

## Componentes

### `hangard` (o painel)

- Binário Go único, roda como serviço **systemd no host** (não em container).
  Motivo: ele precisa do socket do Docker; rodar fora de container evita o
  padrão perigoso de montar `/var/run/docker.sock` dentro de um container
  exposto à internet.
- Nunca escuta em IP público. Listeners:
  - `127.0.0.1:7700` — painel, para acesso via túnel SSH/WireGuard (modo bunker).
  - `172.30.0.1:7700` — painel, no gateway da rede `hangar-edge`, para o Caddy
    publicar em `painel.seudominio.com` (opcional; ver [04](04-seguranca.md)).
  - `172.30.0.1:7701` — **somente** `/internal/tls/ask` (ver [03](03-dominios-customizados-tls.md)).
  - Os listeners no gateway aceitam conexões **apenas** do IP fixo do Caddy
    (`172.30.0.2`), checado no código e reforçado por regra nftables.
- Usuário de sistema dedicado `hangar`, membro do grupo `docker`. Unit systemd
  com sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=yes`, etc.).
- Estado em `/var/lib/hangar/hangar.db` (SQLite) e chave mestra em
  `/etc/hangar/master.key` (0400).
- Interface web, API, coletor de métricas, streaming de logs, agendador
  (backups, limpeza) — tudo no mesmo processo, em goroutines.

### Caddy (proxy de borda)

- Container gerenciado pelo próprio Hangar (`hangar-caddy`), com as portas 80 e
  443 publicadas (TCP e UDP/443 para HTTP/3).
- Configurado **somente via Admin API JSON**, exposta em um unix socket num
  volume compartilhado com o host (`/run/hangar/caddy/admin.sock`). Nunca em
  porta TCP.
- O Hangar é a fonte da verdade: a cada mudança, gera a configuração completa e
  faz `POST /load`. Se o Caddy reiniciar, o Hangar reenvia.
- Certificados persistidos no volume `hangar-caddy-data`.

### Docker Engine

- Instalado a partir do repositório oficial da Docker.
- `daemon.json` endurecido (ver [05](05-isolamento-e-recursos.md)).

## Redes

| Rede | Quem participa | Propósito |
|---|---|---|
| `hangar-edge` (subnet fixa `172.30.0.0/24`, gateway `.1`, Caddy em `.2`) | Caddy + serviços que têm domínio | Tráfego HTTP de entrada; Caddy fala com o `hangard` pelo gateway |
| `hangar_<slug>` (bridge comum, com saída para a internet) | Todos os serviços de um projeto (+ projetos conectados) | Comunicação interna (app ↔ postgres ↔ redis). Projetos diferentes ficam em bridges diferentes e não se enxergam (validado em teste de integração) |

- Modelo de containers igual ao do Easypanel: nomes `<projeto>_<serviço>`,
  aba "Portas" para expor qualquer porta, e projetos que podem se enxergar
  quando você conecta um ao outro ([05](05-isolamento-e-recursos.md),
  [ADR 0006](adr/0006-modelo-de-containers-easypanel.md)).
- Bancos e caches não entram em `hangar-edge` (não recebem tráfego HTTP do
  proxy). Expor porta de banco é uma ação sua, com opção de restringir por IP
  e regra real no firewall.

## Fluxo de uma requisição para uma loja

1. Cliente acessa `https://minhaloja.com.br`.
2. DNS do lojista aponta para o IP da VPS.
3. Caddy recebe o handshake TLS. Não tem certificado para esse nome.
4. Caddy chama `GET http://172.30.0.1:7701/internal/tls/ask?domain=minhaloja.com.br`.
5. Hangar valida (ver [03](03-dominios-customizados-tls.md)): formato, cache,
   pergunta à aplicação Django se o domínio pertence a uma loja ativa.
6. Se `200`, o Caddy emite o certificado (Let's Encrypt, fallback ZeroSSL),
   guarda e conclui o handshake. Se não, recusa.
7. Caddy faz proxy para `app-django:8000` na rede `hangar-edge`, preservando
   `Host` e definindo `X-Forwarded-*`.
8. O Django identifica a loja pelo `Host`.

## Fluxo de um deploy

Ver [07](07-deploy-e-builds.md). Resumo: build/pull → container novo sobe →
healthcheck passa → Caddy troca o upstream → container antigo para.

## Layout no disco do servidor

```
/usr/local/bin/hangard           binário
/etc/hangar/hangar.toml          configuração
/etc/hangar/master.key           chave de criptografia (0400 hangar:hangar)
/var/lib/hangar/hangar.db        estado do painel
/var/lib/hangar/builds/          workspace de builds (limpo após cada build)
/var/lib/hangar/backups/         staging local de backups
/run/hangar/caddy/               socket da Admin API do Caddy (montado no container)
```
