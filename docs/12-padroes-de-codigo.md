# 12 — Padrões de código

## Layout do repositório

```
hangar/
├── cmd/
│   ├── hangard/            o painel: serve, user, lockdown, secrets, restore, self-update, system, audit, version
│   ├── hangar-cofre/       ferramenta de backup do computador do operador
│   └── hangar-release/     gera a chave e assina as releases (CI)
├── internal/
│   ├── app/                composição: monta dependências e sobe os servidores
│   ├── auth/               senhas, TOTP, sessões, papéis, sudo
│   ├── audit/              log de auditoria encadeado
│   ├── alerts/             regras, canais (Telegram, e-mail, webhook), alertas de segurança
│   ├── backup/             dumps testados, WAL, destinos S3 com Object Lock
│   ├── cofre/              lógica do hangar-cofre e da restauração fora do painel
│   ├── config/             leitura/validação do hangar.toml
│   ├── deps/               monitor de dependências e vulnerabilidades (OSV.dev)
│   ├── docker/             implementação de node.Node sobre o Docker Engine (labels/hardening)
│   ├── edge/               Caddy: configuração, contêiner, endpoint ask
│   ├── firewall/           portas publicadas restritas por IP (DOCKER-USER)
│   ├── gitsrc/             clone de repositórios (go-git, só HTTPS)
│   ├── i18n/               catálogos de idioma (locales/*.toml)
│   ├── ids/                identificadores com prefixo de tipo
│   ├── lockdown/           Trancar painel
│   ├── metrics/            coletores, ring buffer, downsampling
│   ├── netguard/           filtro anti-SSRF
│   ├── node/               interface Node (operações de container); impl. local agora, agente depois
│   ├── projects/           projetos, serviços, variáveis, domínios, deploys, credenciais Git
│   ├── release/            descrição e verificação das releases assinadas
│   ├── secrets/            cifra de segredos (chave mestra, AEAD, rotação)
│   ├── statuspage/         links públicos de status
│   ├── store/              abertura do SQLite + migrações embutidas
│   │   ├── migrations/     *.sql (goose)
│   │   ├── queries/        *.sql (sqlc)
│   │   └── dbq/            código gerado pelo sqlc (não editar)
│   ├── templates/          catálogo de templates (pastas compose + toml, sync assinado)
│   ├── update/             atualização com um clique
│   ├── chaos/              testes de caos (só com a tag integration)
│   └── web/                handlers HTTP, middlewares, views templ, assets embutidos
├── deploy/                 install.sh, units do systemd
├── e2e/                    testes Playwright
├── examples/               app de laboratório (domínios dinâmicos)
├── tools/                  tailwind.sh, painel de laboratório, teste de carga
├── docs/
├── justfile
├── go.mod
└── .golangci.yml
```

Regra de dependência: `web` → domínio (`deploy`, `edge`, `auth`...) → `store`/`docker`.
Pacotes de domínio não importam `web`. Nada fora de `docker` importa o SDK do Docker,
e o domínio fala com containers **só** pela interface `node.Node` (pré-requisito
para multi-servidor).

## Estilo Go

- `gofumpt` + `goimports`; `golangci-lint` v2 com: `govet`, `staticcheck`,
  `errcheck`, `gosec`, `revive`, `bodyclose`, `noctx`, `sqlclosecheck`,
  `errorlint`, `contextcheck`.
- Erros: retornar e embrulhar com contexto (`fmt.Errorf("criar rede %s: %w", nome, err)`).
  Sem `panic` fora de `main`/init de programa inválido.
- `context.Context` como primeiro parâmetro em tudo que faz I/O; timeouts
  explícitos em toda chamada externa (Docker, Caddy, app, S3, ACME).
- Interfaces pequenas, definidas **no lado de quem consome**.
- Sem variáveis globais mutáveis; dependências por construtor.
- Logs com `slog`, estruturados; nunca logar segredo (tipo `Secret` com
  `LogValue()` que retorna `"[redacted]"`).
- **Idioma (padrão inglês):**

  | Em inglês | Em português |
  |---|---|
  | Nomes no código (pacotes, tipos, funções, variáveis) | Textos das telas |
  | **Comentários** e mensagens de teste | Mensagens de erro mostradas ao usuário (tela e CLI) |
  | Rotas (`/projects`, `/update`, `/env/reveal`) e campos de formulário | Saída da linha de comando (`hangard user create`…) |
  | Banco: tabelas, colunas e valores gravados (`running`, `create`, `missing`) | Comentários do `hangar.toml` gerado pelo instalador |
  | Auditoria: ações e chaves do resumo (`secret.reveal`, `reason`) | Docs e mensagens de commit |
  | Logs: mensagens e chaves (`"deploy failed", "error"`) | |
  | Comentários de CSS, JS, units do systemd, scripts, CI | |

  Valor gravado em inglês que aparece na tela passa por uma função de rótulo
  na view (ex.: `triggerLabel("create")` → "criação").

  Desde a Etapa 3b, os textos da coluna "em português" vêm dos catálogos de
  idioma (`internal/i18n/locales/*.toml`, [22](22-idiomas-e-temas.md)): o
  código usa chaves em inglês (`t(ctx, "login.title")`, `i18n.E("...")`) e o
  texto sai no idioma do usuário. Nenhum texto de tela é escrito direto no
  template ou no handler: o CI falha se isso acontecer.

## Testes

- Unitários com a stdlib (`testing`) + tabelas de casos.
- Integração (`//go:build integration`) contra Docker real e Caddy real em CI,
  usando Pebble como ACME de teste.
- Obrigatório ter teste para: endpoint `ask`, autenticação/sessão, cifra de
  segredos, geração da config do Caddy (golden files), hardening aplicado aos
  containers.
- `go test -race` no CI.

## Git

- Branch principal `main`, protegida; trabalho em branches curtas + PR.
- Mensagens **em português**, com um título curto que diz o que muda para quem
  usa e um corpo explicando **por que** a mudança existe. Sem prefixo
  Conventional Commits e sem trailers de atribuição.
- Toda decisão de arquitetura relevante vira um ADR em `docs/adr/`.

## CI (GitHub Actions)

`ci.yml`, em todo push no `main` e em PR (o mesmo que `just check`):

1. `golangci-lint run`
2. `go test -race ./...`
3. testes de integração com Docker real (`internal/docker`, `internal/alerts`)
4. `govulncheck ./...`
5. `sqlc diff`, páginas templ e `app.css` em dia
6. build para Linux amd64 e arm64
7. E2E com Playwright (opcional, não bloqueia)

`release.yml`, em tag `vX.Y.Z` ([21](21-atualizacao-do-painel.md)), em jobs
separados para a chave de release nunca estar perto de código de teste ou de
terceiros:

1. `gate`: a tag aponta para um commit da `main` e o CI desse commit passou;
2. `edge-image`: imagem do Caddy do edge; reaproveita a de antes só se o
   binário assinado da release anterior já cita aquele digest;
3. `build`: testes, binários `hangard-linux-{amd64,arm64}`, `install.sh` e
   `SHA256SUMS`, sem nenhum segredo;
4. `sign`: único job com `HANGAR_RELEASE_KEY`, no environment `release`.
   Confere o artefato contra o hash que o `build` passou como saída, compila
   o `hangar-release` do código da tag e gera `release.json` (SHA-256 de cada
   binário) e `release.json.sig` (Ed25519);
5. `publish`: confere a assinatura de novo e cria a release.

`vulncheck.yml` roda o `govulncheck` toda segunda-feira, para aviso novo não
esperar o próximo push. O Dependabot cobre actions, módulos Go e as imagens
dos Dockerfiles.

## Dependências

- Antes de adicionar uma dependência: dá para fazer com a stdlib em < 100 linhas?
  Se sim, não adicionar.
- `go.mod` com versões fixadas; Dependabot/Renovate semanal; ler changelog
  antes de aprovar.
