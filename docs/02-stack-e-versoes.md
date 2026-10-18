# 02 — Stack e versões

> Regra: **sempre a última versão estável** de cada peça no momento do
> bootstrap, fixada (pinned) no repositório. Atualizações passam por PR com
> changelog lido. Versões abaixo foram levantadas em 15/out/2026 — confirme no
> link oficial antes de fixar.

## Painel (`hangard`)

| Peça | Escolha | Versão-alvo | Por quê |
|---|---|---|---|
| Linguagem | **Go** | 1.27.x (se ainda não houver, 1.26.x) — [go.dev/doc/devel/release](https://go.dev/doc/devel/release) | Binário estático único, ~20–40 MB de RAM, mesmo ecossistema de Docker e Caddy. Ver [ADR 0001](adr/0001-linguagem-go.md) |
| HTTP | `net/http` da stdlib (roteamento com padrões de método/caminho) | stdlib | Sem framework; menos dependências = menos superfície de ataque |
| Docker | SDK oficial (`github.com/moby/moby/client`) | compatível com Engine 29.x | API completa: containers, redes, volumes, stats, logs, exec |
| Banco | SQLite via `modernc.org/sqlite` (puro Go, sem CGO) | última | Zero serviço extra; backup = copiar um arquivo. Ver [ADR 0003](adr/0003-sqlite.md) |
| Queries | `sqlc` (gera Go tipado a partir de SQL) | última | SQL explícito, sem ORM, sem SQL injection por construção |
| Migrações | `pressly/goose` (embutidas no binário) | última | Migração automática e versionada no boot |
| Templates HTML | `a-h/templ` | última | HTML tipado e compilado, escape automático (anti-XSS) |
| Interatividade | HTMX + **Tucano** (biblioteca própria, sem dependências) — embutidos no binário | HTMX última; Tucano 0.38.x | Sem build de SPA, sem Node em produção. Ver [18](18-design-system.md) |
| Fontes | Geist + Geist Mono (SIL OFL), woff2 embutido | última | |
| Ícones | Lucide (ISC), sprite SVG | última | |
| CSS | Tailwind CSS (CLI standalone, só em build) | v4.x | CSS final pequeno, embutido |
| Gráficos | uPlot | última | ~50 KB, rápido para séries temporais |
| Terminal web | xterm.js | última | Padrão de mercado |
| Senhas | `golang.org/x/crypto/argon2` (argon2id) | última | Recomendação OWASP atual |
| 2FA | `pquerna/otp` (TOTP) + `go-webauthn/webauthn` (passkeys) | última | |
| Criptografia de segredos | XChaCha20-Poly1305 (`golang.org/x/crypto`) | última | AEAD, nonce de 24 bytes aleatório seguro |
| Logs do painel | `log/slog` (stdlib), JSON | stdlib | |
| Config | TOML (`pelletier/go-toml/v2`) | última | |
| Inventário de dependências | OSV-SCALIBR (`google/osv-scalibr`), só os extratores de pacotes | última | Lê a imagem de cada serviço em todas as linguagens (SO, PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet, Packagist...). Ver [14](14-atualizacoes-de-dependencias.md) |

## Infra no servidor

| Peça | Versão-alvo | Observação |
|---|---|---|
| SO | Debian 13 (trixie) ou Ubuntu 26.04 LTS | Kernel com cgroups v2 |
| Docker Engine | 29.x mais recente — [release notes](https://docs.docker.com/engine/release-notes/29/) | Houve correções de segurança relevantes em 29.3.1 e 29.5.1; nunca ficar atrás |
| Caddy | 2.11.x mais recente (2.11.7 em out/2026) — [releases](https://github.com/caddyserver/caddy/releases) | 2.11.1 corrigiu falhas de mTLS fail-open e bypass de path matcher |
| BuildKit | o que vem com o Docker 29 | Builds com cache |
| Railpack | última | Build sem Dockerfile (sucessor do Nixpacks) — opcional |

## Imagens dos serviços (templates)

| Serviço | Imagem padrão |
|---|---|
| PostgreSQL | `postgres:18-alpine` (ou a major mais nova disponível) |
| Redis | `redis:8-alpine` |
| Valkey | `valkey/valkey:<major mais nova>-alpine` |
| MySQL / MariaDB | `mysql:<lts>` / `mariadb:<lts>` |
| MongoDB | `mongo:<major mais nova>` |

Todas as imagens são fixadas por **digest** (`@sha256:...`) no momento da
criação do serviço, para que um `pull` futuro não troque a imagem por baixo.

## Ferramentas de desenvolvimento

- `golangci-lint` (v2), `gofumpt`, `govulncheck`, `staticcheck` (via golangci).
- `just` como task runner.
- `goreleaser` para gerar binários (linux/amd64, linux/arm64) com checksum e
  assinatura (cosign).
