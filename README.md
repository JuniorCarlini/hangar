# Hangar

Painel self-hosted para rodar aplicações em containers numa VPS, no estilo do
Railway, Easypanel e Coolify, em **um binário Go só**. O diferencial é o
**HTTPS automático nos domínios dos clientes**: o lojista aponta o próprio
domínio para o servidor e a loja abre com certificado válido, sem ninguém
cadastrar nada, porque a própria aplicação autoriza cada domínio antes de o
certificado ser emitido.

O Hangar nasceu para tirar um SaaS multi-loja do Easypanel, onde isso só saía
com gambiarra no Traefik, e hoje hospeda qualquer projeto do operador (sites,
APIs, bots), cada um isolado no seu projeto. Segurança vem fechada por padrão:
o painel não escuta na internet, 2FA é exigida e toda ação fica numa
auditoria encadeada.

> Versão atual: **v0.5.19**. Projeto em desenvolvimento ativo: use, teste e
> reporte, mas leia as [notas de cada versão](CHANGELOG.md) antes de atualizar.

## Sumário

- [Recursos](#recursos)
- [Instalação](#instalação)
- [Primeiros passos](#primeiros-passos)
- [Configuração](#configuração)
- [Operação](#operação)
- [Segurança](#segurança)
- [Desenvolvimento](#desenvolvimento)
- [Documentação](#documentação)
- [Licença](#licença)

## Recursos

- **Domínios dos clientes com HTTPS sob demanda** — Caddy emite o certificado
  só depois que a app confirma, por chamada assinada (HMAC), que o domínio é
  de um cliente ativo; limite por hora e bloqueio manual. ([03](docs/03-dominios-customizados-tls.md))
- **Canvas de serviços** — projetos com vários serviços, ligações entre eles
  por referência (`${{db.DATABASE_URL}}`), métricas e deploy ao vivo no card.
- **Templates de um clique** — PostgreSQL, MariaDB, MongoDB, Redis e Valkey
  (cache ou filas), RabbitMQ, Meilisearch, RustFS (S3), n8n, Uptime Kuma,
  pgAdmin e Adminer, já endurecidos. Os de administração nascem internos.
  ([08](docs/08-servicos-templates.md))
- **Links automáticos com HTTPS sem domínio** — cada porta pública ganha um
  endereço `projeto-servico.IP.sslip.io` com certificado de verdade; com
  domínio próprio, um subdomínio dele (curinga via DNS-01). Nada vai para a
  internet sem senha confirmada. ([28](docs/28-endpoints-web-e-dominios-automaticos.md))
- **Build por Git** — clone HTTPS dentro do processo, build com BuildKit,
  segredos mascarados no log e deploy automático por webhook do GitHub
  (HMAC + anti-replay). ([07](docs/07-deploy-e-builds.md))
- **Credenciais Git** — o token do GitHub é guardado uma vez (no servidor ou
  num projeto) e escolhido por serviço; trocar o token vale para todos no
  próximo deploy.
- **Deploy sem downtime e rollback em segundos** — imagem fixada por ID, sem
  rebuild para voltar.
- **Backups que o servidor não consegue apagar** — dumps testados antes do
  envio, WAL contínuo (volta até o minuto), cifra **age** com chave que só
  você tem e S3 com **Object Lock**. ([09](docs/09-backups.md))
- **Alertas** por Telegram, e-mail e webhook assinado; os de segurança não
  dá para desligar. ([06](docs/06-monitoramento-e-logs.md))
- **Links públicos de status** (página, modo TV, JSON, Prometheus) sem nomes,
  IPs nem versões. ([15](docs/15-painel-publico-de-status.md))
- **Monitor de vulnerabilidades** — consulta diária ao OSV.dev dos pacotes de
  cada container. ([14](docs/14-atualizacoes-de-dependencias.md))
- **Proteção de conta** — 2FA (TOTP), modo sudo para ações críticas, papéis
  (dono, admin, operador, leitor), auditoria encadeada e **Trancar painel**
  (botão de pânico que derruba todas as sessões sem tirar as lojas do ar).
- **Atualização com um clique** — release assinada (Ed25519), cópia do banco
  antes e volta automática se a versão nova não subir. ([21](docs/21-atualizacao-do-painel.md))
- **Português e inglês, tema claro/escuro/sistema**, por usuário. ([22](docs/22-idiomas-e-temas.md))

## Instalação

### Requisitos

- VPS limpa com **Debian 13** ou **Ubuntu 24.04+**, amd64 ou arm64, com systemd.
- Portas **80/tcp, 443/tcp e 443/udp** liberadas no firewall do provedor
  (Oracle, AWS, Hetzner e outros têm um firewall fora da VPS, que o Hangar não
  controla). O painel em si não precisa de porta aberta.
- Acesso root (sudo) e `openssl`/`sha256sum` (padrão nessas distros).
- O Docker é instalado pelo próprio instalador, a partir do repositório
  oficial, se ainda não existir.

### Instalar

```bash
curl -fsSL https://github.com/JuniorCarlini/hangar/releases/latest/download/install.sh | sudo bash
```

Prefere ler antes de rodar? Baixe com `curl -fsSLO ...install.sh`, leia e
rode `sudo bash install.sh`. Opções: `--version vX.Y.Z` (versão fixa),
`--from-dir diretório` (release já baixada, para servidor sem acesso ao
GitHub) e `--token-file arquivo` (token só leitura, para um fork privado).

O instalador **não instala nada sem conferir** a assinatura Ed25519 do
`release.json` e o SHA-256 do binário. Depois cria o usuário de sistema
`hangar`, configura o Docker (logs com rotação, `live-restore`), gera a chave
mestra em `/etc/hangar/master.key`, escreve `/etc/hangar/hangar.toml` (com o HTTPS e o painel público ligados
quando as portas 80/443 estão livres), sobe o serviço `hangard` e mostra o
endereço do painel. Rodar de novo é seguro: nunca
apaga dados nem a chave.

<details>
<summary>Conferir a assinatura à mão</summary>

Cada release publica `hangard-linux-amd64`, `hangard-linux-arm64`,
`install.sh`, `release.json` (versão e SHA-256 de cada binário) e
`release.json.sig` (assinatura Ed25519 em base64). A chave pública é a mesma
embutida no `install.sh` e no binário. No seu computador (OpenSSL 3):

```bash
gh release download v0.1.0 -R JuniorCarlini/hangar -p 'release.json*' -p hangard-linux-amd64
KEY=3c84b55c17438e93d4fd0a11dde9e88de3d00cf2bab5fad52589b841c6d49121
echo "302a300506032b6570032100$KEY" | xxd -r -p > pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
base64 -d < release.json.sig > release.sig
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in release.json -sigfile release.sig
shasum -a 256 hangard-linux-amd64    # tem que bater com o valor em release.json
```

</details>

### Primeiro acesso

O instalador termina mostrando o endereço do painel, já com HTTPS:

```
Painel: https://hangar.203-0-113-10.sslip.io
```

Abra e crie a **conta de dono** (e-mail, senha e verificação em duas etapas
opcional, que vem marcada) nos **30 minutos** seguintes. Passou do prazo?
`sudo systemctl restart hangard` abre mais 30. Quem criar a conta vira o
dono, e a tela some para sempre.

Se as portas 80/443 já estiverem em uso ou o IP público não for
descoberto, o painel fica só pelo túnel SSH (`ssh -L 7700:127.0.0.1:7700
usuario@servidor` e `http://localhost:7700`); ligue `[edge]` e `[panel]
public` no `hangar.toml` depois. Para usar o seu domínio no painel:
`public_host = "painel.seudominio.com"`.

Prefere o terminal? `sudo -u hangar hangard user create -config
/etc/hangar/hangar.toml -email voce@exemplo.com` cria o dono com o QR code
da 2FA no terminal, e também fecha a tela de primeiro acesso.

Depois de entrar:

- [ ] Gere o **Kit de recuperação** em Backups e cadastre um destino S3 com
      Object Lock. O backup do painel leva a chave mestra junto, trancada com
      o kit: guardando o kit, não precisa copiar nada pelo SSH. A cada 5
      meses o painel pede para você confirmar que o kit ainda está guardado.
- [ ] Cadastre um canal de alerta (Telegram, e-mail ou webhook) e teste.
- [ ] Faça o endurecimento do host que o instalador ainda não faz (SSH só por
      chave, firewall, `unattended-upgrades`, `chrony`):
      [docs/24 § 2](docs/24-operacao.md#2-instalar).

Os comandos do `hangard` rodam **como o usuário `hangar`**; como root, eles
recusam (o SQLite criaria arquivos que o serviço não consegue abrir).

## Primeiros passos

1. **Projeto** — **Novo projeto** na barra lateral. Cada projeto tem a própria
   rede Docker; projetos não se enxergam a não ser que você os conecte (com 2FA).
2. **Serviço** — no canvas, **Novo serviço**, por uma de três abas:
   - **Template**: PostgreSQL ou Redis, com volume, senha gerada e limites.
   - **Imagem Docker**: qualquer imagem pública (`nginx:1.29`, `ghcr.io/...`).
   - **Repositório Git**: URL HTTPS, branch, pasta e Dockerfile. Para
     repositório privado, escolha uma **Credencial Git** (as do projeto
     aparecem primeiro, depois as do servidor) ou **Adicionar um token novo…**.
3. **Credenciais Git** — página própria na barra lateral (e nas Configurações
   do projeto). Guarde ali um token *fine-grained* só de leitura (`Contents:
   Read-only`) uma vez: com escopo de **servidor** (qualquer projeto usa) ou de
   **um projeto**. O token fica cifrado e nunca é mostrado de novo; trocar o
   token vale para todos os serviços que usam a credencial no próximo deploy,
   e uma credencial em uso não pode ser apagada. Cada credencial só vale para
   o servidor Git em que foi criada.
4. **Variáveis** — aba Variáveis do serviço; referências como
   `${{db.DATABASE_URL}}` ligam um serviço ao outro. Valores secretos ficam
   cifrados e só aparecem com sudo.
5. **Domínio** — defina a porta interna do serviço, aponte o DNS (A/AAAA)
   para o servidor e adicione o domínio na aba Domínios: o HTTPS é automático.
   Requer `[edge] enabled = true` no `hangar.toml`. Para **domínios dos
   clientes**, ligue "Aceitar domínios dos clientes": a app responde em
   `/.well-known/hangar/domain-check` e recebe o segredo da assinatura em
   `HANGAR_DOMAIN_CHECK_SECRET` (exemplo completo em
   [`examples/lab-multidominio`](examples/lab-multidominio/README.md)).
6. **Deploy** — **Fazer deploy**. O log aparece ao vivo; comando pré-deploy
   (ex.: `migrate`) e healthcheck ficam na aba Configurações. Para deploy a
   cada push, gere o webhook do serviço Git (com 2FA) e cole no GitHub; com o
   painel fechado, use `[edge] hooks_hostname`.

## Configuração

Um arquivo só: `/etc/hangar/hangar.toml` (root:hangar, 0640). Campo
desconhecido é erro, para um erro de digitação não desligar uma proteção em
silêncio. Destinos de backup, canais de alerta e chaves ficam no painel, não
aqui.

```toml
data_dir        = "/var/lib/hangar"
master_key_file = "/etc/hangar/master.key"

[panel]
listen = ["127.0.0.1:7700"]                     # só loopback ou IP privado, nunca público
hosts  = ["127.0.0.1:7700", "localhost:7700"]   # Host aceito; o resto recebe 421
public = true                                   # painel com HTTPS pelo Caddy (exige [edge])
# public_host = "painel.exemplo.com"            # padrão: hangar.<ip>.sslip.io

[auth]
require_2fa = false   # true: ninguém entra sem 2FA

[update]
repo       = "JuniorCarlini/hangar"
token_file = "/etc/hangar/github-token"         # só enquanto o repositório for privado

[edge]                                          # Caddy nas portas 80/443
enabled                = true
acme_email             = "voce@exemplo.com"
public_ips             = ["203.0.113.10"]        # domínio de cliente só com DNS apontando para cá
max_new_certs_per_hour = 30
hooks_hostname         = "hooks.exemplo.com"     # publica só /hooks/git/* para o webhook do GitHub

[scan]                                          # monitor de vulnerabilidades (OSV.dev)
enabled = true
hour    = 6

[status]
hosts = ["status.exemplo.com"]                  # domínio que só alcança os links públicos de status

[alerts]
allowed_ports = [22]                            # portas fora do painel que não geram alerta

[backup]
allow_private_endpoints = false                 # true só para MinIO de laboratório
```

Todas as chaves, padrões e validações estão em
[`internal/config/config.go`](internal/config/config.go); o arquivo gerado
pelo instalador está em [`deploy/install.sh`](deploy/install.sh).

## Operação

O manual completo é o [docs/24 — Operação](docs/24-operacao.md). Os comandos
mais usados:

| Tarefa | Como | Detalhes |
|---|---|---|
| Atualizar | botão **Atualizar Hangar** (2FA) ou `sudo -u hangar hangard self-update stage` | [24 § 3](docs/24-operacao.md#3-atualizar-e-voltar), [21](docs/21-atualizacao-do-painel.md) |
| Voltar versão | automático se não subir em 90 s; à mão com os binários em `/var/lib/hangar/releases/` | [24 § 3](docs/24-operacao.md#3-atualizar-e-voltar) |
| Trancar painel | menu da conta → **Trancar painel** ou `sudo -u hangar hangard lockdown` | [24 § 4](docs/24-operacao.md#4-trancar-e-destrancar-botão-de-pânico) |
| Destrancar | só pelo servidor: `sudo -u hangar hangard lockdown off` (`status` mostra o estado) | [24 § 4](docs/24-operacao.md#4-trancar-e-destrancar-botão-de-pânico) |
| Conferir a auditoria | `sudo -u hangar hangard audit verify` | [24 § 4](docs/24-operacao.md#4-trancar-e-destrancar-botão-de-pânico) |
| Senha esquecida, 2FA perdida, conta bloqueada | `sudo -u hangar hangard user password\|totp\|totp-off\|unlock -email ...` | [24 § 6](docs/24-operacao.md#6-trocar-chaves-senhas-e-tokens) |
| Trocar a chave mestra | com o painel parado: `sudo -u hangar hangard secrets rotate-key` e trocar o arquivo | [24 § 6](docs/24-operacao.md#6-trocar-chaves-senhas-e-tokens) |
| Simulado de restauração (mensal) | no seu computador: `hangar-cofre sync PASTA` e `hangar-cofre test` | [24 § 5](docs/24-operacao.md#5-ensaio-de-restauração-simulado-mensal) |
| Restaurar um banco | aba **Backups → Restaurar** do Postgres (2FA, num serviço novo por padrão) | [09](docs/09-backups.md#restaurar) |
| Servidor perdido | VPS nova + instalador; `sudo hangard restore -cofre cofre.toml`; depois `sudo -u hangar hangard restore databases -cofre cofre.toml` | [24 § 5](docs/24-operacao.md#5-ensaio-de-restauração-simulado-mensal) |

**`hangar-cofre`** é a ferramenta de backup do **seu computador** (macOS,
Linux, Windows): baixa os backups do bucket com credencial só leitura, decifra
com o kit, sobe um banco no Docker local até um minuto exato e faz o simulado.
Funciona sem o painel. Gere com `just build-cofre` (ou `just build-cofre-all`)
e veja `hangar-cofre help`.

As lojas **não dependem do painel**: com o `hangard` parado, atualizando ou
trancado, containers e Caddy continuam servindo.

## Segurança

- O painel só escuta em loopback ou IP privado e confere o cabeçalho `Host`;
  na internet ele aparece só pelo Caddy, com HTTPS (ou só por túnel SSH, no
  modo bunker).
- Senhas argon2id, 2FA TOTP, sessões curtas em cookie `__Host-`, CSRF em toda
  escrita, CSP sem `unsafe-*`, **sudo** (2FA de novo) para revelar segredos,
  abrir portas, mexer em domínios e conectar projetos.
- Segredos cifrados com XChaCha20-Poly1305 e chave mestra fora do banco;
  backups cifrados com age e travados com Object Lock.
- Containers com `no-new-privileges`, `cap_drop ALL`, sem `docker.sock`, rede
  por projeto; filtro anti-SSRF para Git, S3, webhooks e Telegram.
- Auditoria encadeada por hash (sem UPDATE/DELETE) e alertas de segurança que
  não dá para desligar.

As 34 brechas do modelo de ameaça e as proteções de cada tela estão em
[docs/17](docs/17-telas-fluxos-e-seguranca.md). Encontrou uma vulnerabilidade? Veja
[SECURITY.md](SECURITY.md) — não abra issue pública.

## Desenvolvimento

### Requisitos

- **Go 1.27.3** (o `go.mod` manda; `templ`, `govulncheck` e afins vêm por `go tool`)
- [just](https://just.systems), **golangci-lint v2** (o CI usa v2.15.0) e
  **sqlc** (o CI usa 1.31.1)
- **Docker** para os testes de integração e para rodar serviços localmente
- **Node LTS** só para os testes E2E (Playwright)
- O Tailwind é baixado pelo `tools/tailwind.sh` (CLI standalone, versão e
  SHA-256 fixados), sem npm

### Comandos

```bash
just                   # lista as receitas
just run               # compila e sobe o painel em http://127.0.0.1:7710 (hangar.dev.toml, dados em .data/)
just check             # o mesmo que o CI: lint, testes com -race, govulncheck, sqlc diff, templ e CSS em dia
just generate          # sqlc + templ + Tailwind, depois de mexer em queries, .templ ou classes
just test-integration  # contra o Docker de verdade (MinIO, Postgres e caos descartáveis)
just e2e               # Playwright num painel descartável (lento, fora do check)
just build-linux       # binários para o servidor
```

Para entrar no painel local, crie um usuário com
`./bin/hangard user create -config hangar.dev.toml -email voce@exemplo.com`.

### Estrutura

```
cmd/
  hangard/          o painel e a CLI do servidor (serve, user, lockdown, secrets, restore, self-update, audit...)
  hangar-cofre/     ferramenta de backup do computador do operador
  hangar-release/   gera a chave e assina as releases (CI)
internal/
  app/              composição: monta as dependências e sobe os servidores
  web/              handlers, middlewares, views templ, assets embutidos
  projects/         projetos, serviços, variáveis, domínios, deploys, credenciais Git
  docker/ node/     operações de container (node.Node, implementação local)
  edge/             Caddy: configuração e o endpoint ask dos domínios dinâmicos
  auth/ audit/ lockdown/ secrets/ netguard/ firewall/
  backup/ cofre/    backups e a lógica do hangar-cofre
  alerts/ metrics/ deps/ statuspage/ update/ release/ gitsrc/ templates/
  i18n/             catálogos pt-BR e en
  store/            SQLite: migrations/ (goose), queries/ (sqlc), dbq/ (gerado, não editar)
deploy/             install.sh e units do systemd
e2e/                testes Playwright
examples/           app de laboratório para domínios dinâmicos
tools/              tailwind.sh, painel de laboratório, teste de carga
docs/               documentação de projeto e ADRs
```

### Padrões

Resumo; as regras completas estão em [CONTRIBUTING.md](CONTRIBUTING.md) e
[docs/12](docs/12-padroes-de-codigo.md).

- **Código e comentários em inglês**; o que o usuário lê, em português, via
  catálogos de idioma (`internal/i18n/locales/pt-BR.toml` e `en.toml`, chave
  em inglês). Nenhum texto de tela direto no template — um teste falha
  ([22](docs/22-idiomas-e-temas.md)).
- Interface server-side: **templ** + **Tailwind** + componentes **Tucano** +
  ícones **Lucide**, design system "Pista" ([18](docs/18-design-system.md)).
- Banco: migrações **goose** numeradas em `internal/store/migrations/`, queries
  **sqlc** em `internal/store/queries/`; o código gerado vai junto no commit.
- Toda mudança com teste; `just check` passando antes de subir.
- **Mensagens de commit em português**, explicando **por que** a mudança existe.

## Documentação

| Doc | Conteúdo |
|---|---|
| [00 — Visão geral](docs/00-visao-geral.md) | O problema, objetivos e o que está fora do escopo |
| [01 — Arquitetura](docs/01-arquitetura.md) | Componentes, fluxo de requisição, redes |
| [02 — Stack e versões](docs/02-stack-e-versoes.md) | Linguagem, bibliotecas e versões |
| [03 — Domínios customizados e TLS](docs/03-dominios-customizados-tls.md) | On-demand TLS com autorização pela app |
| [04 — Segurança](docs/04-seguranca.md) | Modelo de ameaça e controles |
| [05 — Isolamento e recursos](docs/05-isolamento-e-recursos.md) | Containers, redes, limites, portas, firewall |
| [06 — Monitoramento e logs](docs/06-monitoramento-e-logs.md) | Métricas, logs ao vivo e alertas |
| [07 — Deploy e builds](docs/07-deploy-e-builds.md) | Imagem e Git, zero-downtime, rollback, webhook |
| [08 — Serviços (templates)](docs/08-servicos-templates.md) | Postgres e Redis com um clique |
| [09 — Backups](docs/09-backups.md) | age, Object Lock, WAL, kit de recuperação, hangar-cofre |
| [10 — Modelo de dados](docs/10-modelo-de-dados.md) | Tabelas do SQLite do painel |
| [11 — API](docs/11-api.md) | Endpoints HTTP do painel |
| [12 — Padrões de código](docs/12-padroes-de-codigo.md) | Layout, convenções, lint, testes |
| [14 — Atualizações e vulnerabilidades](docs/14-atualizacoes-de-dependencias.md) | Monitor OSV.dev de bibliotecas e imagens |
| [15 — Painel público de status](docs/15-painel-publico-de-status.md) | Links externos sem expor nomes nem detalhes |
| [17 — Telas, fluxos e segurança](docs/17-telas-fluxos-e-seguranca.md) | Cada tela, quem usa, proteções; as 34 brechas |
| [18 — Design system "Pista"](docs/18-design-system.md) | Tokens, canvas, drawer, componentes Tucano |
| [20 — Logs e retenção](docs/20-logs-e-retencao.md) | Onde cada log mora, limites, retenção |
| [21 — Atualização com um clique](docs/21-atualizacao-do-painel.md) | Release assinada, troca segura, volta automática |
| [22 — Idiomas e temas](docs/22-idiomas-e-temas.md) | i18n e tema claro/escuro por usuário |
| [24 — Operação](docs/24-operacao.md) | Instalar, atualizar, trancar, restaurar, trocar chaves, incidentes, migração |
| [27 — Criar serviços e compose](docs/27-criar-servicos-e-compose.md) | Imagem, Git, template ou docker-compose colado |
| [28 — Links do serviço](docs/28-endpoints-web-e-dominios-automaticos.md) | Portas públicas, link automático sslip.io/subdomínio, quem pode expor |
| [adr/](docs/adr/README.md) | Decisões de arquitetura registradas |

O índice com as decisões principais fica em [docs/README.md](docs/README.md).

## Licença

[Apache-2.0](LICENSE) © Junior Carlini. Pode usar, modificar e redistribuir,
inclusive comercialmente, mantendo o aviso de licença.
