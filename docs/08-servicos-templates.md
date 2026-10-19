# 08 — Serviços (templates)

Templates são o "um clique" do Hangar: você escolhe "PostgreSQL" ou "n8n",
preenche 2 ou 3 campos e o painel cria tudo **já seguro**: senhas fortes
geradas, limites, sem porta aberta, volume certo, healthcheck e backup
configurados.

## Como as outras plataformas fazem (e o que copiamos)

| Plataforma | Como funciona | O que aproveitamos | O que evitamos |
|---|---|---|---|
| **Easypanel** | Catálogo grande; cada template é um formulário que gera um ou mais serviços já ligados (ex.: Chatwoot = app + worker + Postgres + Redis) | **Templates de vários serviços**, formulário curto, nomes `<projeto>_<serviço>` | Templates sem revisão de segurança, versão `latest` |
| **Coolify** | Templates em docker-compose, centenas de serviços | Catálogo amplo, variáveis mágicas (senhas e URLs geradas) | Compose livre (permite `privileged`, `docker.sock`, bind mount) |
| **Dokploy** | Templates em compose + formulário | Busca por categoria | Mesmos riscos do compose livre |
| **Railway** | Templates como "projeto pronto" com serviços conectados no canvas | **Referências entre serviços** (`${{postgres.DATABASE_URL}}`) e o canvas mostrando as ligações | — |

A diferença do Hangar: **nenhum template pode pedir o que um serviço comum
não pode** (privileged, docker.sock, bind mount do host, capabilities fora
da lista, porta pública sem você pedir). Templates que dependem disso, como
Portainer, Watchtower e Dozzle, **não entram no catálogo de propósito**:
eles dão controle total do servidor a quem invadir o app, e o Hangar já faz
o que eles fazem.

## Formato: uma pasta por template

Cada template é uma pasta, no modelo do Dokploy: um **Docker Compose comum**
(qualquer pessoa já sabe escrever) mais o que o Compose não sabe dizer
(nome nas duas línguas, campos do formulário, senhas geradas, o que os
outros serviços podem referenciar). Um template pode criar **vários
serviços** ligados entre si (o n8n traz o próprio PostgreSQL).

```
internal/templates/catalog/<id>/
  compose.yaml    # Docker Compose comum, só um subconjunto seguro
  template.toml   # o que o compose não carrega
  logo.svg        # até 64 KB
  README.md       # opcional
```

Nada mais pode existir na pasta. Os templates embutidos ficam em
`internal/templates/catalog/` e vão dentro do binário (assinado); os da
comunidade chegam pelo catálogo assinado (abaixo).

### `template.toml`

```toml
id = "postgres"            # igual ao nome da pasta
version = 1                # versão do template (não da imagem); sobe a cada mudança
category = "database"      # database | cache | queue | search | storage | automation | monitoring | admin | other
tags = ["sql", "relational"]   # até 8, minúsculas, para a busca
docs = "https://www.postgresql.org/docs/18/"
backup = "pg_dump"         # opcional: liga o "Baixar backup"
main = "postgres"          # o serviço do compose que recebe o nome escolhido
min_hangar = "v0.1.0"      # opcional: versão mínima do Hangar
name = { en = "PostgreSQL", "pt-BR" = "PostgreSQL" }
description = { en = "...", "pt-BR" = "..." }

[variables.database]       # campo do formulário (na ordem do arquivo)
default = "app"
pattern = '^[a-z_][a-z0-9_]{0,62}$'   # obrigatório, com ^ e $
label = { en = "Database name", "pt-BR" = "Nome do banco" }

[variables.password]       # gerado, nunca digitado: 32 bytes aleatórios, base64url
generate = "secret"

[[exports]]                # o que outros serviços referenciam como ${{db.DATABASE_URL}}
key = "DATABASE_URL"
value = "postgres://${user}:${password}@${service}:5432/${database}"
secret = true

[volumes.data]             # opcional: limite sugerido para o volume "data" do compose
size = "10GB"              # número inteiro + GB ou TB (unidades binárias), de 1GB a 8TB
```

`[volumes.<nome>] size` sugere um **limite de tamanho** para um volume
declarado no `compose.yaml` (o do dono, se compartilhado; nome que nenhum
serviço monta é recusado). No formulário de criação ele vem **marcado**,
com o tamanho editável, e o admin pode desmarcar; sem a chave, o volume nasce
sem limite e pode ganhar um depois. Como todo limite, só vale com a senha
confirmada há pouco (sudo); sem isso o disco nasce sem limite
([05](05-isolamento-e-recursos.md)). Use só onde faz sentido guardar muito
dado (bancos, armazenamento): no catálogo embutido, PostgreSQL, MariaDB e
MongoDB sugerem 10 GB e o RustFS 50 GB. Painéis anteriores a esta chave
recusam o template (chave desconhecida): use `min_hangar` no catálogo da
comunidade.

O serviço `main` fica com o nome que o usuário escolheu (`db`); os outros
ganham o sufixo com o nome do compose (`db` + serviço `cache` = `db-cache`).
Os exports pertencem ao serviço principal.

### `compose.yaml`

```yaml
services:
  postgres:
    image: postgres:18-alpine
    command: ["postgres", "-c", "shared_buffers=128MB"]
    environment:
      POSTGRES_USER: ${user}
      POSTGRES_PASSWORD: ${password}
    volumes:
      - data:/var/lib/postgresql
    expose: ["5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${user}"]
      interval: 10s
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
    deploy:
      resources:
        limits: { memory: 512M, cpus: "1.0" }

volumes:
  data:
```

**Placeholders**, no compose e nos exports: `${variavel}` (minúsculas, as
de `template.toml`), mais `${name}` (nome do serviço), `${project}`,
`${service}` (endereço interno do serviço principal, `projeto_nome`) e
`${service_<nome>}` (endereço dos outros serviços do template, ex.:
`${service_db}`). Como no Compose, `$$` é um `$` literal (use `$$VAR` para
o shell do container ler a variável); qualquer outro `$` é erro, assim
nada some sem aviso.

**Só estas chaves existem** em cada serviço: `image`, `command` (em forma de
lista), `environment`, `volumes` (só volumes nomeados declarados em
`volumes:` no topo, sem driver; `nome:/caminho`, `nome:/caminho:ro` para
só leitura, ou a forma longa com `type: volume`, `source`, `target` e
`read_only: true`), `expose` (exatamente uma porta: a que o
serviço escuta dentro da rede; é nela que você liga um domínio depois),
`healthcheck` (`test`, `interval`, `timeout`, `start_period`, `retries`),
`cap_add`, `read_only`, `stop_grace_period`,
`deploy.resources.limits.{memory,cpus}` e `depends_on`. No topo, só
`services` e `volumes`. Qualquer outra chave é
erro com o nome dela: `ports`, `privileged`, `network_mode`, `pid`, `ipc`,
`devices`, `build`, `entrypoint`, `user`, `env_file`, `secrets`... Sem
`cap_add`, o serviço recebe as capabilities padrão do Hangar; `cap_add: []`
significa nenhuma (o certo para imagens que já rodam sem root).

`stop_grace_period` (`45s`, `1m30s`) é quanto o Hangar espera depois do
`SIGTERM` antes de matar o container — em toda parada: deploy que troca o
container, botão parar, reinício, exclusão do serviço e o próprio Docker
desligando (o valor fica gravado no container). Sem a chave, 30 s. O teto é
120 s: um valor maior vira 120 s e o `hangard template check` avisa (sem
recusar). Servidores que salvam o estado ao desligar (jogos, bancos) são o
caso de uso.

**Volume compartilhado entre serviços do template:** dois serviços podem
montar o mesmo volume declarado no topo (um servidor e a ferramenta que lê
os arquivos dele, por exemplo `world:/srv/world` num e `world:/data:ro` no
outro). O volume pertence a um deles, o **dono**: o serviço principal se
ele o monta, senão o primeiro do arquivo que o monta. No Docker o volume tem
o nome e os labels do dono (`hangar_<projeto>_<dono>_<volume>`) e os outros
montam esse mesmo volume; continua dentro do projeto, nunca é caminho do
servidor e só vale para volumes declarados naquele `compose.yaml`. O painel
cria o volume antes dos deploys (que rodam juntos), o backup lê o volume do
dono, e o dono não pode ser apagado enquanto outro serviço monta o volume
(apague os outros primeiro; apagar um deles só tira a montagem dele). Quem
escreve no volume compartilhado precisa de healthcheck como o dono; quem só
lê (`:ro`) não. A aba Discos mostra "o disco de …" e "também usado por …".

O healthcheck também define quanto o deploy espera o container novo ficar
saudável: `start_period + interval × retries + timeout`, no mínimo 2 min e
no máximo 15 min ([07](07-deploy-e-builds.md)). Quem demora para subir
declara um `start_period` honesto.

### Regras que o carregador confere (o template é recusado se falhar)

1. Imagem com tag de versão explícita: nada de `latest`. Na criação, é
   resolvida para **digest** e o serviço fica preso nela até você atualizar.
2. `cap_add` só da lista permitida (`node.AllowedCaps`).
3. Nenhum `privileged`, `docker.sock`, bind mount (caminho do servidor),
   `network_mode`, `devices`, `pid`/`ipc` ou `build`.
4. Senha nunca tem valor padrão: campo digitado com cara de segredo
   (`pass`, `secret`, `token`, `key`) é recusado; use `generate = "secret"`.
5. Limites de memória (16M ou mais) e CPU obrigatórios.
6. Serviço com volume precisa de healthcheck (dono do volume ou quem
   escreve num volume compartilhado; quem só lê um volume de outro serviço
   do template fica dispensado).
7. Porta pública: nenhum template publica porta. Expor é ação sua, na aba
   Portas ([05](05-isolamento-e-recursos.md)).
8. Placeholder inexistente é erro; chave desconhecida no `template.toml`
   também.
9. Logo: SVG bem formado, até 64 KB, raiz `<svg>`, sem `<script>`,
   `<foreignObject>`, atributos `on*`, links externos (`href` só `#id`),
   `url()` externa ou DTD. A rota `GET /templates/<id>/logo.svg` ainda manda
   um CSP que proíbe scripts e qualquer carregamento de fora.

## Como criar um template

1. Crie a pasta `<id>/` (minúsculas, números e `-`) com `compose.yaml`,
   `template.toml` e `logo.svg`. Comece copiando um parecido do catálogo.
2. Escreva o `compose.yaml` como escreveria para o seu servidor, só com as
   chaves acima: imagem com versão, limites, volume nomeado, healthcheck,
   `expose` com a porta. Senhas e chaves viram `${variavel}` com
   `generate = "secret"` no `template.toml`.
3. Preencha nome e descrição em `en` e `pt-BR` (curtos, dizendo o que vem
   seguro de fábrica) e os `[[exports]]` que os outros serviços vão usar.
4. Logo: pegue o SVG do [Simple Icons](https://simpleicons.org) (CC0) e
   coloque a cor da marca em `fill`; se a marca não estiver lá, desenhe um
   ícone genérico. Nunca invente marca.
5. Rode `hangard template check <pasta>` (ou `just template-check`): a
   saída diz arquivo e chave de cada problema, com a mesma regra do painel.
6. Suba no Docker de laboratório (nunca num projeto real) e confira que fica
   "healthy". Abra o pull request no `hangar-templates`.

## Catálogo da comunidade (assinado e automático)

- Os templates embutidos em cada versão são a base e funcionam sem
  internet.
- Uma vez por dia (e logo depois de subir, com um atraso aleatório), o
  painel baixa `catalog.tar.gz` e `catalog.tar.gz.sig` da última release de
  `JuniorCarlini/hangar-templates` (até 5 MB, só HTTPS, só endereços
  públicos). A assinatura é Ed25519 sobre os bytes do arquivo, com uma chave
  própria do catálogo embutida no binário (separada da chave das releases).
  Sem essa chave no binário, a sincronização fica desligada.
- Depois da assinatura, **cada template passa pelas mesmas regras** dos
  embutidos; um template inválido é pulado sozinho (o log diz o motivo),
  assim como um com `min_hangar` mais novo que o painel. Nada remoto pula a
  validação.
- Regra de junção: por id, vence a `version` maior; no empate, vence o
  embutido.
- O catálogo aceito fica em `data_dir/templates/` e é conferido de novo ao
  subir o painel.
- Desligar: `[templates] sync = false` no `hangar.toml` (há também
  `catalog_url`, para um espelho).
- No CI do `hangar-templates`: `hangard template check .` em todo PR e, na
  release, `hangard template pack . -out dist` com a chave privada em
  `HANGAR_CATALOG_KEY`. O par de chaves sai de `just catalog-key` (a pública
  vai para `CatalogPublicKeyHex` em `internal/templates/remote.go`).

### Teste automático de cada template

No CI, cada template do catálogo é **criado de verdade** num Docker
descartável. O teste sobe os serviços, espera o healthcheck ficar
"healthy", confere que nenhuma proteção foi afrouxada e apaga tudo. Template
que não passa não entra numa versão do Hangar.

### Atualização dos templates

- Template novo ou corrigido chega **junto com a atualização do Hangar**
  (assinada) ou, entre versões, pelo **catálogo da comunidade** (assinado,
  ver abaixo). Mudar um template não muda serviços já criados.
- Imagem nova de um serviço já criado (Postgres 18.0 → 18.1) aparece no
  monitor de atualizações ([14](14-atualizacoes-de-dependencias.md)) com
  botão "atualizar", que faz backup antes. Versão **major** nunca atualiza
  com um clique: mostra o guia de migração.

## Catálogo

Organizado em levas. Cada leva só entra depois da anterior estar testada.

### Leva 1 — o que os seus projetos usam (Etapa 5)

| Template | Serviços criados | Observação |
|---|---|---|
| **App por imagem** | 1 | O genérico (já existe na Etapa 3) |
| **PostgreSQL** | 1 | `shared_buffers` ajustado ao limite de memória; backup contínuo (WAL) |
| **Redis** (cache) | 1 | Sem persistência, `allkeys-lru`, senha gerada, `FLUSHALL`/`CONFIG`/`DEBUG` bloqueados por ACL |
| **Redis** (filas e sessões) | 1 | AOF ligado, `noeviction`; o tipo certo para Celery e sessões |
| **Valkey** | 1 | Fork aberto do Redis, mesmas variantes |
| **PgBouncer** | 1 | Na frente do Postgres, quando houver réplicas |

### Leva 2 — infraestrutura comum

| Template | Observação |
|---|---|
| MySQL / MariaDB | Backup com `mysqldump` |
| MongoDB | Autenticação obrigatória, backup com `mongodump` |
| RabbitMQ | Senha gerada; painel de gestão só pela rede interna ou túnel |
| Meilisearch | Busca rápida (catálogo de lojas); master key gerada |
| Armazenamento S3 próprio | Garage ou SeaweedFS (avaliar; o MinIO mudou a licença e o modelo de distribuição) |
| Mailpit | SMTP de teste para o laboratório (nunca em produção) |

### Leva 3 — aplicações populares (muito usadas no Easypanel no Brasil)

| Template | Serviços | Observação |
|---|---|---|
| **n8n** | app + Postgres (+ Redis no modo fila) | Automação; chave de cifra gerada |
| **Evolution API** | app + Postgres + Redis | WhatsApp; chave global gerada |
| **Typebot** | builder + viewer + Postgres | Chatbots |
| **Chatwoot** | app + worker + Postgres + Redis | Atendimento |
| **Uptime Kuma** | 1 | Monitor externo dos seus sites |
| **Metabase** | app + Postgres | Relatórios (o mesmo Postgres de produção só por réplica de leitura) |
| **Umami** ou **Plausible** | app + Postgres | Analytics sem cookies |
| **WordPress** | app + MariaDB | Com cabeçalhos de segurança e `xmlrpc` bloqueado |
| **Directus** / **Strapi** | app + Postgres | CMS headless |
| **Vaultwarden** | 1 | Cofre de senhas da equipe (exige domínio com HTTPS) |
| **Gitea** / **Forgejo** | app + Postgres | Git próprio |

### Fora do catálogo de propósito

| Serviço | Por quê |
|---|---|
| Portainer, Dozzle, Watchtower, Yacht | Exigem `docker.sock`: quem invade o app vira dono do servidor. O Hangar já faz o que eles fazem |
| pgAdmin / Adminer expostos na internet | Viram alvo de força bruta; use túnel SSH ou a porta "só localhost" |
| Qualquer imagem `latest` sem versão | Atualização silenciosa quebra produção |

Pedidos de template novo passam pelo checklist de segurança de
[04](04-seguranca.md) e pelo teste automático acima.

## Vários bancos na mesma VPS

Cada instância é um container com volume, rede e limite próprios. Cinco
Postgres = cinco containers isolados, cada um só visível na rede do seu
projeto. Para muitos bancos pequenos, alternativa econômica: um Postgres por
projeto com vários databases (o painel permite criar databases e usuários
extras numa instância existente).

## Situação (Etapa 5)

- **Uma pasta por template** (`compose.yaml` + `template.toml` + `logo.svg`),
  no lugar do arquivo TOML único do começo da etapa. O compose é lido com o
  mesmo `go.yaml.in/yaml/v3` do importador de compose e o `template.toml`
  com o `go-toml` da configuração: nenhuma dependência nova. Tudo vira a
  mesma estrutura interna de antes, então criar serviços, exports e o
  importador de compose não mudaram.
- Textos (nome, descrição, rótulos) ficam no próprio template, em `en` e
  `pt-BR`.
- **No catálogo** (imagens de 10/2026):

  | Template | Imagem | Categoria | Porta exposta |
  |---|---|---|---|
  | PostgreSQL | `postgres:18-alpine` | database | 5432 |
  | Redis (cache) / (filas e sessões) | `redis:8-alpine` | cache / queue | 6379 |
  | Valkey (cache) / (filas e sessões) | `valkey/valkey:9-alpine` | cache / queue | 6379 |
  | MariaDB | `mariadb:12.3` (LTS) | database | 3306 |
  | MongoDB | `mongo:9.0` | database | 27017 |
  | n8n (+ PostgreSQL próprio) | `n8nio/n8n:2.43.7` | automation | 5678 |
  | Uptime Kuma | `louislam/uptime-kuma:2-rootless` | monitoring | 3001 |
  | RustFS (S3) | `rustfs/rustfs:1.0.3` | storage | 9001 (console) |
  | pgAdmin | `dpage/pgadmin4:9.18` | admin | 5050 |
  | Adminer | `adminer:6-standalone` | admin | 8080 |
  | RabbitMQ | `rabbitmq:4.3-management-alpine` | queue | 15672 (gestão) |
  | Meilisearch | `getmeili/meilisearch:v1.55` | search | 7700 |

  Os Redis e Valkey: senha gerada, `FLUSHALL`, `FLUSHDB`, `CONFIG` e `DEBUG`
  desligados. **MinIO ficou de fora:** desde o fim de 2025 o MinIO não
  publica mais imagens da edição comunitária (Docker Hub e Quay recusam
  download anônimo e a última imagem tem falha conhecida); o RustFS, de
  código aberto e compatível com S3, ocupa o lugar.
- Senhas geradas viram variáveis secretas e "exports" cifrados. A seção
  **Conexão** do serviço mostra `HOST`, `PORT`, `DATABASE_URL` etc., com os
  segredos mascarados (revelar exige 2FA e fica na auditoria).
- **Referências** `${{servico.CHAVE}}` (mesmo projeto) e
  `${{projeto.servico.CHAVE}}` (projeto conectado), resolvidas a cada deploy.
  Só um nível: um valor referenciado é usado como está, então referências
  nunca entram em loop. Referência quebrada faz o deploy falhar com a
  mensagem certa, em vez de subir com valor vazio.

**Ficou para depois:** PgBouncer; backup com um clique para MariaDB e
MongoDB; fixar a imagem por digest na
criação; teste no CI que sobe cada template até "healthy" (hoje feito na
VM); ajustar `shared_buffers` sozinho quando o limite de memória muda;
"aviso de alteração pendente" quando o valor referenciado muda.

