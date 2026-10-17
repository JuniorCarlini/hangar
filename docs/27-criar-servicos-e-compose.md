# 27 — Criar serviços e importar docker-compose

> Como o Hangar cria um serviço a partir de um nome só, e como ele importa um
> `docker-compose.yml` inteiro de uma vez — o que reconhece, o que ignora e
> por quê.

## 1. Novo serviço: um nome só

O **Novo serviço** é um modal do Tucano que abre por cima do canvas (botão
*Novo serviço*, arrastar uma linha de um cartão para o vazio, ou a paleta
`⌘K`). O endereço `/p/{projeto}/new` continua existindo: abre o canvas com o
modal já aberto (é também o que acontece quando um formulário volta com erro).

Cada aba pede **um nome**, já preenchido com uma sugestão que o usuário pode
trocar:

| Aba | Sugestão |
|---|---|
| Template | o tipo: PostgreSQL → `db`, Redis (cache) → `cache`, Redis (filas) → `redis` |
| Imagem Docker | o nome da imagem: `nginx:1.29` → `nginx`, `ghcr.io/dono/api:2` → `api` |
| Repositório Git | o nome do repositório: `github.com/dono/loja-api` → `loja-api` |
| (sem pista) | `web` |

Se o nome sugerido já existe no projeto, vem com sufixo: `db-2`, `db-3`…

O **endereço interno** (o identificador: nome do container, host na rede do
projeto) é derivado do nome e aparece embaixo dele como prévia: minúsculas,
sem acento, espaços e símbolos viram hífen, no máximo 32 caracteres
(`node.SlugRE`). "Loja Café" vira `loja-cafe`. O servidor deriva de novo e
nunca confia no que veio do navegador; se o endereço já existe, o erro diz
qual (`Já existe um serviço com o endereço interno loja-cafe…`).

O que quase ninguém muda fica em **Opções avançadas** (recolhido):

| Campo | Padrão |
|---|---|
| Porta interna (imagem) | a de imagens conhecidas (nginx 80, grafana 3000…), senão nenhuma |
| Porta interna (Git) | o primeiro `EXPOSE` do Dockerfile; sem ele, 8000 |
| Branch | `main` |
| Pasta / Dockerfile | raiz / `Dockerfile` |
| Memória / CPU | 512 MB / 1 CPU |

O arrastar do canvas continua funcionando em todas as abas: os campos ocultos
`from`, `x` e `y` (componente `placeFields`) vão em todos os formulários; o
cartão novo nasce onde a linha caiu e o serviço de origem ganha a referência
(`DATABASE_URL=${{db.DATABASE_URL}}`).

## 2. Importar docker-compose

Aba **Compose** do mesmo modal. Duas origens:

- **Colar o arquivo** (até 256 KB e 20 serviços);
- **Ler do repositório Git**: o Hangar faz um clone raso e sem checkout
  (`gitsrc.Fetch`) e lê `compose.yaml`, `compose.yml`, `docker-compose.yaml`
  ou `docker-compose.yml` da raiz. Serviços com `build:` viram builds desse
  mesmo repositório.

O fluxo tem duas etapas: **Analisar** mostra a prévia (o que será criado, o
que foi reconhecido e o que fica de fora, com o motivo) e **Criar N serviços**
cria tudo numa transação só — tudo ou nada. A confirmação lê o arquivo de
novo: a prévia nunca é usada como verdade. Os bancos fazem deploy primeiro.

O arquivo é **lido, nunca executado**. O parser é `go.yaml.in/yaml/v3` (a
continuação mantida do `gopkg.in/yaml.v3`, sem dependências e com proteção
contra "alias bomb"); o `compose-spec/compose-go` foi descartado porque traz
dezenas de módulos para recursos que o importador ignora de propósito.

### 2.1 O que vira o quê

| No compose | No Hangar |
|---|---|
| `image: postgres:*` | template **PostgreSQL**: senha gerada, disco, healthcheck, backups, exports (`DATABASE_URL`, `HOST`, `USER`…). `POSTGRES_DB`/`POSTGRES_USER` viram as entradas do template; a senha do arquivo é descartada |
| `image: redis:*` | template **Redis (cache)**; com volume, `--appendonly yes` ou `--save`, **Redis (filas e sessões)** |
| outra `image:` | serviço por imagem |
| `build:` (context, dockerfile) lido do repositório | serviço por Git: mesmo repositório, pasta = `context`, `dockerfile` relativo a ela |
| `build:` colado | não é criado (precisa do repositório); com `image:` junto, usa a imagem |
| `environment:` (lista ou mapa) | variáveis; nomes com PASS/SECRET/TOKEN/KEY viram secretas |
| `${VAR:-padrão}` | o padrão |
| `${VAR}`, `KEY` sem valor | vazia, com aviso (o Hangar não lê o ambiente do servidor) |
| URL apontando para um banco importado (`postgres://u:s@db:5432/x`) | `${{db.DATABASE_URL}}` (ou montada com `${{db.USER}}`, `${{db.PASSWORD}}`…) |
| `redis://cache:6379/1` | `redis://:${{cache.PASSWORD}}@${{cache.HOST}}:${{cache.PORT}}/1` |
| `DB_HOST=db`, `DB_PASSWORD=<a do arquivo>` | `${{db.HOST}}`, `${{db.PASSWORD}}` |
| `volumes:` nomeado (`media:/app/media`) | disco do Hangar (`AddServiceVolume`: até 8, sem caminhos do sistema) |
| `expose:` / porta do container em `ports:` | porta interna |
| `command:` (texto ou lista) | comando |
| `deploy.resources.limits` / `mem_limit` / `cpus` | memória e CPU |
| `depends_on` | só informativo |

### 2.2 O que fica de fora (e aparece na prévia)

| No compose | Por quê |
|---|---|
| bind mount (`./pasta:/x`, `/host:/x`, `~/x`, `type: bind`, volume com `driver_opts` de bind) | o Hangar não monta pastas do servidor em containers |
| socket do Docker | nunca é montado |
| `ports:` | nenhuma porta é aberta sozinha: use um domínio ou abra em **Rede** |
| `privileged`, `cap_add`, `devices`, `pid`, `ipc`, `security_opt`, `userns_mode`, `sysctls`, `network_mode: host`… | recusados por segurança; o serviço é criado sem eles |
| `entrypoint`, `user`, `working_dir`, `env_file`, `extends`, `profiles` | não suportados |
| `healthcheck` | use o caminho de saúde nas configurações de deploy |
| `secrets:`/`configs:` | cadastre como variáveis secretas |
| `container_name`, `restart`, `networks`, `labels`, `logging`… | o Hangar cuida disso |

Bloqueiam a importação (em vermelho na prévia): nome que já existe no
projeto, dois serviços que viram o mesmo endereço (`web_app` e `web-app`),
Dockerfile ausente no repositório, build sem builder configurado.

### 2.3 Posição no canvas

Os cartões importados nascem abaixo de tudo o que já está no canvas (ou onde
a linha foi solta): aplicações na coluna da esquerda, bancos e caches ao lado,
uma linha por serviço. As referências viram linhas na hora.

## 3. Modelo que o Hangar reconhece bem

Na aba Compose, **Ver modelo** mostra (e copia, ou coloca na caixa de texto)
o arquivo abaixo — o mesmo de `internal/projects/compose_sample.yaml`, servido
em `/compose-sample.yaml`. Django + PostgreSQL + Redis + worker do Celery:
coloque na raiz do repositório e use *Ler do repositório Git*. Nada nele é
perdido na importação.

```yaml
services:
  db:
    image: postgres:18-alpine
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: app
      POSTGRES_PASSWORD: senha-local
    volumes:
      - pgdata:/var/lib/postgresql

  redis:
    image: redis:8-alpine
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data

  web:
    build:
      context: .
      dockerfile: Dockerfile
    command: gunicorn config.wsgi --bind 0.0.0.0:8000 --workers 3
    expose:
      - "8000"
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgres://app:senha-local@db:5432/app
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/1
      DJANGO_SETTINGS_MODULE: config.settings
      DJANGO_ALLOWED_HOSTS: "*"
      SECRET_KEY: ${SECRET_KEY:-troque-esta-chave}
    volumes:
      - media:/app/media
    depends_on: [db, redis]
    deploy:
      resources:
        limits: { memory: 512M, cpus: "1" }

  worker:
    build: .
    command: celery -A config worker --loglevel=info
    environment:
      DATABASE_URL: postgres://app:senha-local@db:5432/app
      CELERY_BROKER_URL: redis://redis:6379/1
      DJANGO_SETTINGS_MODULE: config.settings
      SECRET_KEY: ${SECRET_KEY:-troque-esta-chave}
    depends_on: [db, redis]
    deploy:
      resources:
        limits: { memory: 384M, cpus: "0.5" }

volumes:
  pgdata:
  redisdata:
  media:
```

Resultado: `db` (template PostgreSQL) e `redis` (template Redis filas), `web`
e `worker` construídos do repositório; `DATABASE_URL` vira
`${{db.DATABASE_URL}}`, `REDIS_URL` vira `${{redis.REDIS_URL}}`, o broker do
Celery aponta para o banco 1 do mesmo Redis, `media` vira um disco do `web`.
Depois de criar: troque `SECRET_KEY` (aba Variáveis) e ponha um domínio no
`web`.

## 4. Rotas

| Rota | Papel | O que faz |
|---|---|---|
| `GET /p/{p}/new` | admin | canvas com o modal aberto (`?template=`, `?from=&x=&y=`) |
| `POST /p/{p}/services`, `/services/git`, `/templates` | admin | criam a partir do nome (`name`; `slug` ainda é aceito) |
| `POST /p/{p}/compose/preview` | admin | analisa e mostra a prévia; não cria nada |
| `POST /p/{p}/compose` | admin | analisa de novo e cria tudo (auditoria `service.create` por serviço, com `compose: true`) |
| `GET /compose-sample.yaml` | leitor | o modelo, em texto |
