# 28 — Endpoints web e domínios automáticos

Como um serviço ganha link externo: o modelo de *endpoints* (portas expostas),
o domínio automático sempre presente (sslip.io) e o domínio próprio do operador
com certificado curinga via DNS-01. Complementa [03](03-dominios-customizados-tls.md)
(TLS on-demand) e [27](27-criar-servicos-e-compose.md) (criação de serviços).

## Segurança primeiro

A funcionalidade se adequa à segurança, nunca o contrário. As regras invioláveis:

1. **Interno por padrão.** Uma porta só fica pública se alguém disser
   explicitamente — o autor do template (`public = true`) ou o operador no
   formulário. O padrão de uma porta não declarada é **privada**: um banco ou
   um worker nunca vaza pra internet por esquecimento (fail-closed).
2. **O sslip não burla nenhuma trava.** O nome automático passa pelos mesmos
   trilhos de qualquer domínio: autorização do `ask`, limite `MaxNewPerHour`,
   checagem `pointsHere` (o nome tem que resolver pro IP do servidor) e registro
   em `tls_ask_log`. Ver [03](03-dominios-customizados-tls.md).
3. **Domínio de cliente continua on-demand + autorizado.** O caminho dos
   domínios próprios (`loja.com.br`) não muda: HTTP-01 sob demanda, só depois
   do `domain-check` da aplicação aprovar (fail-closed).
4. **Token de DNS protegido.** A credencial do provedor de DNS (DNS-01) vem
   do `config.toml` e entra na config do Caddy, que precisa lê-la para provar o
   desafio. Ela fica no `edge/admin/bootstrap.json` (0600, só o usuário do Hangar
   e o Caddy leem) e é removida de qualquer mensagem de erro antes de ir para o
   log ou a tela. Não é cifrada em repouso ali — o Caddy precisa do valor em
   claro; proteja o `config.toml` e o diretório de dados como segredos.
5. **O certificado curinga não cobre domínio de cliente.** `*.base` cobre só os
   subdomínios da base, um nível. Domínio de cliente tem certificado próprio.

## O conceito: endpoint

Um serviço expõe **N endpoints**. Cada endpoint é:

- uma **porta** interna do container (ex.: 9000, 9001);
- um **rótulo** (`Console`, `CDN`, `API`);
- uma **exposição**: `interna` ou `pública`.

**Interna** → alcançável só na rede do projeto em `<serviço>:<porta>` (bots,
workers, banco, a API S3 que outros serviços consomem). Sem link externo.

**Pública** → ganha link externo. Toda porta pública tem **sempre** o link
sslip de graça; por cima dela grudam 0..N **domínios próprios**.

> A tabela `ports` que já existe é outra coisa: publicação de porta TCP/UDP no
> host (aba "Portas", com firewall). Endpoint é HTTP pelo proxy de borda.

### Exemplo (MinIO/RustFS)

```
Serviço rustfs
├─ endpoint "Console"  9001  pública
│     sslip (sempre):  loja-rustfs.203-0-113-10.sslip.io
│     domínio próprio:  admin.minhaloja.com        (opcional)
└─ endpoint "S3/CDN"   9000  interna por padrão
      interno:  rustfs:9000  (outros serviços usam)
      se publicada → CDN:  cdn.minhaloja.com
```

## Quem define a exposição

**Template** declara as portas e o padrão:

```toml
[[endpoints]]
port   = 9001
label  = { en = "Console", "pt-BR" = "Console" }
public = true          # painel já nasce público

[[endpoints]]
port   = 9000
label  = { en = "S3 / CDN", "pt-BR" = "S3 / CDN" }
public = false         # nasce interno; o operador pode publicar (CDN)
```

Recebem endpoint web no catálogo: `adminer`, `pgadmin`, `n8n`, `uptime-kuma`,
`rabbitmq` (painel 15672) e `rustfs` (console 9001 público, S3 9000 interno).
Bancos (`postgres`, `mariadb`, `mongodb`, `redis-*`, `valkey-*`, `meilisearch`)
ficam sem endpoint — não têm página.

**App do GitHub** (sem template): o formulário de deploy tem a seção de portas,
onde se adiciona a porta, o rótulo e a exposição. Um bot/worker fica **interno**
e não ganha link.

## O nome automático (sslip.io)

Formato, único por instância:

```
<projeto>-<serviço>[-<rótulo-porta>].<ip-com-hífens>.sslip.io
loja-rustfs.203-0-113-10.sslip.io          (porta principal)
loja-rustfs-cdn.203-0-113-10.sslip.io      (segunda porta pública)
```

- `<projeto>-<serviço>` garante unicidade (slug de projeto é único; serviço é
  único no projeto). O rótulo da porta só entra quando o serviço tem mais de uma
  porta pública.
- Trava de unicidade no banco + sufixo numérico de último recurso
  (`loja-rustfs-2`), como o `UniqueName` de `internal/projects/naming.go`.
- O sslip é **derivado do IP** (`cfg.Edge.PublicIPs`), não uma linha no banco: o
  `edge` gera a rota pra cada endpoint público. Por isso o IP fica no nome — é
  como o DNS mágico resolve sem domínio próprio. Encurtar além disso não dá sem
  tirar o IP (e aí precisa de domínio de verdade).

### sslip desativa, não remove

Cada endpoint público tem `sslip_enabled` (começa ligado):

- adicionar um domínio próprio → o sslip **desativa sozinho** (continua existindo);
- remover o domínio próprio → o sslip **volta**;
- toggle manual também disponível.

O sslip nunca se perde; só domínios próprios são removíveis. Desligar tira a
rota do Caddy; religar traz de volta (certificado sslip fica em cache, custo zero).

## Os três níveis (open-source: funciona pra quem não configura nada)

O Hangar é código aberto; nada é amarrado a um operador. O sistema degrada com
elegância:

| Nível | Operador faz | Link | Certificado | Pra quem |
|---|---|---|---|---|
| **0 — zero config** | nada | `app.203-0-113-10.sslip.io` | HTTP-01 | todos, na hora |
| **1 — domínio simples** | compra domínio + aponta curinga | `app.apps.suaempresa.com` | HTTP-01 por subdomínio | self-hoster comum (até ~50 novos/semana) |
| **2 — escala/SaaS** | domínio + **token de DNS** | `app.apps.suaempresa.com` | **DNS-01 curinga (1 cert)** | cadastro em massa |

- **Nível 0** é o sslip, **sempre presente** — o padrão de fábrica.
- **Nível 1** some o IP do nome; o limite do Let's Encrypt (50 cert/semana por
  domínio registrado) só incomoda acima de ~50 subdomínios novos por semana.
- **Nível 2** resolve o limite: um certificado curinga `*.apps.suaempresa.com`
  via DNS-01 cobre infinitos subdomínios. É como EasyPanel/Coolify fazem o
  subdomínio em escala; o diferencial do Hangar é aceitar, por cima, o domínio
  próprio do cliente on-demand ([03](03-dominios-customizados-tls.md)).

### Limite do Let's Encrypt, por cenário

- **sslip**: `sslip.io` está na Public Suffix List, então cada `<ip>.sslip.io`
  conta como domínio registrado próprio → cada VPS tem seu orçamento. Sem
  problema. (Confirmar a PSL ao fixar o provedor mágico.)
- **domínio de cliente** (`loja.com.br`): cada um é domínio registrado próprio →
  50/semana só dele; na prática, ilimitado.
- **subdomínio sob a base do operador** (`a.apps.suaempresa.com`): todos somam
  no balde de `suaempresa.com`. Per-subdomínio (HTTP-01) estoura em ~50/semana;
  curinga (DNS-01) resolve com 1 certificado.

## Provedores de DNS (Nível 2)

DNS-01 precisa de um módulo compilado no Caddy. A imagem oficial do Hangar embute
um conjunto curado (Cloudflare, Route 53, DigitalOcean, Google, Hetzner, Gandi,
Porkbun, deSEC, DuckDNS…); o `config.toml` escolhe qual usar
(`dns_provider = "cloudflare"`). Quem usa um provedor fora da lista monta a
imagem com `xcaddy`. O registrador não precisa mudar: basta hospedar o DNS num
provedor com API (para `.com.br`, costuma-se apontar os nameservers pra
Cloudflare, mantendo o registro no Registro.br).

## Apontamento de DNS (quem aponta o quê)

| O quê | Quem | Onde | Vezes |
|---|---|---|---|
| `*.apps.suaempresa.com` (curinga da base) | **operador** | DNS da base | 1 |
| token DNS-01 | **operador** | só pra `suaempresa.com` | 1 |
| `loja.com.br` (domínio do cliente) | **o cliente** | registrador dele | 1 por cliente |

O cliente só cria um registro `A` pro IP do servidor (ou `CNAME` pra um host da
base); o painel mostra a instrução. O Hangar emite o certificado via HTTP-01
depois que `pointsHere` confirma o apontamento — sem nenhuma credencial do cliente.

## Mudanças de dados

- Nova tabela `endpoints` (id, service_id, port, label, public, sslip_enabled,
  created_at). A `InternalPort` atual de um serviço vira o primeiro endpoint na
  migração.
- `domains` ganha `endpoint_id` (o domínio aponta pra uma porta específica, não
  mais pro serviço inteiro).
- `config.toml`: `[edge] base_domain`, `dns_provider`, `dns_token` (lido pelo
  Caddy; protegido pelo modo 0600 do config e do diretório de dados, não cifrado).

## Ordem de implementação

1. Template `[[endpoints]]` + catálogo (universal, no binário; sem infra). ← base
2. Tabela `endpoints` + `domains.endpoint_id` + sqlc.
3. `edge/config.go`: rota sslip por endpoint público + issuer DNS-01; imagem do
   Caddy com os módulos de DNS.
4. Formulário de deploy (toggle público/interno) e card do serviço (endpoints +
   links + toggle sslip).

Fora de escopo: páginas públicas/LP e o modo sudo ([[sudo-reavaliar]] na memória).
