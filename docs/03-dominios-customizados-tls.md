# 03 — Domínios customizados e TLS

Este é o motivo de o Hangar existir. Leia com atenção.

## Por que o Traefik/Easypanel não resolve

O Traefik emite certificados para domínios que **já conhecem na configuração**
(regras `Host(...)`). Não existe no Traefik um "emita certificado na hora do
handshake, para qualquer nome, depois de me perguntar se pode". Então, para
aceitar `qualquerloja.com.br`, é preciso cadastrar cada domínio — ou usar
catch-all sem TLS válido. Daí a gambiarra.

O **Caddy tem isso nativo: On-Demand TLS**. Durante o handshake, se não houver
certificado para o nome pedido, ele consulta um endpoint de permissão (`ask`) e,
se autorizado, emite o certificado ali mesmo (leva poucos segundos na primeira
visita; depois fica em cache e renova sozinho).

## Situação típica no Easypanel

Num SaaS multi-loja (ex.: o projeto `minhaloja`) hospedado no Easypanel, o
problema costuma ser contornado com um arquivo
`/etc/easypanel/traefik/config/custom.yaml`, editado pelo SSH:

- Um router catch-all `HostRegexp(\`.+\`)` com `priority: 2`, para vencer o
  `error-page` do Easypanel, que tem prioridade 1.
- O router manda tudo para `minhaloja_web:8000`, e o
  `StoreMiddleware` resolve a loja pelo `StoreDomain`.

O roteamento funciona. O que **não** funciona é o certificado:

1. **O Traefik não emite certificado para `HostRegexp(.+)`.** O `certResolver`
   só pede certificado para nomes que ele consegue tirar da regra, e `.+` não
   tem nome nenhum. O Traefik entrega o **certificado padrão autoassinado**
   dele. Por isso é preciso usar "SSL Full" e **não** "Full (strict)" no
   Cloudflare: a origem não tem certificado válido.
2. **Só funciona para lojista que usa o Cloudflare com proxy laranja.** O
   Cloudflare dele cuida do HTTPS para o visitante e aceita o certificado
   inválido da origem. Para um lojista que **não** usa o Cloudflare:
   - Com registro `A` direto para o IP: o visitante vê erro de certificado.
   - Com `CNAME` para `host.minhaloja.com.br` (que é proxied): o Cloudflare
     recebe um domínio que não está em nenhuma conta dele e devolve erro
     (1001). O recurso que faz isso funcionar é o *Cloudflare for SaaS*, pago
     por hostname e que precisa de cadastro via API.
3. **É frágil:** depende de nomes internos do Easypanel (entrypoints `http`
   e `https`, prioridade do `error-page`, nome do container) que podem mudar
   numa atualização do Easypanel sem aviso.
4. `ALLOWED_HOSTS = ["*"]` em `production.py`: a proteção de Host fica só no
   `StoreMiddleware`.

No Hangar, o Caddy emite um certificado **válido** para cada domínio de loja
autorizado. Isso funciona com ou sem Cloudflare na frente: com Cloudflare dá
para usar "Full (strict)".

### Cloudflare for SaaS como opção complementar

Se a prioridade for **nunca expor o IP** e ter a proteção anti-DDoS do
Cloudflare para todas as lojas, a alternativa é o *Cloudflare for SaaS*
(Custom Hostnames). O lojista faz CNAME para `host.minhaloja.com.br`, e o
Cloudflare emite o certificado na borda dele. O Hangar pode integrar via API:
quando o Django cadastra um `StoreDomain`, cria o custom hostname. As duas
abordagens convivem: Caddy na origem com certificado válido + Cloudflare for
SaaS na frente para quem quiser. Decisão de custo × proteção a tomar na Fase 1.

## O risco (e por que "aceitar qualquer domínio" sem controle é perigoso)

Sem autorização, qualquer pessoa pode apontar milhares de domínios para o IP e:

- Esgotar os limites de emissão da Let's Encrypt para a nossa conta
  (rate limits por conta) → lojas reais deixam de conseguir certificado.
- Encher o disco com certificados.
- Usar nosso servidor para servir HTTPS "válido" em domínio de phishing,
  apontando para a nossa aplicação.

Por isso o `ask` **nunca** pode responder "sim" para tudo.

## Desenho

### Dois tipos de domínio no Hangar

| Tipo | Exemplo | Como funciona |
|---|---|---|
| **Fixo** | `painel.seudominio.com`, `api.seudominio.com` | Cadastrado no serviço; certificado emitido na hora do cadastro. |
| **Coringa** | `*.lojas.seudominio.com` | Cadastrado no serviço; cobre um nível de subdomínio. Certificado **por subdomínio, sob demanda** (veja abaixo). |
| **Dinâmico** | Qualquer domínio de lojista | Serviço marcado como "aceita domínios dinâmicos"; certificado emitido sob demanda após autorização. |

Apenas **um** serviço por servidor pode ser o destino de domínios dinâmicos
(o "catch-all"). No nosso caso, o app Django das lojas.

**Coringa sem certificado coringa.** Um certificado `*.exemplo.com` só sai
pelo desafio DNS-01, que exige credenciais da API do provedor de DNS; a edge
responde apenas HTTP-01. Por isso o coringa entra no Caddy como host
`*.exemplo.com` com uma política TLS `on_demand` só para ele: cada subdomínio
ganha o próprio certificado na primeira visita, depois que o `ask` aprova.
O `ask` aprova um subdomínio coberto por um coringa cadastrado sem consultar a
app, mas aplica a lista de bloqueio, o limite de nomes novos por hora (quem
visita inventa o nome; nomes aleatórios não podem gastar os limites do Let's
Encrypt) e, se configurado, a verificação de DNS. Regras: cobre um nível só
(`a.exemplo.com`, não `exemplo.com` nem `a.b.exemplo.com`); coringa sobre
sufixo público (`*.com.br`) é recusado; um nome cadastrado sozinho vence o
coringa que o cobre (rotas exatas vêm antes). A primeira visita a um
subdomínio novo leva alguns segundos a mais (emissão do certificado).

### Configuração gerada no Caddy (JSON, resumida)

```jsonc
{
  "apps": {
    "tls": {
      "automation": {
        "on_demand": {
          "permission": {
            "module": "http",
            "endpoint": "http://172.30.0.1:7701/internal/tls/ask"
          }
        },
        "policies": [
          { "subjects": ["painel.seudominio.com", "..."] },   // fixos
          { "on_demand": true }                               // todo o resto
        ]
      }
    },
    "http": {
      "servers": {
        "edge": {
          "listen": [":443"],
          "routes": [
            /* 1. rotas dos domínios fixos (match host exato) */
            /* 2. rota catch-all → upstream do serviço dinâmico */
          ]
        }
      }
    }
  }
}
```

> O endpoint `ask` escuta num listener separado (`172.30.0.1:7701`, gateway
> da rede `hangar-edge`), que tem **só** a rota `/internal/tls/ask` e só aceita
> conexões vindas do IP do Caddy. Não compartilha listener com o painel e não
> é alcançável da internet.

### O que o `/internal/tls/ask` verifica (em ordem)

1. **Formato**: nome DNS válido, minúsculo, punycode, sem IP literal, ≤ 253
   caracteres, não termina em domínio nosso que não esteja cadastrado.
2. **Lista de bloqueio**: domínios negados manualmente.
3. **Cache**: decisão positiva cacheada por 1 h, negativa por 5 min (evita
   martelar a aplicação). Erros passageiros (DNS, TXT ausente, limite, app
   fora do ar) não entram no cache.
4. **Domínios fixos cadastrados** → permite. **Subdomínio de um coringa
   cadastrado** → permite, depois do DNS e do limite por hora (itens 5 e 7).
5. **Caminho do DNS**: o nome resolve para um IP do servidor (**direto**) ou
   só para endereços do Cloudflare (**via Cloudflare**, nuvem laranja; lista
   oficial em `internal/edge/cloudflare.go`). Qualquer outra resposta, ou
   uma mistura, → nega (`dns_mismatch`) sem perguntar à aplicação. O caminho
   fica gravado na decisão e aparece na tela.
6. **TXT de posse** (opcional, por serviço): com "Exigir o TXT de posse"
   ligado, um domínio **novo** só passa se `_hangar.<domínio>` tiver o código
   `"hg-" + hex(HMAC-SHA256(segredo, "txt|" + domínio))[:12]`. O segredo é o
   mesmo `HANGAR_DOMAIN_CHECK_SECRET`, então a aplicação calcula o código sem
   guardar nada. Domínios já aprovados antes não precisam do TXT (ligar o
   switch não quebra renovações).
7. **Limite por hora**: no máximo N nomes novos aprovados por hora (padrão
   30, ajustável de 1 a 1000 na tela Domínios, auditado). Nomes já aprovados
   antes não contam.
8. **Pergunta à aplicação** (o ponto-chave):
   `GET http://<ip-do-container-app>:<porta>/.well-known/hangar/domain-check?domain=X`
   com `X-Hangar-Timestamp` e `X-Hangar-Signature` (HMAC-SHA256 de
   `domain|timestamp` com o segredo compartilhado). A aplicação responde
   `200` só se o domínio está cadastrado num cliente **ativo**, `404` se não,
   `403` se a assinatura não bate. Timeout curto; erro = negar.

### Cloudflare na frente

- Clientes podem usar a nuvem laranja (SSL em **Full**; Flexible gera
  redirecionamento infinito). Como o desafio HTTP pode não chegar até o
  servidor, as políticas sob demanda têm o emissor interno do Caddy como
  reserva: o Cloudflare em modo Full aceita esse certificado.
- O Caddy só confia em `CF-Connecting-IP` quando a conexão vem de um
  endereço do Cloudflare (`trusted_proxies` estrito); o IP do visitante vai
  para a aplicação em `X-Forwarded-For`/`X-Real-Ip`.
- O endereço dos clientes (`entrada.<domínio base>`, ou
  `entrada.<ip>.sslip.io` sem domínio base) deve ficar com a **nuvem
  cinza**: um CNAME de outra conta Cloudflare para um nome laranja dá o
  erro 1014. A tela Domínios avisa.

### Kit do desenvolvedor

Na seção Domínios do serviço que aceita domínios dos clientes, o botão
"Kit do desenvolvedor" mostra a chamada assinada, o código do TXT em
Python/Node/PHP (testado contra o Go em `domain_kit_test.go`), o texto
pronto para o cliente e um **teste** que roda DNS, TXT e a resposta da app
para um domínio sem gravar, cachear, contar no limite nem emitir nada
(só admin).

Cada decisão é registrada (tabela `tls_ask_log`) para auditoria e para a tela
de "Domínios dinâmicos" no painel.

### Do lado da aplicação Django

Três coisas a implementar no sistema de lojas:

1. **Endpoint de verificação** (`/.well-known/hangar/domain-check`):
   - Valida a assinatura HMAC e o timestamp; se inválido → 403.
   - Responde 200 se `StoreDomain.objects.filter(hostname=domain, is_active=True).exists()`
     (reaproveitando o cache Redis do `StoreMiddleware`), senão 404.
   - Esse caminho não é alcançável de fora: a rota catch-all do Caddy
     responde 404 para `/.well-known/hangar/*` antes do proxy.
2. **`ALLOWED_HOSTS`**: hoje é `["*"]` em produção, e quem barra Host
   desconhecido é o `StoreMiddleware`. Com o Caddy só aceitando domínios
   autorizados, isso já fica coberto na borda. Manter o middleware como
   segunda camada.
3. **Fluxo do lojista**: tela "Conectar domínio" com instruções de DNS e um
   botão "verificar" que confere o DNS antes de marcar a loja como pronta.

### Instruções de DNS para o lojista

| Caso | Registro |
|---|---|
| Subdomínio (`www.minhaloja.com.br`, `loja.minhaloja.com.br`) | `CNAME` → endereço dos clientes (`entrada.…`) |
| Domínio raiz (`minhaloja.com.br`) | `A` → IP da VPS, ou CNAME flattening do provedor |
| Com o TXT de posse ligado | `TXT` `_hangar.<domínio>` → código mostrado pela app |

Usar o CNAME sempre que possível: se o IP do servidor mudar, só o registro
do endereço dos clientes precisa ser atualizado.

Domínio raiz + `www`: cadastrar ambos na loja; o app redireciona um para o outro.

### Emissores de certificado

- Let's Encrypt como principal, ZeroSSL como fallback (comportamento padrão do
  Caddy quando há e-mail configurado).
- Conta ACME com e-mail real para avisos.
- Chaves ECDSA P-256.

### Renovação e limpeza

- Caddy renova automaticamente.
- Quando uma loja é desativada, a aplicação para de autorizar o domínio.
  Job diário do Hangar remove do storage certificados de domínios que não
  passam mais no `ask` há mais de 30 dias.

## Tela no painel

"Domínios dinâmicos" mostra: domínios com certificado, data de emissão/expiração,
últimas tentativas negadas (com motivo), limite de emissão atual e botão de
bloquear domínio.

## Testes obrigatórios desta parte

- Domínio não cadastrado na app → nenhum certificado emitido.
- App fora do ar → nega (fail-closed).
- Assinatura HMAC errada / timestamp velho → app retorna 403.
- 1000 domínios aleatórios em sequência → limite dispara, nenhum certificado.
- Domínio autorizado → certificado emitido e loja abre (teste com Pebble,
  o servidor ACME de teste da Let's Encrypt).

## Situação (Etapa 4, concluída)

O que está no ar:

- **Caddy gerenciado pelo Hangar**, ligado em `[edge] enabled = true` no
  `hangar.toml`. Container `hangar_caddy` na rede `hangar_edge`
  (172.30.0.0/24; o host é o .1, o Caddy é o .2), portas 80, 443/tcp e
  443/udp. Roda **sem root** (usuário do painel), sem nenhuma capability,
  com `no-new-privileges` e disco somente leitura. Memória medida: ~12 MB.
- A imagem oficial do Caddy marca o binário com uma capability de arquivo, e
  com `no-new-privileges` o kernel recusa executá-lo. O Hangar deriva, uma
  vez por versão, uma cópia local sem essa marca (`hangar-edge-caddy:<id>`).
  Não precisa dela: o Docker já libera portas baixas dentro do container.
- **Admin API só por socket unix** (`/var/lib/hangar/edge/admin/admin.sock`,
  0660). O painel manda a configuração inteira a cada mudança (`POST /load`)
  e também a grava em `bootstrap.json`, para o Caddy subir certo se reiniciar
  sozinho.
- **Domínios fixos** por serviço e **domínios dinâmicos** (um serviço por
  servidor), na seção "Domínios" do serviço. Ligar o dinâmico exige 2FA
  recente. O segredo HMAC é gerado pelo Hangar e chega na app sozinho, na
  variável `HANGAR_DOMAIN_CHECK_SECRET`, no próximo deploy; revelar exige 2FA
  e fica na auditoria.
- **Página "Domínios"**: pedidos de certificado recentes (agregados por hora,
  com motivo), lista de bloqueio, bloquear e desbloquear.
- O `ask` faz, nesta ordem: formato, bloqueio, cache, domínio fixo, teto de
  domínios **novos** por hora (padrão 30; quem já foi aprovado antes não
  conta, para uma enxurrada não travar renovações), pergunta assinada à app e,
  se `public_ips` estiver preenchido, DNS apontando para cá.
- Resposta da app: `200` libera, `404` nega (cache de 5 min), `403` é
  assinatura recusada, ou seja, segredo desatualizado: vira o motivo "a app
  recusou a assinatura" e **não** entra em cache, para voltar a funcionar
  assim que o deploy entregar o segredo novo. Erro ou demora acima de 2 s
  nega sem cache.
- HTTP na porta 80 redireciona para HTTPS (308) em qualquer host, inclusive
  domínios de cliente, e responde os desafios HTTP-01.
- Retenção do `tls_ask_log`: negações 30 dias, aprovações 180 dias (servem
  para isentar renovações do teto).
- Projetos com nome `edge` ou `hangar` são recusados (colidiriam com a rede e
  os containers do próprio Hangar).

Testado na VM com Pebble (o servidor ACME de teste da Let's Encrypt) e o
Django de laboratório (`examples/lab-multidominio/`), 22 verificações:
certificado para loja ativa e para domínio fixo; nenhum certificado para
domínio que não é loja, para app fora do ar (e volta sozinho quando ela
volta), para domínio bloqueado e acima do teto por hora; app recusa HMAC
errado; caminho interno bloqueado na internet; redirecionamento HTTP;
reiniciar o Caddy e o painel não reemite nem perde nada.

**Ficou para depois:**

- Wildcard (`*.lojas.seudominio.com`) via DNS-01: precisa do provedor de DNS.
- ZeroSSL como segundo emissor: hoje só Let's Encrypt (ou o `acme_ca`
  configurado).
- Teto por domínio registrável (hoje o teto é por servidor).
- Listar certificados com data de expiração na tela e o job que limpa
  certificados de domínios que não passam mais no `ask`.
- Teste com domínio real na VPS (Etapa 1, esperando VPS e domínio).

