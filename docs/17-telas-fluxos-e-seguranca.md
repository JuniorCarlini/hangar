# 17 — Telas, fluxos e segurança

Este documento junta tudo: **cada tela do Hangar, como funciona, quem pode
usar, que proteção tem e como o fluxo acontece por trás.** É a referência para
implementar a interface.

> Verdade honesta: não existe sistema sem brecha. O que existe é **defesa em
> camadas**: para chegar em algo importante, o atacante precisa vencer várias
> barreiras independentes, e cada tentativa deixa rastro e gera alerta. A seção
> final lista o risco que sobra mesmo assim.

---

## Parte 1 — A base: proteções que valem para TODAS as telas

### 1.1 O caminho de uma requisição

Toda requisição ao painel passa por esta esteira, **nesta ordem**. Se qualquer
etapa recusa, a requisição para ali.

```
 Navegador
    │ HTTPS (TLS 1.3, HSTS)
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ CADDY                                                           │
│  ① Só aceita o host do painel (painel.seudominio.com)           │
│  ② Allowlist de IP (opcional)  ③ Limite de requisições por IP   │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ HANGARD — cadeia de middlewares                                 │
│  ④ Host exato? (anti DNS-rebinding)              não → 421      │
│  ⑤ Cabeçalhos de segurança (CSP, HSTS, frame...) sempre         │
│  ⑥ Tamanho máx. do corpo, timeout de leitura                    │
│  ⑦ Rota existe NO REGISTRO DE ROTAS?             não → 404      │
│  ⑧ Sessão válida? (cookie __Host-, hash no banco) não → /login  │
│  ⑨ Sessão ociosa > 30 min ou > 12 h?              → /login      │
│  ⑩ Método de escrita? → token CSRF + Origin/Sec-Fetch-Site      │
│  ⑪ Papel do usuário permite esta ação?           não → 403      │
│  ⑫ O recurso pedido (ID) pertence ao escopo?     não → 404      │
│  ⑬ Ação crítica? → modo sudo válido?             não → pede 2FA │
│  ⑭ Rate limit por usuário e por ação                            │
│  ⑮ Validação estrita da entrada (tipos, regex, limites)         │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
                         HANDLER (a ação)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  ⑯ Audit log (quem, o quê, quando, IP, resultado) — encadeado  │
│  ⑰ Evento de segurança? → alerta Telegram/e-mail               │
│  ⑱ Resposta: HTML escapado pelo templ, sem segredos            │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 "Negado por padrão": o registro de rotas

Nenhuma rota existe sem declarar sua política. É código, não convenção:

```go
r.Handle("POST /services/{id}/env", h.UpdateEnv, policy{
    Role:  RoleOperator,      // papel mínimo
    Sudo:  false,             // exige reautenticação recente?
    Audit: "service.env.update",
    Rate:  "30/min",
    Scope: scopeService,      // confere se {id} existe e o usuário pode vê-lo
})
```

- Um teste no CI percorre todas as rotas e **falha o build** se alguma não tem
  política, se uma rota de escrita não tem auditoria, ou se uma rota da lista
  de ações críticas não exige sudo.
- Isso elimina a brecha mais comum em painéis: "esqueci de proteger essa rota
  nova".

### 1.3 Papéis e permissões

| Ação | Dono | Admin | Operador | Leitor |
|---|:-:|:-:|:-:|:-:|
| Ver projetos, serviços, métricas, logs | ✅ | ✅ | ✅ | ✅ |
| Deploy, restart, rollback | ✅ | ✅ | ✅ | ❌ |
| Editar variáveis (valores secretos ficam mascarados) | ✅ | ✅ | ✅ | ❌ |
| Revelar segredo 🔒 | ✅ | ✅ | ❌ | ❌ |
| Criar/apagar serviço, volume; limitar o tamanho de um disco 🔒 | ✅ | ✅ | ❌ | ❌ |
| Domínios, portas, conexões entre projetos 🔒 | ✅ | ✅ | ❌ | ❌ |
| Terminal no container 🔒 | ✅ | ✅ | ❌ | ❌ |
| Backups: baixar/restaurar 🔒 | ✅ | ✅ | ❌ | ❌ |
| Links públicos de status 🔒 | ✅ | ✅ | ❌ | ❌ |
| Usuários e papéis 🔒 | ✅ | ❌ | ❌ | ❌ |
| Configurações do servidor, modo de acesso 🔒 | ✅ | ❌ | ❌ | ❌ |
| Auditoria (ver) | ✅ | ✅ | ❌ | ❌ |

🔒 = pode exigir **modo sudo** (senha ou 2FA de novo, há pouco). Quanto, o dono escolhe em
Minha conta → Nível de segurança, acima da verificação em duas etapas (`auth.Level`):

| Nível | Pede de novo | Confirmação vale | Sai parado após |
|---|---|---|---|
| Básico | nada (só o login; ações perigosas mantêm a confirmação digitada) | — | 12 h |
| Médio (padrão) | o que não tem volta ou mostra segredo (`auth.SudoCritical`): apagar projeto/serviço/disco, revelar segredos, terminal, baixar/restaurar backup, chaves e destinos de backup, equipe | 30 min | 2 h |
| Avançado | todo 🔒, inclusive domínios, portas, imagem, limites, marca, alertas, links de status e atualização (`auth.SudoStrict`) | 5 min | 30 min |

Trocar o nível pede a senha em qualquer nível (`auth.SudoAlways`) e vira alerta de segurança.

Permissão por projeto (pós-MVP): um operador pode ver só o projeto "minhaloja".

### 1.4 Login e sessão

| Controle | Como |
|---|---|
| Senha | ≥ 14 caracteres, checada contra lista de senhas vazadas, hash argon2id |
| 2FA | **Obrigatória** para donos e admins; para todos enquanto "Exigir 2FA de todos" (Equipe → Segurança) estiver ligada, o padrão. TOTP (passkey planejada). Sem 2FA a conta só alcança a tela de cadastro |
| Passkey | Recomendada: imune a phishing (vinculada ao domínio) |
| Força bruta | 5 tentativas / 15 min por IP e por usuário → atraso crescente → bloqueio após 20 |
| Enumeração | Mesma resposta e mesmo tempo para usuário inexistente |
| Recuperação | **Não existe "esqueci minha senha" por e-mail** (é a porta mais atacada). Recuperação: códigos de recuperação ou CLI no servidor via SSH (`hangard user password`) |
| Cookie | `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`; ID de 256 bits, só o hash no banco |
| Expiração | 30 min ocioso, 12 h no máximo; novo ID após login e após sudo |
| Vínculo | Sessão anotada com IP/agente; mudança brusca (país/ASN) → pede 2FA de novo |
| Login novo | Alerta "login de IP novo" no Telegram/e-mail |

### 1.5 Navegador

| Cabeçalho | Valor | Protege contra |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` | XSS, injeção de script |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | rebaixamento para HTTP |
| `X-Frame-Options` | `DENY` | clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `no-referrer` | vazamento de URL/tokens |
| `Permissions-Policy` | tudo desligado (câmera, microfone, geolocalização…) | abuso de APIs |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | `same-origin` | ataques entre abas/origens |
| `Cache-Control` | `no-store` em páginas autenticadas | dados em cache compartilhado |

Sem CDN externo: todo JS/CSS sai do próprio binário.

### 1.6 Botão de pânico — "Modo trancado"

Na barra superior (só Dono) e por CLI (`hangard lockdown`):

1. Encerra **todas** as sessões, inclusive a sua.
2. Desliga todos os links públicos de status e webhooks de Git.
3. O painel passa a responder **só em 127.0.0.1** (acesso apenas por túnel SSH).
4. Envia alerta para todos os canais.

Os containers continuam rodando: as lojas não caem. Sair do modo trancado só
é possível pela CLI no servidor.

**Como ficou (Etapa 8):** item **Trancar painel** no menu da conta (só
Dono; confirma em vermelho; atalho Cmd/Ctrl+Shift+L, porque Cmd+L é do
navegador) e `hangard lockdown` no servidor. Trancado, toda requisição que
não tenha as duas pontas em loopback (túnel SSH) recebe 403, inclusive o
login; quem entra pelo túnel vê uma faixa vermelha com o comando para
destrancar. `hangard lockdown off` destranca e `hangard lockdown status`
mostra o estado; o painel em execução percebe a mudança da CLI em até
2 s. O item 2 (links de status e webhooks de Git) passa a valer quando
essas funções existirem (Etapas 10 e 11).

---

## Parte 2 — Mapa de telas

```
Hangar
├── 🔓 Login ─── 2º fator ─── (recuperação)
├── 📊 Visão geral do servidor
├── 📁 Projetos
│   └── Projeto
│       ├── Serviços (lista)
│       ├── Rede (conexões com outros projetos)
│       └── Serviço
│           ├── Visão geral      ├── Domínios     ├── Logs
│           ├── Deploys          ├── Portas       ├── Métricas
│           ├── Ambiente         ├── Volumes      ├── Terminal 🔒
│           ├── Recursos         ├── Backups      ├── Atualizações
│           └── Avançado / Zona de perigo 🔒
├── ➕ Novo serviço (assistente)
├── 🌐 Domínios dinâmicos (TLS)
├── 🔌 Portas abertas (todas)
├── 🛡️ Atualizações e vulnerabilidades
├── 💾 Backups (destinos, agendas, histórico)
├── 🔔 Alertas e notificações (canais)
├── 📡 Links de status
├── 🖥️ Servidores (futuro)
├── ⚙️ Administração
│   ├── Usuários e papéis 🔒
│   ├── Auditoria
│   └── Configurações do servidor 🔒
├── 👤 Minha conta (senha, 2FA, passkeys, sessões)
└── 🌍 Página pública de status (fora do painel)
```

---

## Parte 3 — Cada tela

Formato: **desenho → o que faz → segurança → fluxo**.

### 3.1 Login

```
┌──────────────────────────────────────┐
│              ✈ HANGAR                │
│                                      │
│  E-mail   [_______________________]  │
│  Senha    [_______________________]  │
│                                      │
│          [ Entrar ]                  │
│  ───────────── ou ─────────────      │
│          [ 🔑 Entrar com passkey ]   │
└──────────────────────────────────────┘
          │ senha certa
          ▼
┌──────────────────────────────────────┐
│  Código do autenticador              │
│  [ _ _ _  _ _ _ ]                    │
│  Usar código de recuperação          │
└──────────────────────────────────────┘
```

**Segurança:** tudo da seção 1.4. A tela não diz se o erro foi no e-mail ou na
senha. O formulário tem CSRF mesmo antes do login (impede *login CSRF*). O
estado "senha ok, falta 2FA" dura 5 min e é de uso único.

**Fluxo:**

```
senha ──► argon2id confere ──► falhou? ──► contador +1, atraso, audit "login.fail"
                │ ok                          (20 falhas → conta bloqueada + alerta)
                ▼
        2FA (TOTP ±1 janela, código não reutilizável) ou passkey
                │ ok
                ▼
   cria sessão nova ─► audit "login.ok" ─► IP novo? ─► alerta "login de IP novo"
```

**Primeiro usuário:** pela tela de primeiro acesso, aberta só enquanto não
há usuário e por 30 minutos depois que o painel liga (reabre com `sudo
systemctl restart hangard`), ou pela CLI (`hangard user create`). Ver
[04](04-seguranca.md).

---

### 3.2 Visão geral do servidor

```
┌─ Hangar ─────────────────────────────────────────── 🔒Trancar  👤 Junior ─┐
│ CPU ▁▂▃▅▃▂ 37%   RAM ▃▃▄▄▅ 61%   Disco 48%   Rede ↓1.8 ↑5.2 MB/s        │
│ Uptime 14 d   Containers 11 🟢 1 🟡 0 🔴   Alertas ativos: 0              │
├───────────────────────────────────────────────────────────────────────────┤
│ Quem está consumindo mais                         ordenar: [CPU ▼]        │
│ ┌──────────────────────┬──────┬──────────┬─────────┬────────┐            │
│ │ Serviço              │ CPU  │ RAM      │ Rede    │ Estado │            │
│ │ minhaloja_web        │ 22%  │ 1.1/2 GB │ 4.1MB/s │ 🟢     │            │
│ │ minhaloja_postgres   │  8%  │ 1.4/2 GB │ 0.3MB/s │ 🟢     │            │
│ │ minhaloja_worker     │  6%  │ 0.6/1 GB │ 0.1MB/s │ 🟡 3 restarts │     │
│ └──────────────────────┴──────┴──────────┴─────────┴────────┘            │
│ ⚠ 2 vulnerabilidades críticas · 1 porta exposta para qualquer IP         │
└───────────────────────────────────────────────────────────────────────────┘
```

**Faz:** saúde do servidor, ranking de consumo, avisos que exigem atenção.
**Segurança:** só leitura; todos os papéis. Os dados ao vivo chegam por SSE
autenticado (mesma sessão, conferência de `Origin`). Avisos de segurança
(portas abertas, CVEs) ficam sempre visíveis no topo.

---

### 3.3 Projetos e Projeto

```
┌ Projeto: minhaloja ───────────────────────────────── [+ Novo serviço] ┐
│ Serviços                                                               │
│  🟢 web          app       3 réplicas   loja.minhaloja.com.br + dinâmicos│
│  🟢 worker       app       1                                           │
│  🟢 postgres     Postgres 18                                           │
│  🟢 redis        Redis 8                                               │
│                                                                        │
│ Rede ─────────────────────────────────────────────────────────────    │
│  Isolado. Conectado com: [ site-institucional ✕ ]  [+ Conectar]       │
└────────────────────────────────────────────────────────────────────────┘
```

**Segurança:** criar projeto (Admin+), apagar projeto 🔒 exige digitar o nome
e só é possível sem serviços. "Conectar com projeto" 🔒 mostra antes o que
passa a se enxergar ("web do projeto X poderá acessar postgres do projeto Y").

---

### 3.4 Serviço — abas

#### Visão geral
Estado, imagem/commit atual, uptime, botões **Deploy / Reiniciar / Parar**,
mini-gráficos, último deploy. Operador+. Toda ação auditada; "Parar" pede
confirmação.

#### Deploys

```
┌ Deploys ─────────────────────────────────────────────── [ Deploy agora ] ┐
│ #48  🟢 ao vivo   a1b2c3 "fix frete"     há 2 h    por Junior  [log]     │
│ #47  ⚪ anterior  9f8e7d "checkout"      ontem     webhook     [↩ voltar]│
│ #46  🔴 falhou    healthcheck timeout    ontem     webhook     [log]     │
└──────────────────────────────────────────────────────────────────────────┘
```

**Fluxo:** ver [07](07-deploy-e-builds.md). O pré-deploy (`migrate`) roda
uma vez. Falhou antes da troca → a versão antiga nunca saiu do ar.
**Segurança:** Operador+. O log de build passa por filtro que **mascara
segredos conhecidos** (qualquer valor de env secreta que apareça vira `••••`).
Webhook do Git: assinatura HMAC, ID de entrega não reutilizável (anti-replay),
só o branch configurado.

#### Ambiente (variáveis)

```
┌ Ambiente ───────────────────────────────────────────────────────────────┐
│ DJANGO_SETTINGS_MODULE  config.settings.production                       │
│ DATABASE_URL            ${{minhaloja_postgres.DATABASE_URL}}   🔗        │
│ SECRET_KEY              ••••••••••••   🔐 secreta   [👁 revelar 🔒]     │
│ R2_SECRET_ACCESS_KEY    ••••••••••••   🔐 secreta   [👁 revelar 🔒]     │
│ [+ Adicionar]   [Importar .env]        ⚠ Alterações pendentes: redeploy  │
└──────────────────────────────────────────────────────────────────────────┘
```

**Segurança:**
- Valores secretos cifrados (XChaCha20-Poly1305) e **nunca** enviados ao
  navegador, nem escondidos no HTML. "Revelar" é uma requisição separada 🔒,
  auditada, e o valor some da tela após 30 s.
- Editar um secreto = escrever um valor novo; o antigo não é mostrado.
- Importar `.env`: o conteúdo é lido no servidor e nada é salvo antes da sua
  confirmação na prévia.
- Referências `${{...}}` evitam copiar senhas entre serviços.

#### Domínios

```
┌ Domínios ───────────────────────────────────────────────────────────────┐
│ loja.minhaloja.com.br        🔒 cert válido até 12/jan   [remover 🔒]   │
│ *.minhaloja.com.br           🔒 wildcard (DNS-01)        [remover 🔒]   │
│ [✓] Aceitar domínios dinâmicos de lojistas  → ver Domínios dinâmicos    │
│     Endpoint de verificação: /.well-known/hangar/domain-check  [testar] │
│ [+ Adicionar domínio]                                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

**Segurança:** Admin+ 🔒. Ao adicionar, o Hangar confere se o DNS já aponta
para o servidor antes de pedir o certificado (não gasta o limite da Let's
Encrypt à toa). Só **um** serviço do servidor pode aceitar domínios
dinâmicos. O botão "testar" chama a verificação com um domínio cadastrado e
outro inventado, e mostra se a aplicação responde certo nos dois casos.

#### Portas

```
┌ Portas ─────────────────────────────────────────────────────────────────┐
│ 5433 → 5432 TCP   Acesso: só 189.10.20.30        expira: nunca  [✕ 🔒] │
│                                                                          │
│ [+ Expor porta]                                                          │
│   Porta no servidor [5434]   Porta do container [5432]   [TCP ▼]        │
│   Quem pode acessar:  ( ) Qualquer IP                                    │
│                       (•) Somente estes IPs [189.10.20.30, ...]          │
│                       ( ) Só localhost (túnel SSH)                       │
│   Expira: [nunca ▼]                                                      │
│   ⚠ Isto é um banco de dados. Expor para qualquer IP atrai varreduras.  │
│   Comando do túnel: ssh -L 5434:127.0.0.1:5434 usuario@vps  [copiar]    │
└──────────────────────────────────────────────────────────────────────────┘
```

**Fluxo:**

```
salvar 🔒 ─► valida porta livre e fora da lista reservada (22, 80, 443, 7700, 7701)
          ─► publica no Docker (0.0.0.0 ou 127.0.0.1)
          ─► escreve regra nftables na chain DOCKER-USER (IPs permitidos)
          ─► confere de fato: regra presente? porta respondendo como esperado?
          ─► audit "port.expose" + aparece em "Portas abertas"
expira ─► job remove a publicação e a regra ─► audit + aviso
```

#### Volumes
Lista, tamanho, ponto de montagem. Apagar volume 🔒 só com o serviço parado,
digitando o nome; oferece backup antes. Bind mounts do host são proibidos,
exceto em `/srv/hangar-data/` (Admin+, com aviso).

#### Recursos
Limites de CPU/RAM/PIDs, réplicas (futuro), reiniciar automaticamente,
healthcheck. Mostra quanto o servidor ainda tem livre. Mudança → redeploy.

#### Logs

```
┌ Logs  [ao vivo ●]  [stdout ✓] [stderr ✓]  filtro [checkout____]  [⏸] [⬇] ┐
│ 18:42:01 INFO  POST /checkout/confirmar 200 182ms                         │
│ 18:42:03 WARN  frete: timeout correios (2s), usando tabela                │
└───────────────────────────────────────────────────────────────────────────┘
```

**Segurança:** Leitor+. **Log é dado não confiável**: um atacante pode
escrever `<script>` num campo que vai parar no log. Tudo é escapado e as
cores ANSI são convertidas em classes CSS fixas (nunca HTML cru). Baixar log
é auditado. O stream (SSE) encerra sozinho quando a sessão expira.

#### Métricas
Gráficos de 1 h / 24 h / 7 d / 90 d (CPU, RAM, rede, disco). Só leitura.

#### Terminal 🔒

```
┌ Terminal — minhaloja_web  (sessão gravada · encerra em 14:59) ─────────┐
│ $ python manage.py shell                                               │
│ >>>                                                                    │
└────────────────────────────────────────────────────────────────────────┘
```

**É a tela mais perigosa do painel** (é execução de comando dentro do
container). Por isso:

| Controle | Detalhe |
|---|---|
| Papel | Admin+ |
| Sudo | Obrigatório, sempre, a cada abertura |
| WebSocket | Só com sessão válida + `Origin` conferido + token de uso único e curta duração na URL |
| Tempo | Máx. 15 min por sessão; ociosa por 5 min fecha |
| Gravação | Tudo que entra e sai fica gravado (cifrado) e referenciado no audit log |
| Usuário | Abre como o usuário não-root da imagem, quando houver |
| Alerta | "Terminal aberto em minhaloja_web por Junior" vai para o Telegram |
| Desligável | Configuração do servidor pode desligar o terminal de vez |

#### Backups (do serviço)
Agenda, destino, histórico, **Baixar backup agora** 🔒 (gera o `pg_dump`,
entrega por link de uso único válido por 5 min, auditado), **Restaurar** 🔒
(padrão: num serviço novo; sobrescrever exige digitar o nome do serviço).

#### Atualizações (do serviço)
Lista de bibliotecas/imagem com versão nova ou CVE, gravidade e linha a
mudar. "Ignorar" exige motivo (auditado).

#### Avançado / Zona de perigo 🔒
Comando, entrypoint, usuário, rede, capabilities extras, **apagar serviço**.
Tudo com aviso explicando o risco. Opções proibidas (privileged, docker.sock)
**não aparecem**: não existe botão para elas.

---

### 3.5 Novo serviço (assistente)

```
 ① Tipo            ② Origem               ③ Configuração        ④ Revisão
 ( ) App           Imagem [________]      Nome [web]            Resumo + avisos
 ( ) Postgres      Git    [repo/branch]   Porta interna [8000]  de segurança
 ( ) Redis         Token Git (só leitura) Recursos [512M/1cpu]  [ Criar ]
 ( ) ...
```

**Segurança:** nome validado (`^[a-z][a-z0-9-]{1,30}$`); imagem resolvida
para digest; URL do Git/registry passa pelo **filtro anti-SSRF** (seção 4); o
token do Git é cifrado e testado com permissão só de leitura. Templates já
saem com hardening, senha forte gerada e sem porta exposta.

---

### 3.6 Domínios dinâmicos

```
┌ Domínios dinâmicos ── serviço: minhaloja_web ── limite: 7/30 por hora ───┐
│ Certificados ativos (214)                         buscar [_________]     │
│  criartdecor.com.br     emitido 02/out   expira 31/dez   🟢              │
│  ...                                                                     │
│ Negados recentemente                                                     │
│  xn--pypal-4ve.com      não cadastrado na aplicação   3x   [bloquear 🔒] │
│  teste123.ru            DNS não aponta para o servidor 1x                │
└──────────────────────────────────────────────────────────────────────────┘
```

**Fluxo completo:** ver [03](03-dominios-customizados-tls.md).

```
visitante ─► Caddy: sem cert ─► ask ─► Hangar:
   formato ok? ─► bloqueado? ─► cache? ─► app autoriza (HMAC)? ─► DNS aponta? ─► limite ok?
        │ qualquer "não"                                                 │ todos "sim"
        ▼                                                                ▼
   handshake recusado + log                              Let's Encrypt emite ─► loja abre
```

**Segurança:** Admin+. Fail-closed: se a aplicação ou o Hangar estiverem fora,
nenhum certificado novo é emitido (os existentes continuam valendo). Pico de
negações dispara alerta (sinal de alguém testando).

---

### 3.7 Portas abertas (visão global)

Todas as portas publicadas no servidor, inclusive as que **não** foram
criadas pelo Hangar (detectadas no Docker e no sistema). Porta desconhecida
aberta → alerta. Fechar 🔒.

---

### 3.8 Atualizações e vulnerabilidades

```
┌ Atualizações ── 🔴 2  🟠 5  🟡 14  ⚪ 3 ──────────── [Verificar agora] ───┐
│ 🔴 minhaloja_web   Django 5.2.3 → 5.2.7   CVE-2026-XXXX   requirements…  │
│ 🔴 servidor        Docker 29.5.0 → 29.8.2  correção de segurança          │
│ 🟠 minhaloja_web   imagem python:3.13-slim  openssl  CVE-…                │
└───────────────────────────────────────────────────────────────────────────┘
```

Ver [14](14-atualizacoes-de-dependencias.md). Leitor+ vê; ignorar exige
Operador+ e motivo.

---

### 3.9 Backups

Plano completo e desenhos em [09](09-backups.md). Destinos (S3/R2/B2),
agendas, histórico com tamanho e checksum, teste de restauração, WAL contínuo
(voltar a qualquer minuto), Kit de recuperação. **Segurança:** credenciais S3 cifradas; arquivos cifrados com
**age** antes de sair (a chave privada fica com você, fora do servidor:
quem roubar o bucket não lê nada); endpoint S3 passa pelo filtro anti-SSRF;
restauração 🔒 confere o checksum e descompacta com limite de tamanho (anti
*zip bomb*) e sem caminhos absolutos ou `..` (anti *path traversal*).

---

### 3.10 Alertas e notificações

```
┌ Canais ─────────────────────────────────────────────────────────────────┐
│ Telegram  @hangar_bot → chat 12345     🔴🟠 alertas, segurança  [testar] │
│ E-mail    junior@...                   resumo semanal           [testar] │
│ Webhook   https://n8n…  (HMAC)         tudo                     [testar] │
├ Regras ─────────────────────────────────────────────────────────────────┤
│ [✓] Container caiu  [✓] OOM  [✓] Disco > 85%  [✓] Login de IP novo  ...  │
└──────────────────────────────────────────────────────────────────────────┘
```

**Segurança:** tokens cifrados; mensagens **sem dados sensíveis** (sem IP do
servidor, sem segredos, sem nomes de cliente); webhooks de saída assinados e
com filtro anti-SSRF. **Alertas de segurança não podem ser desligados**
(login de IP novo, conta bloqueada, terminal aberto, segredo revelado, porta
aberta para qualquer IP, usuário criado, modo trancado).

**Como ficou (Etapa 8):** em vez de escolher categorias por canal, cada
canal escolhe o nível mínimo (tudo / avisos e críticos / só críticos) e os
alertas de segurança chegam em todos. As regras valem para o servidor
inteiro (não por canal). Detalhes em [06](06-monitoramento-e-logs.md).
Leitor e Operador veem o histórico só com os alertas do servidor; canais,
regras, silêncio e entregas são de Admin+, e revelar, pausar ou remover um
canal pede sudo.

---

### 3.11 Links de status

```
┌ Links de status ────────────────────────────────────────────── [+ Novo] ┐
│ Monitor de casa   apelidos   IP: 189.10.20.30   nunca expira  312 acessos│
│ Sócio             genérico   senha ✓            expira 30/out  4 acessos │
└──────────────────────────────────────────────────────────────────────────┘
```

Ver [15](15-painel-publico-de-status.md). Criar/revogar 🔒. O link aparece
**uma vez** na criação.

---

### 3.12 Servidores (futuro)

Lista de servidores, recursos, estado do agente, "Adicionar servidor" (gera
token de uso único, válido por 15 min) e "Remover" 🔒 (revoga o certificado
do agente na hora).

---

### 3.13 Administração

**Usuários e papéis** (Dono 🔒): convidar gera link de uso único (24 h) em que
a pessoa define senha **e 2FA** antes de entrar. Rebaixar/remover encerra as
sessões dela na hora. Não é possível remover o último Dono.

**Auditoria** (Admin+): filtro por pessoa, ação, período; exportar; botão
**Verificar integridade** (recalcula a cadeia de hashes e acusa adulteração).
Ninguém, nem o Dono, apaga registros pela interface.

```
18:40  Junior  189.10.20.30  secret.reveal   minhaloja_web/SECRET_KEY   ok
18:35  Junior  189.10.20.30  sudo.ok         —                          ok
18:12  —       45.x.x.x      login.fail      junior@...                 bloqueado
```

**Configurações do servidor** (Dono 🔒): modo de acesso (bunker/público),
allowlist de IP do painel, e-mail ACME, limite de emissão dinâmica,
terminal liga/desliga, atualização do Hangar (verifica assinatura), status da
chave mestra ("guardada fora do servidor?" — lembrete até você confirmar).

---

### 3.14 Minha conta

Trocar senha (pede a atual + 2FA), gerenciar passkeys e TOTP, gerar novos
códigos de recuperação 🔒, **sessões ativas** com "encerrar" (e "encerrar
todas as outras").

---

### 3.15 Página pública de status (fora do painel)

Listener separado, só leitura, dados agregados e anonimizados, sem cookies
de sessão, cache de 10 s, rate limit. Ver [15](15-painel-publico-de-status.md).

---

## Parte 4 — Lista de brechas e como cada uma é fechada

| # | Ataque | Onde poderia acontecer | Mitigação |
|---|---|---|---|
| 1 | Força bruta / senhas vazadas | Login | Rate limit, bloqueio, 2FA obrigatório, lista de senhas vazadas |
| 2 | Phishing da senha | Login | Passkey (não funciona em domínio falso); alerta de login de IP novo |
| 3 | Roubo de sessão | Cookie | `__Host-`, HttpOnly, Secure, SameSite=Strict, expiração curta, revalidação em mudança de IP/ASN |
| 4 | CSRF | Toda escrita | Token + `Origin`/`Sec-Fetch-Site`, SameSite=Strict |
| 5 | XSS | Logs, nomes, mensagens de commit, respostas externas | templ escapa tudo, CSP sem inline, ANSI convertido em classes |
| 6 | Clickjacking | Todas | `frame-ancestors 'none'` + `X-Frame-Options: DENY` |
| 7 | IDOR (mudar o ID na URL) | Todas as rotas com `{id}` | Escopo checado no middleware (⑫); resposta 404, não 403 |
| 8 | Rota esquecida sem proteção | Código novo | Registro de rotas com política obrigatória + teste no CI |
| 9 | SQL injection | Banco | Só queries do sqlc (parametrizadas), sem SQL montado com string |
| 10 | Injeção de comando | Docker, Git, backups | Só API do Docker; nada vai para shell; argumentos validados |
| 11 | **SSRF** (fazer o servidor acessar rede interna) | URL de Git, registry, S3, webhook, verificação de domínio | Filtro: bloqueia IPs privados, loopback, link-local (169.254.169.254, metadados da nuvem), resolve o DNS e fixa o IP (anti DNS-rebinding), só HTTPS, sem seguir redirect para IP proibido |
| 12 | DNS rebinding no painel | Painel | Host exato obrigatório (④) |
| 13 | Path traversal | Download de log/backup, restauração | IDs no lugar de caminhos; restauração rejeita `..` e caminhos absolutos |
| 14 | Zip/tar bomb | Restauração, importar `.env` | Limites de tamanho e de proporção de compressão |
| 15 | Replay de webhook | `/hooks/git` | HMAC + ID de entrega único + janela de tempo |
| 16 | Abuso de domínio dinâmico | Caddy | `ask` fail-closed, HMAC com a app, DNS, limite, bloqueio |
| 17 | Banco exposto | Portas | Padrão sem porta; opção por IP/localhost no `DOCKER-USER`; aviso; tela global; expiração |
| 18 | Movimento lateral entre projetos | Redes | Rede por projeto; conexão só explícita 🔒 |
| 19 | Fuga de container | Containers | no-new-privileges, cap_drop ALL, seccomp, sem privileged, sem docker.sock, limites, não-root |
| 20 | DoS no painel | Painel | Caddy + rate limit + limite de corpo/tempo; painel fora da internet em modo bunker |
| 21 | DoS via status público | `/s/` | Cache de 10 s, rate limit, listener separado |
| 22 | Vazamento de segredo | Logs, telas, erros, backups | Cifrado no banco; nunca no HTML; mascaramento nos logs; tipo `Secret` no código; backups cifrados com age |
| 23 | Roubo do banco do painel | Disco | Segredos cifrados com chave mestra fora do banco |
| 24 | Roubo da chave mestra | Disco | 0400, usuário dedicado; opcional systemd-creds/TPM |
| 25 | Admin API do Caddy | Caddy | Unix socket, nunca porta TCP |
| 26 | Supply chain | Dependências, imagens, atualização do Hangar | Digest fixo, govulncheck no CI, binário assinado (cosign) e verificado |
| 27 | Operador mal-intencionado ou conta comprometida | Painel | Papéis, sudo, auditoria encadeada, alertas não desligáveis, sessões visíveis |
| 28 | Computador do operador infectado | Navegador | Sudo para ações críticas, alerta de cada ação sensível, modo trancado |
| 29 | Enumeração de usuários | Login, convites | Respostas e tempos iguais |
| 30 | Timing attack em tokens | Tokens, HMAC | Comparação em tempo constante |
| 31 | Injeção em e-mail/Telegram | Notificações | Templates fixos, escape de Markdown/HTML do canal |
| 32 | Abuso do terminal | Terminal | Sudo, 15 min, gravação, alerta, pode ser desligado |
| 33 | Porta aberta fora do Hangar | Servidor | Varredura de portas em escuta + alerta |
| 34 | Servidor desatualizado | Docker, Caddy, SO | Monitor de atualizações + unattended-upgrades |

---

## Parte 5 — O que ainda sobra de risco (e como reduzimos)

| Risco residual | Por que existe | Redução |
|---|---|---|
| O `hangard` controla o Docker, e isso equivale a root | É inevitável num painel desse tipo | Modo bunker, 2FA, sudo, superfície mínima, systemd sandbox |
| Falha nova (zero-day) em Docker, Caddy, kernel ou Go | Ninguém controla | Atualização rápida avisada pelo monitor; camadas independentes |
| Sua conta de e-mail ou celular comprometidos | Fora do sistema | Passkey, códigos de recuperação offline, sem recuperação por e-mail |
| Acesso do provedor da VPS | Ele controla o hardware | Backups cifrados fora do provedor; chave mestra guardada com você |
| Bug na aplicação (Django) | Fora do Hangar | Hardening do container limita o estrago; monitor de CVEs nas bibliotecas |

## Parte 6 — Como provamos que está seguro

1. **Testes automáticos de segurança** no CI: política de rotas, CSRF em
   toda escrita, IDOR (usuário A tentando o recurso de B), headers presentes,
   anti-SSRF, `ask` fail-closed, hardening aplicado.
2. `govulncheck`, `gosec` e `golangci-lint` em todo PR.
3. **Fuzzing** (nativo do Go) nos parsers: domínio, `.env`, templates, entrada da API.
4. Checklist de revisão de segurança ([04](04-seguranca.md)) obrigatório em PR
   que toca auth, rotas, Docker ou rede.
5. **Pentest** antes de colocar o primeiro projeto real em produção no Hangar (mesmo que
   interno: OWASP ZAP + tentativa manual das 34 brechas acima).
