# 07 — Deploy e builds

## Fontes de um serviço "App"

| Fonte | Como |
|---|---|
| Imagem | `registry/imagem:tag` (resolvida para digest no deploy). Registry privado com credencial cifrada. |
| Git + Dockerfile | Clona o repositório, `docker build` com BuildKit. |
| Git sem Dockerfile | Railpack detecta a stack e gera a imagem (opcional). |

## Pipeline de um deploy

```
pending → building → starting → healthy → switching → live
                         │           │
                         └── failed ◄┘   (antigo continua no ar)
```

1. **pending**: deployment criado (manual, webhook ou rollback). Um deploy por
   serviço por vez; os demais entram na fila.
2. **building** (se Git): clone raso em `/var/lib/hangar/builds/<id>` com token
   de leitura; build com limite de CPU/RAM e timeout (padrão 20 min); imagem
   tagueada `hangar/<projeto>-<serviço>:<deployment-id>`. Workspace apagado ao fim.
3. **starting**: cria o container novo com nome `<serviço>-<deploy-id curto>`,
   mesmas redes, envs, volumes e limites.
4. **healthy**: espera healthcheck (HTTP no caminho configurado, ou
   healthcheck do Docker), timeout configurável (padrão 120 s).
5. **switching**: atualiza o upstream no Caddy para o container novo
   (`POST /load` atômico). Conexões em andamento terminam no antigo.
6. **live**: para o antigo com `SIGTERM` + período de graça (padrão 30 s),
   depois remove. A imagem antiga fica guardada para rollback (últimas 5).

Falhou em qualquer passo antes de `switching` → container novo removido, o
antigo nunca saiu do ar.

### Serviços com volume (bancos)

Não fazem blue/green (dois Postgres no mesmo volume corromperiam dados).
Estratégia "recreate": para → sobe novo → healthcheck. O painel avisa que há
downtime curto e sugere backup antes de trocar de versão major.

### Comandos de release (ex.: `migrate` do Django)

Campo opcional "comando pré-deploy": roda num container temporário com a
imagem nova, mesmas envs e redes, **antes** do `switching`. Se falhar, o deploy
é abortado.

## Rollback

Botão "voltar para esta versão" em qualquer um dos últimos 5 deployments: cria
um deployment novo apontando para a imagem antiga (sem rebuild).

## Webhooks de Git

- Endpoint `POST /hooks/git/<service-token>` (token aleatório por serviço).
- Verificação da assinatura (`X-Hub-Signature-256` no GitHub, token no GitLab).
- Só dispara se o branch do push for o configurado.
- Esse é o **único** endpoint do painel acessível sem login quando o painel
  está em modo público; em modo bunker, um caminho específico pode ser
  exposto no Caddy só para ele.

## Variáveis de ambiente

- Por serviço, com marcação "secreta" (cifrada, mascarada na tela).
- Referências entre serviços: `${{postgres-lojas.DATABASE_URL}}` resolvido no
  deploy, para não copiar senha à mão.
- Mudar env exige redeploy (o painel mostra "alterações pendentes").

## Situação (Etapa 6)

- **Sem downtime** para serviços sem volume e sem porta publicada: o
  container novo (`<projeto>_<serviço>-next`) sobe com o mesmo nome de rede
  (alias) do antigo, passa no healthcheck, e só então o antigo recebe
  `SIGTERM` com 30 s de graça; o novo é renomeado para `<projeto>_<serviço>`.
  O Caddy repete por até 10 s as conexões recusadas, então quem chega na
  hora da troca é atendido pelo novo.
- **Para e sobe** para bancos e serviços com porta publicada (dois
  containers no mesmo volume corrompem dados; dois não publicam a mesma
  porta). A tela diz qual estratégia o serviço usa e por quê.
- **Healthcheck:** o da imagem ou do template; senão `GET` no caminho
  configurado (resposta abaixo de 400); senão conexão TCP na porta; senão 5 s
  rodando sem reiniciar. Timeout 2 min, ou mais quando o healthcheck
  guardado no serviço (template, compose) pode demorar mais para decidir:
  `start_period + interval × retries + timeout` (com os padrões do Docker
  para o que faltar), no máximo os 15 min do deploy inteiro. Um servidor
  que carrega o mundo ou o banco por minutos não é dado como falho no
  meio da subida. Falhou: o novo é apagado, o antigo
  nunca saiu do ar, e as últimas linhas de log do novo vão para o log do
  deploy.
- **Pré-deploy:** container temporário com a imagem nova, mesmas variáveis,
  redes e volumes, sem porta; roda uma vez por deploy; código de saída
  diferente de zero aborta o deploy antes de qualquer troca.
- **Linha do tempo:** fase em andamento, log do deploy (últimos 16 KB) e
  "Voltar para esta versão" nos últimos 5 deploys que ficaram no ar.
- **Rollback** usa a imagem exata daquele deploy (digest do registry, ou o
  ID da imagem construída no servidor), sem depender da tag ter mudado. As
  variáveis são as atuais.
- Não há fila: um deploy por serviço por vez; o segundo pedido é recusado.

Testado na VM com o Django de laboratório + Postgres pelo Caddy, 6
conexões em paralelo sem parar: 1139 requisições durante um deploy (troca
de imagem e de variável) sem nenhum 5xx; 15054 durante um deploy com
healthcheck quebrado, todas atendidas pela versão no ar; rollback em 5 s;
`migrate` rodou exatamente uma vez por deploy.

**Ficou para depois:** fila de deploys, guardar as variáveis de cada deploy
para o rollback voltar com elas, limpar imagens antigas (manter as 5 do
rollback), build por Git (feito na Etapa 10, abaixo).

## Situação (Etapa 10 — build por Git)

- **Fonte Git:** "Novo serviço" → aba "Repositório Git" (URL HTTPS, branch,
  pasta, Dockerfile, token de leitura). O acesso é testado (ls-remote) antes
  de salvar. Em Configurações, o cartão "Repositório" edita a fonte e o
  token; trocar de repositório apaga o token salvo (ele nunca vai para um
  host para o qual não foi criado).
- **Clone:** dentro do processo (go-git), sem binário `git` e sem shell; o
  token fica só na memória e cifrado no banco (`service_git|<id>|token`).
  Clone raso de um commit, sem tags e sem submódulos, em
  `/var/lib/hangar/builds/<deploy>`, apagado ao fim (e na partida, se ficou
  algo de uma queda). Só HTTPS, por um cliente que confere o IP na hora da
  conexão (bloqueia loopback, privados, link-local/metadados, CGNAT, NAT64):
  vale também contra DNS rebinding. `file://`, `ssh://`, `git://` e `http://`
  não existem no painel.
- **Build:** BuildKit pela API do Docker (`/build` com `version=2`), contexto
  enviado como tar respeitando o `.dockerignore` (sem `.git`, symlinks vão
  como symlinks, limite de 2 GiB), timeout de 20 min. A imagem é
  `hangar/<projeto>/<serviço>:<deploy>` com os rótulos do Hangar, fixada pelo
  **ID** para o rollback, e **nunca** é baixada de registry pelo nome. Depois
  de cada deploy as imagens antigas do serviço são apagadas, menos as que o
  rollback ainda usa; apagar o serviço apaga todas.
- **Log:** fases `clone` e `build` entram no mesmo log do deploy, com a saída
  de cada passo do BuildKit (`#5 [2/4] RUN …`). Antes de gravar, toda linha
  passa pela máscara: variáveis secretas (como estão e depois de resolver
  referências), valores vindos de referências (e a senha dentro de URLs),
  o token (também em Basic auth/base64) e o segredo do webhook viram `••••`.
- **Webhook do GitHub:** `POST /hooks/git/<token>` (token aleatório por
  serviço, guardado como hash para achar o serviço). HMAC-SHA256
  (`X-Hub-Signature-256`) em tempo constante; ID de entrega
  (`X-GitHub-Delivery`) aceito uma vez só; `repository.pushed_at` (dentro do
  corpo assinado) tem que estar nos últimos 10 min; repositório e branch têm
  que bater. Aceita JSON e o formulário padrão do GitHub. Push durante um
  deploy fica na fila (um por serviço, o próximo build pega a ponta do
  branch). Ligar, mostrar URL e segredo, gerar novo e desligar exigem sudo.
- **Webhook com painel fechado:** com `edge.hooks_hostname`, o Caddy publica
  só `/hooks/git/*` desse domínio (o resto é 404) e entrega no listener do
  edge, que só aceita conexões vindas do Caddy. O painel continua só em
  127.0.0.1.

Testado no Docker local (OrbStack): build de um repositório em disco, deploy
por webhook assinado, segredo impresso no build aparece como `••••`, rollback
sem rebuild (`just test-integration`); e clone + build de um repositório
público do GitHub pelo painel.

**Ficou para depois:** limite de CPU/RAM do build (o BuildKit do dockerd
ignora os limites por build; o timeout vale), rede isolada para o `RUN` do
build, variáveis como build args/secrets do BuildKit, GitLab/Gitea no
webhook (o clone já funciona), Railpack para repositório sem Dockerfile.

