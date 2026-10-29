# 06 — Monitoramento e logs

## Métricas

### Fontes

| Escopo | Fonte | Métricas |
|---|---|---|
| Container | Docker API `stats` (stream) | CPU %, memória (uso, limite, %), rede rx/tx, I/O de bloco, PIDs |
| Container | Docker API `inspect` | estado, restarts, healthcheck, uptime, OOMKilled |
| Volume | `system df` (a cada 10 min — é caro) | bytes usados |
| Host | `/proc` e `/sys` (lidos direto, sem dependência) | CPU, load, RAM, swap, disco por partição, rede, uptime |
| Caddy | métricas Prometheus do Caddy (via Admin API) | req/s, latência, erros por host |

### Coleta e armazenamento

- Um coletor por container, mantendo um stream de `stats` aberto (o Docker
  envia a cada ~1 s; agregamos em janelas de 10 s).
- **Memória**: ring buffer com a última hora em resolução de 10 s (para a tela
  ao vivo).
- **SQLite**: tabela `metrics` com agregados de 1 min (retenção 48 h: os
  gráficos só leem minutos até a faixa de 24 h) e de 1 h (retenção 90 dias).
  O rollup para horas roda a cada minuto; a poda, na faxina de hora em hora
  ([20](20-logs-e-retencao.md)).
- Custo estimado: dezenas de serviços cabem em poucos MB de RAM e < 1% de CPU.

### Telas

- **Visão geral do servidor**: host + tabela de todos os containers ordenável
  por CPU/RAM/rede (o "quem está comendo minha máquina?").
- **Por serviço**: gráficos (uPlot) de 1 h, 24 h, 7 d, 90 d; atualização ao vivo
  por SSE.
- Exportação opcional em `/metrics` (formato Prometheus, protegido por token)
  para quem quiser plugar Grafana depois.
- **Link externo de status** (anonimizado, para monitorar de casa ou num monitor
  de parede): ver [15](15-painel-publico-de-status.md).

## Logs

Política completa de onde cada log fica e por quanto tempo: [20](20-logs-e-retencao.md).

- **Ao vivo**: `ContainerLogs(follow=true, tail=500)` → SSE para o navegador.
  Pausar, filtrar por texto, alternar stdout/stderr, baixar.
- **Histórico**: o que o log driver `local` guarda (até ~150 MB por container).
  Busca simples por texto e intervalo de tempo.
- **Logs de build e deploy**: os últimos 16 KB de cada deploy ficam em
  `deployments.log`; o log fica nos 20 deploys mais novos de cada serviço e o
  histórico, nos 100 mais novos (paginado na aba do serviço).
- **Logs de acesso do Caddy**: JSON, filtráveis por domínio (útil para ver o
  tráfego de cada loja).
- Escape de sequências ANSI/HTML antes de exibir (log é entrada não confiável).
- Pós-MVP: envio opcional para Loki/VictoriaLogs.

## Alertas (Etapa 8)

Código em `internal/alerts`. Tela em **Alertas** no menu lateral
(`/alerts`) e o sino na barra superior (últimos alertas, ponto vermelho
enquanto houver alerta não visto).

### Regras do servidor

Avaliadas a cada 10 s pelo monitor. Cada uma pode ser desligada e, quando
tem limite, ajustada em **Alertas › Regras do servidor** (Admin+).

| Regra | Condição | Nível |
|---|---|---|
| Container caiu | serviço que deveria rodar está parado (ou sumiu) há > 30 s; parado pelo usuário, nunca publicado ou no meio de deploy não conta | crítico |
| Loop de reinício | mais de 3 reinícios em 5 min (limite ajustável) | crítico |
| OOM | `OOMKilled=true` no container atual | aviso |
| Memória alta num serviço | > 90% do limite por 5 min | aviso |
| CPU do servidor | > 90% por 5 min | aviso |
| Memória do servidor | > 90% por 5 min | aviso |
| Disco do servidor | > 85% do disco de dados por 1 min | aviso |
| Disco limitado quase cheio | disco com limite de tamanho ([05](05-isolamento-e-recursos.md)) > 80% por 1 min | aviso |
| Disco limitado cheio | disco com limite de tamanho > 95% por 1 min | crítico |

Quando a condição some, sai o aviso "Normalizado". Se o Docker não
responde numa rodada, nada dispara nem normaliza (um soluço do Docker não
pode anunciar que está tudo bem). Ainda não implementados: certificado
(falha de emissão/renovação, expira em < 14 dias) e limite de emissão de
domínios dinâmicos atingido.

### Alertas de segurança (não podem ser desligados nem silenciados)

Saem do log de auditoria (passo ⑰ do [17](17-telas-fluxos-e-seguranca.md)):
login de IP novo (a tabela `login_ips` guarda os endereços já usados por
conta), logins falhos em série (limite do rate limit atingido), conta
bloqueada, 2FA desligada (pela tela ou pela CLI), toda ação que exige sudo
(revelar segredo, apagar serviço/projeto, domínios dinâmicos, baixar
backup, pedir atualização, pausar/remover canal), usuário criado, porta
aberta para qualquer IP, canal novo, atualização aplicada ou desfeita,
painel trancado e destrancado. Um teste falha se uma rota com sudo não
estiver na lista.

### Canais

Telegram (token do bot + chat ID), e-mail (SMTP com STARTTLS ou TLS
direto, nunca em claro) e webhook (HTTPS, endereço público, corpo JSON
assinado: `X-Hangar-Signature: sha256=HMAC(segredo, timestamp + "." +
corpo)` e `X-Hangar-Timestamp`). Toda a configuração do canal fica cifrada
com a chave mestra; revelar o token/senha/segredo pede sudo e gera alerta.
Cada canal escolhe o que recebe (tudo, avisos e críticos, só críticos);
alerta de segurança vai para todos os canais ativos. Botão **Testar** em
cada canal.

### Entrega, deduplicação e silêncio

- Alerta repetido da mesma condição dentro de 30 min (10 min para
  segurança) não é reenviado: vira "+N repetições" no histórico.
- Mais de 3 disparos da mesma condição por hora (pisca-pisca) são
  engolidos.
- Até 20 mensagens por canal a cada 10 min; o excesso fica só no painel.
- Até 3 tentativas por entrega (espera de 2 s e 10 s); token errado ou
  destino recusado não insiste. Tudo vai para o registro de **Entregas**.
- "Silenciar" (1 h, 4 h, 24 h) cala só os alertas do servidor; eles
  continuam gravados no histórico.
- Mensagens são texto fixo com os nomes limpos de quebras de linha; o
  e-mail codifica o assunto. Nada vindo de fora vira marcação.

`[alerts] telegram_api` no `hangar.toml` troca o endereço da API do
Telegram (Bot API próprio, ou um endereço morto nos testes E2E).
