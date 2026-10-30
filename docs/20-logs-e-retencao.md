# 20 — Logs e retenção

Regra principal: **log de alto volume nunca vai para o SQLite.** O banco do
painel guarda só o que é pequeno e precisa ser consultado: configuração,
auditoria, métricas agregadas, histórico de deploys/backups/alertas e
decisões de TLS. Todo o resto vai para arquivos com rotação, cuidados pelo
próprio Docker, pelo Caddy ou pelo journald.

Meta: o `hangar.db` fica **abaixo de ~100 MB** num servidor com dezenas de
serviços, e o painel avisa (no log) se passar de 512 MB. Hoje (out/2026) o
banco de produção tem ~3 MB.

Duas regras para tudo que acumula:

1. **O que precisa ser guardado tem paginação** no painel (cursor por
   tempo + id, 10 a 50 linhas por página), nunca uma lista inteira.
2. **Ruído é podado com o tempo** (domínios recusados, tentativas, entregas),
   ficando só o que é válido.

## Onde cada log mora

| Log | Volume | Onde fica | Limite | Quem limpa |
|---|---|---|---|---|
| **stdout/stderr dos containers** (Django, Celery…) | Alto | Driver `local` do Docker (comprimido) | 50 MB × 3 arquivos por container | O Docker (rotação) |
| **Log do Caddy** | Médio | stderr do container do Caddy (driver `local`) | 50 MB × 3 | O Docker |
| **Log do próprio `hangard`** | Baixo | journald (stderr JSON) | `SystemMaxUse=500M` no journald (o instalador configura) | O journald |
| **Log de build/deploy** | Médio | SQLite (`deployments.log`), 16 KB por deploy | Log nos 20 deploys mais novos de cada serviço | Faxina do Hangar |
| **Auditoria** | Baixo | SQLite (`audit_log` + `audit_archive`) | Ver abaixo | Arquivamento |

## Política de retenção (`internal/retention`)

Um único processo de faxina (o *janitor*) roda **a cada hora** (com ±10 %
de variação, e a primeira vez 5–10 min depois do boot). Os valores ficam em
`retention.Default`, no código; não há botão no painel.

| O quê | Tabela/arquivo | Antes | Agora | Por quê (referência) | Tela |
|---|---|---|---|---|---|
| Métricas de 1 min | `metrics` (1m) | 7 dias | **48 h** | Os gráficos só leem minutos até a faixa de 24 h; 7 d e 90 d leem horas. Rollup no estilo Prometheus/Grafana (raw curto → agregado longo) | Gráfico (faixas fixas) |
| Métricas de 1 h | `metrics` (1h) | 90 dias | 90 dias | Faixa de 90 d do gráfico | Gráfico |
| Decisões TLS negadas | `tls_ask_log` | 30 dias | **7 dias** | Ruído: uma semana basta para ver um ataque e bloquear | `/domains`, paginada |
| Decisões TLS aprovadas | `tls_ask_log` | 180 dias | 180 dias | Domínio aprovado renova sem contar no teto por hora; 2× a vida de um certificado (90 d) | `/domains`, paginada |
| Domínios aprovados (teto por hora) | `tls_approvals` | — | 180 dias desde a última renovação | Uma linha por domínio aprovado; é o que o teto de certificados novos conta, separado do log | Contadores de `/domains` |
| Alertas | `alerts` | 90 dias (por criação) | **90 dias pela última ocorrência**; o alerta de servidor ainda disparando fica até 1 ano | Histórico de incidentes como PagerDuty/Grafana OnCall | `/alerts`, paginada |
| Entregas de alerta | `alert_deliveries` | 30 dias | 30 dias | Diagnóstico de canal | `/alerts?f=deliveries`, paginada |
| Deploys | `deployments` | **sem limite** | **100 por serviço**, log só nos 20 mais novos; `running` e `live` nunca saem | Heroku/Render/Vercel guardam um histórico dessa ordem; o rollback usa os 5 últimos | Aba do serviço, paginada |
| Execuções de backup | `backup_runs` | 400 dias | **enquanto o objeto pode existir no bucket** (dias do ciclo de vida da pasta: diário 7, semanal 35, painel 35, WAL 9, mensal 400) **+ 30 dias**; falhas 90 dias; a última de cada rótulo fica sempre | O registro acompanha o ciclo de vida do bucket ([09](09-backups.md)) | `/backups` e aba do serviço, paginadas |
| Restaurações | `backup_restores`, `project_restores` | sem limite | **400 dias** (a última de cada projeto fica) | Ações manuais e raras | Aba do serviço (10 mais novas) |
| Vulnerabilidades resolvidas | `dependency_findings` | sem limite | **180 dias** depois de resolvidas | A que voltar vira registro (e aviso) novo | `/updates` |
| Ignorar vencido | `finding_ignores` | só ao listar | ao vencer | — | `/updates` |
| Pacotes de imagem | `image_probes` | 60 dias | 60 dias (também no janitor) | — | — |
| IPs conhecidos de login | `login_ips` | sem limite | **180 dias** sem uso | IP sumido há meio ano volta a ser "novo" e alerta | — |
| Convites | `invites` | sem limite | **30 dias** depois de usado/vencido | A tela só lista os abertos | `/team` |
| Marcas no log | `log_marks` | sem limite | **30 dias** | O Docker rotaciona o log bem antes | Log do serviço |
| Entregas de webhook | `webhook_deliveries` | 7 dias | 7 dias (podado a cada push) | Janela anti-replay | — |
| Sessões | `sessions` | expiradas a cada 15 min | igual | — | `/account` |
| Auditoria | `audit_log` | sem limite | **400 dias** na tabela, depois arquivo comprimido até **7 anos**, depois só os hashes | PCI DSS v4 10.5.1 (12 meses, 3 à mão); ISO 27001/NIST SP 800-92 (≥ 1 ano); 7 anos estilo SOX | Feed da visão geral, histórico de atualização (paginado) |
| Sobras de scan | `data_dir/tmp` | nunca | **24 h** | Nada ali deve durar mais que um scan | — |
| Cópias pré-migração / pré-atualização | `data_dir/backups` | 3 + 3 | igual | — | — |
| Binários antigos | `data_dir/releases` | 3 | igual | — | — |
| Workspaces de build | `data_dir/builds` | apagados ao fim e no boot | igual | — | — |
| Cache de build e imagens órfãs | Docker | a cada 24 h | igual | — | — |

### Como a faxina apaga sem travar o painel

- Cada regra apaga **no máximo 500 linhas por comando**, com uma pausa de
  20 ms entre lotes e **no máximo 200 lotes por execução**. O SQLite tem um
  único escritor: lotes curtos seguram o lock por milissegundos, e um
  acúmulo grande (por exemplo, a primeira poda depois desta mudança) é
  vencido em várias execuções.
- Métricas são podadas **uma chave por vez**, seguindo a chave primária
  `(key, resolution, ts)`, sem varrer a tabela.
- Uma regra que falha vai para o log e as outras seguem.

### Manutenção do SQLite

- `auto_vacuum=INCREMENTAL`, definido na criação do arquivo. Um arquivo
  antigo sem ele é convertido **uma vez** no boot (`VACUUM`, que funciona em
  modo WAL) se tiver até 256 MB; acima disso fica um aviso no log para fazer
  fora do horário.
- Depois de cada passada: `wal_checkpoint(TRUNCATE)`,
  `incremental_vacuum(4096)` (devolve até 16 MB por hora ao disco) e
  `PRAGMA optimize` (o que a documentação do SQLite recomenda rodar
  periodicamente em conexões longas).
- **Sem `VACUUM` completo periódico**: ele reescreve o arquivo inteiro, pede o
  dobro do espaço e bloqueia todas as escritas durante a cópia. Com a
  retenção mantendo o banco pequeno e o vacuum incremental devolvendo as
  páginas livres, a fragmentação não compensa esse custo.
- `journal_size_limit=64 MB`: o arquivo `-wal` não fica gigante depois de um
  pico de escrita.

## Proteções contra inchaço (o que impede um ataque de encher o disco)

1. **Agregação no lugar de linha por evento.** Eventos repetidos viram um
   contador:
   - `tls_ask_log`: uma linha por **(domínio, decisão, hora)** com
     `contagem`. Mil tentativas do mesmo domínio falso viram uma linha, e
     todo nome com formato inválido cai numa única linha por hora (sem o
     nome que veio). Teto de 50 mil linhas; acima disso, só as linhas que
     já existem continuam contando. O teto de certificados novos por hora
     não lê esse log, e sim `tls_approvals` (só aprovações entram lá), então
     encher o log não desliga o teto.
   - Cache de decisões do `ask` na memória: no máximo 10 mil nomes, sai o
     usado há mais tempo (LRU), cada um com validade de 1 h ou 5 min.
   - Falhas de login: as 5 primeiras por IP numa janela de 15 min são
     auditadas uma a uma; depois disso, uma linha agregada por IP e janela
     (`login.fail.agregado`, com contagem).
2. **Nada de 401 na auditoria.** Requisição sem sessão é recusada sem gravar
   (senão qualquer robô encheria o log). Só recusas de **quem já está
   logado** (papel insuficiente, sudo) são auditadas.
3. **Limites na fonte.** O Docker e o Caddy rotacionam sozinhos, mesmo que o
   Hangar pare.
4. **Resumo pequeno.** `summary_json` da auditoria tem no máximo 4 KB;
   user-agent cortado em 256 caracteres.

## Certificados do Caddy (TLS sob demanda)

- Domínio **recusado** nunca ganha certificado: o `ask` responde não antes
  de qualquer emissão, e tentativas recusadas não ficam guardadas no Caddy.
- Domínio **removido** do painel não é renovado (o `ask` é consultado de
  novo e recusa).
- O Caddy varre o armazenamento **a cada 24 h** (`storage_clean_interval`,
  fixado na config gerada) e apaga certificados vencidos há mais de duas
  semanas. Assim só ficam certificados de domínios válidos ou que deixaram
  de ser há pouco.

## Auditoria: retenção sem quebrar a cadeia

A auditoria é pequena (ações humanas). Estimativa: 200 ações/dia × ~500 bytes
≈ **36 MB por ano** na tabela; comprimida, ~10× menos.

- Ficam **400 dias** em `audit_log` (13 meses: "o mesmo mês do ano passado"
  ainda aparece).
- O que passou disso vai, **um mês de calendário por transação**, para um
  bloco gzip em `audit_archive`, gravado na **mesma transação** que apaga as
  linhas: uma queda deixa as linhas ou o bloco, nunca nenhum dos dois. Por
  estar no SQLite, o arquivo entra no backup cifrado do painel sem nada a
  mais.
- Cada bloco guarda o hash de onde a cadeia vinha e o hash do último
  registro. O `hangard audit verify` confere os blocos e depois a tabela, de
  ponta a ponta desde a gênese.
- O arquivamento **recusa** uma cadeia que não confere, e sempre deixa o
  registro mais novo na tabela (os ids novos nunca repetem os arquivados).
- O trigger de `audit_log` só deixa apagar o que um bloco já guarda; blocos
  não podem ser apagados nem alterados.
- Depois de **7 anos**, só os dados do bloco saem (`data = NULL`); ids,
  hashes e o SHA-256 dos dados ficam (centenas de bytes por mês), e a cadeia
  continua verificável.

## Leitura dos logs no painel

- Logs de container são lidos **direto do Docker** (API `logs`, com `tail` e
  `since`) e enviados ao navegador por SSE. Não há cópia intermediária.
- Busca por texto acontece sobre o trecho pedido, com limite de linhas por
  resposta, para uma busca não travar o servidor.
- Pós-MVP: envio opcional para Loki ou VictoriaLogs, para quem quiser busca
  em histórico longo, sem mudar nada do que está acima.
