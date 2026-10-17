# 20 — Logs e retenção

Regra principal: **log de alto volume nunca vai para o SQLite.** O banco do
painel guarda só o que é pequeno e precisa ser consultado: configuração,
auditoria, métricas agregadas e decisões de TLS. Todo o resto vai para
arquivos com rotação, cuidados pelo próprio Docker, pelo Caddy ou pelo
journald.

Meta: o `hangar.db` fica **abaixo de ~100 MB** num servidor com dezenas de
serviços, e o painel avisa se passar de 512 MB.

## Onde cada log mora

| Log | Volume | Onde fica | Limite | Quem limpa |
|---|---|---|---|---|
| **stdout/stderr dos containers** (Django, Celery…) | Alto | Driver `local` do Docker (comprimido) | 50 MB × 3 arquivos por container | O Docker (rotação) |
| **Acesso do Caddy** (cada requisição) | Muito alto | Arquivo JSON em volume do Caddy | 100 MB × 10, 14 dias | O Caddy (`roll_size`, `roll_keep`, `roll_keep_for`) |
| **Log do próprio `hangard`** | Baixo | journald (stderr JSON) | `SystemMaxUse=500M` no journald (o instalador configura) | O journald |
| **Log de build/deploy** | Médio | Arquivo por deploy em `data_dir/deployments/` (gzip) | Últimos 20 por serviço, 20 MB por deploy | Job do Hangar |
| **Gravação do terminal web** | Médio | Arquivo cifrado em `data_dir/terminal/` | 90 dias | Job do Hangar |
| **Auditoria** | Baixo | SQLite (`audit_log`) | Ver abaixo | Arquivamento |
| **Decisões do `ask` (TLS)** | Pode ser alto sob ataque | SQLite (`tls_ask_log`), **agregado** | 30 dias | Job do Hangar |
| **Métricas** | Médio | Memória (1 h) + SQLite agregado | 1 min por 7 dias, 1 h por 90 dias | Job de downsampling |
| **Alertas** | Baixo (repetição vira contador) | SQLite (`alerts`) | 90 dias | Job do Hangar (a cada hora) |
| **Entregas de alerta** | Baixo (máx. 20 por canal a cada 10 min) | SQLite (`alert_deliveries`) | 30 dias | Job do Hangar (a cada hora) |

## Proteções contra inchaço (o que impede um ataque de encher o disco)

1. **Agregação no lugar de linha por evento.** Eventos repetidos viram um
   contador:
   - `tls_ask_log`: uma linha por **(domínio, decisão, hora)** com
     `contagem`. Mil tentativas do mesmo domínio falso viram uma linha.
     Teto de 50 mil linhas; acima disso, só as negações novas entram e
     dispara alerta.
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

## Auditoria: retenção sem quebrar a cadeia

A auditoria é pequena (ações humanas). Estimativa: 200 ações/dia × ~500 bytes
≈ **36 MB por ano**. Mesmo assim ela não pode crescer para sempre:

- Ficam **400 dias** no SQLite (consulta rápida na tela).
- Todo mês, o que passou disso é **arquivado** em
  `data_dir/audit-archive/AAAA-MM.jsonl.gz` (e entra no backup cifrado).
- O arquivamento grava a **âncora** (id e hash do último registro arquivado)
  em `settings`. O `audit verify` confere os arquivos arquivados e continua a
  cadeia a partir da âncora, então a integridade continua verificável de
  ponta a ponta.
- A remoção das linhas arquivadas é o único caminho que passa pelos triggers,
  feito numa transação que só acontece depois do arquivo gravado e
  sincronizado em disco.

## Manutenção do SQLite (já implementado)

- `auto_vacuum=INCREMENTAL`: espaço de linhas apagadas pode voltar ao disco.
- `journal_size_limit=64 MB`: o arquivo `-wal` não fica gigante depois de um
  pico de escrita.
- A cada 6 h: `wal_checkpoint(TRUNCATE)` + `incremental_vacuum` +
  `optimize`, registrando o tamanho. Acima de 512 MB, aviso no log (e alerta
  quando os alertas existirem).

## Leitura dos logs no painel

- Logs de container são lidos **direto do Docker** (API `logs`, com `tail` e
  `since`) e enviados ao navegador por SSE. Não há cópia intermediária.
- Busca por texto acontece sobre o trecho pedido, com limite de linhas por
  resposta, para uma busca não travar o servidor.
- Pós-MVP: envio opcional para Loki ou VictoriaLogs, para quem quiser busca
  em histórico longo, sem mudar nada do que está acima.
