# 09 — Backups

## A ideia central: o servidor consegue **trancar**, mas não consegue **abrir**

Funciona como a fenda de uma caixa de correio: o servidor coloca os backups
lá dentro, mas a chave que abre fica **só com você**.

- Cada backup é cifrado com a sua **chave pública** (criptografia
  assimétrica, ferramenta [age](https://age-encryption.org)). A chave
  privada, a única que decifra, **nunca** fica no servidor.
- Os backups vão para um storage com **trava de imutabilidade** (Object Lock):
  durante o prazo de retenção, ninguém consegue apagar nem sobrescrever,
  nem o próprio servidor, nem quem invadir o servidor.

Consequência: se alguém tomar o servidor inteiro, ele **não consegue ler os
backups antigos** (não tem a chave) e **não consegue apagá-los** (estão
travados). É exatamente o cenário de ransomware, e é o que mais importa
proteger.

```
 SERVIDOR                                  STORAGE (S3 / R2 / B2 / Wasabi)
┌──────────────────────────┐              ┌─────────────────────────────┐
│ pg_dump / WAL / volumes  │              │  🔒 Object Lock (30 dias)   │
│        │                 │              │  ninguém apaga nem altera   │
│        ▼                 │   só envia   │                             │
│ comprime (zstd)          │─────────────►│  diario/   semanal/  mensal/│
│        ▼                 │  (credencial │  wal/      painel/          │
│ cifra p/ CHAVE PÚBLICA   │  sem permis- │                             │
│ (age) — não sabe decifrar│  são de      └──────────────┬──────────────┘
└──────────────────────────┘  apagar)                    │ credencial
                                                         │ só leitura
                                         ┌───────────────▼──────────────┐
                                         │ SEU COMPUTADOR / HD EXTERNO  │
                                         │ hangar-cofre sync            │
                                         │ 🔑 chave privada fica aqui   │
                                         └──────────────────────────────┘
```

## Regra 3-2-1-1-0

| Regra | Como o Hangar cumpre |
|---|---|
| **3** cópias dos dados | Produção + storage na nuvem + seu computador/HD |
| **2** mídias diferentes | Disco da VPS + object storage |
| **1** fora do servidor | Storage S3 de **outro provedor** (não o da VPS) |
| **1** imutável / offline | Object Lock no bucket + cópia no seu HD |
| **0** erros na restauração | Cada backup é testado antes de ser enviado (ver "Verificação") |

## O que é copiado, e como

| Dado | Método | Frequência padrão | Perda máxima (RPO) |
|---|---|---|---|
| **PostgreSQL**: contínuo | Arquivamento de WAL com WAL-G (cifrado com chave pública) + base backup diário | contínuo (`archive_timeout=60s`) | **≤ 1 minuto** |
| **PostgreSQL**: lógico | `pg_dump -Fc` → zstd → age | diário (+ antes de todo deploy com migração e antes de atualizar versão) | 24 h (é a cópia "portátil") |
| Redis de **filas/sessões** *(em breve)* | `BGSAVE` → RDB → zstd → age | a cada 6 h | 6 h |
| Redis de **cache** | **não faz backup** (é descartável) | — | — |
| Volumes de apps *(em breve)* | `tar` do volume (montado só leitura) → zstd → age | diário | 24 h |
| **Painel Hangar** | `VACUUM INTO` do SQLite + `hangar.toml` + **chave mestra** + certificados | diário + a cada mudança de configuração | — |
| Mídia no R2/S3 (fotos dos produtos) | Replicação do bucket para **outro provedor** (rclone, só cópia, nunca apaga do destino) | diário | 24 h |
| Código | Já está no GitHub; imagens são reconstruídas. Opcional: espelhar o repositório | — | — |

Por que dois backups do Postgres:

- **WAL contínuo**: permite voltar o banco para **qualquer minuto** ("restaure
  como estava às 14:32, antes daquele `DELETE` errado"). Numa loja com
  checkout, perder um dia de pedidos não é aceitável.
- **pg_dump diário**: um arquivo único, fácil de baixar e abrir no seu
  computador, e que funciona em outra versão do Postgres.

Por que a chave mestra entra no backup do painel: ela fica **dentro** de um
arquivo que só a sua chave privada abre. Assim, uma única chave (a sua)
recupera tudo, inclusive os segredos.

## As chaves: o "Kit de recuperação"

Na primeira configuração de backup:

1. O painel **gera as chaves no seu navegador** (JavaScript local, nada é
   enviado). Só a **chave pública** vai para o servidor.
2. Você baixa o **Kit de recuperação** (`hangar-kit.txt`), que contém:
   - chave privada age (para dumps, volumes, painel);
   - chave privada PGP (para o WAL-G);
   - opcionalmente protegido com uma frase-senha sua.
3. Você imprime a **versão em papel** (QR code + texto) e guarda num lugar
   físico seguro.
4. O painel só ativa os backups depois que você **prova que guardou o kit**:
   ele pede para colar um trecho do kit e confere com a chave pública.

**Dois destinatários (recomendado):** os backups são cifrados para **duas**
chaves ao mesmo tempo. Por exemplo, a sua e uma chave reserva guardada com
um sócio ou num cofre. Qualquer uma das duas abre. Perder uma chave não é
perder os backups.

> ⚠ Sem nenhuma das chaves privadas, **ninguém** recupera os backups, nem
> você, nem nós. É o preço de o servidor invadido não conseguir lê-los.

## Destinos

| Destino | Imutabilidade | Observação |
|---|---|---|
| Backblaze B2 | Object Lock ✅ | Barato, recomendado como principal |
| Wasabi | Object Lock ✅ | Sem custo de download |
| AWS S3 | Object Lock ✅ | |
| Cloudflare R2 | Bucket lock ✅ | Sem custo de download; **se o projeto já usa R2 para mídia** → preferir outro provedor para backup |
| Hetzner Storage Box / SFTP | ❌ (usar snapshots do provedor) | Opção econômica secundária |
| **Seu computador / HD externo** | offline = imutável na prática | Via `hangar-cofre sync` |

Regras:

- **Dois destinos** recomendados, de provedores diferentes.
- A credencial que fica no servidor **só pode gravar** (sem permissão de
  apagar). A limpeza dos backups antigos é feita pelas **regras de ciclo de
  vida do próprio bucket**, por pasta (`diario/` 7 dias, `semanal/` 35,
  `mensal/` 400), e não pelo servidor.
- Endpoint do S3 passa pelo filtro anti-SSRF ([17](17-telas-fluxos-e-seguranca.md)).

## Verificação: "0 erros"

O servidor não consegue decifrar os backups. Então a verificação acontece
**antes** de cifrar, e depois do envio:

```
pg_dump ──► arquivo temporário (em tmpfs cifrado na memória)
              │
              ├─► TESTE: restaura num Postgres descartável, confere
              │   tabelas e contagens  ──► falhou? alerta 🔴, não envia
              ▼
         zstd + age ──► envia ──► baixa o cabeçalho e confere o SHA-256 ──► registra
              │
              └─► apaga o temporário
```

Além disso:

- **Alertas** (não podem ser desligados):
  - nenhum backup com sucesso nas últimas 26 h;
  - arquivamento de WAL atrasado mais de 5 min;
  - tamanho mudou de forma estranha. Caiu mais de 50% pode ser dado apagado;
    cresceu demais pode ser dado cifrado por ransomware.
- **Simulado mensal** (lembrete no Telegram): `hangar-cofre test` no seu
  computador baixa o último backup, decifra com a sua chave, sobe num Postgres
  local e mostra o resultado. É a prova real de que dá para voltar.

## `hangar-cofre`: ferramenta no seu computador

Binário pequeno (Mac, Windows, Linux), código aberto no mesmo repositório:

| Comando | O que faz |
|---|---|
| `hangar-cofre sync ~/Backups/hangar` | Puxa os backups novos do bucket (credencial **só leitura**, guardada só no seu PC) para uma pasta ou HD. Pode rodar agendado |
| `hangar-cofre list` | Lista backups disponíveis (local e nuvem) |
| `hangar-cofre decrypt arquivo.age` | Decifra com a sua chave |
| `hangar-cofre restore-local minhaloja_postgres --at "2026-10-15 14:32"` | Sobe um Postgres no Docker local e restaura até aquele minuto |
| `hangar-cofre test` | O simulado mensal |

Funciona **sem o painel**: se a VPS sumir, você ainda tem tudo.

## Baixar backup pelo painel

```
[⬇ Baixar backup agora]  🔒 (2FA de novo)
   │
   ├─► gera pg_dump na hora ──► testa ──► cifra com sua chave pública
   └─► link de uso único, válido por 5 min ──► arquivo .age ──► audit log
```

- O arquivo baixado vem **cifrado**. Se o link ou o arquivo vazar, ninguém
  abre sem a sua chave.
- No seu computador: `hangar-cofre decrypt` (ou `age -d -i hangar-kit.txt`).
- Também dá para baixar qualquer backup antigo da lista (do bucket direto,
  por link assinado de curta duração).

## Restaurar

### Pelo painel

```
Serviço ▸ Backups ▸ [Restaurar] 🔒
  ① Escolher o ponto:  (•) Momento exato [15/10/2026 14:32] (WAL)
                       ( ) Backup diário de [14/10 03:00]
  ② Destino:           (•) Serviço NOVO (minhaloja_postgres_restaurado)
                       ( ) Sobrescrever o atual (digite o nome para confirmar)
  ③ Chave:             [ Selecionar hangar-kit.txt ]
  ④ [ Restaurar ]
```

- A chave privada é necessária (o servidor não tem). Ela é enviada nesta
  sessão 🔒, fica **só na memória**, é usada e **apagada** ao fim. Nunca vai
  para disco, log ou banco. Fica registrado no audit log que uma chave foi usada.
- Padrão: restaurar num **serviço novo**, conferir, e só então trocar a
  referência do app. Sobrescrever direto faz um backup do estado atual antes.
- Arquivos restaurados passam por limites de tamanho e de proporção de
  compressão, e por checagem de caminhos (`..` ou absolutos são rejeitados).

### Recuperação de desastre (VPS perdida)

```
1. VPS nova ─► instala Hangar
2. hangard restore -cofre cofre.toml -identity hangar-kit.txt   (ou -endpoint/-bucket/-prefix no lugar do -cofre)
      └─► recupera painel + chave mestra + configurações + certificados
3. Painel recria projetos, redes, volumes e serviços
4. Para cada banco: "restaurar até o último minuto disponível" (WAL)
5. DNS de host.minhaloja.com.br ─► IP novo (lojas com CNAME voltam sozinhas)
```

Meta de tempo (RTO): **menos de 1 hora** para o projeto `minhaloja` voltar inteiro,
com perda de dados de no máximo ~1 minuto no Postgres.

## Tela de Backups (visão geral)

```
┌ Backups ── 🟢 tudo em dia ──────────────────────────────────────────────┐
│ Destinos: B2 (principal, Object Lock 30 d) 🟢 · Wasabi (secundário) 🟢    │
│ Kit de recuperação: confirmado em 15/10 · 2 chaves (Junior, Reserva)     │
├──────────────────────────────────────────────────────────────────────────┤
│ Serviço              Último backup   WAL       Tamanho   Testado   Ações  │
│ minhaloja_postgres   hoje 03:00 🟢   há 40 s   2,1 GB    ✅        ⬇ ↩   │
│ minhaloja_redis      hoje 12:00 🟢   —         18 MB     ✅        ⬇ ↩   │
│ painel Hangar        hoje 03:05 🟢   —         4 MB      ✅        ⬇      │
│ mídia R2 → B2        hoje 04:00 🟢   —         38 GB     —                │
├──────────────────────────────────────────────────────────────────────────┤
│ Último simulado no seu computador: 01/10 ✅ (próximo lembrete: 01/11)    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Segurança desta parte (resumo)

| Ameaça | Proteção |
|---|---|
| Invasor no servidor quer **ler** backups antigos | Não tem a chave privada (cifra assimétrica) |
| Invasor / ransomware quer **apagar** backups | Object Lock + credencial sem permissão de apagar |
| Vazamento do bucket ou do arquivo baixado | Tudo cifrado com age |
| Provedor de storage sai do ar | Segundo destino em outro provedor + cópia no seu HD |
| Backup corrompido sem ninguém saber | Teste de restauração antes do envio + checksum + simulado mensal |
| Backup parou de rodar | Alerta se não houver sucesso em 26 h ou se o WAL atrasar |
| Perda da chave | Duas chaves (sua + reserva), kit em papel, confirmação obrigatória |
| Arquivo malicioso na restauração | Limites de tamanho/compressão, checagem de caminhos |

## Como ficou na implementação (Etapa 9)

O que mudou em relação ao plano acima, e por quê:

| Plano | Implementado | Por quê |
|---|---|---|
| WAL-G com chave PGP | O próprio Postgres copia cada arquivo de WAL (`archive_command` só com `cp`) para `hangar-wal/` dentro do volume de dados, fora do PGDATA; o hangard cifra com **age** e envia a cada 15 s, e só então apaga do volume | Nada extra dentro da imagem oficial, nenhuma chave dentro do container, e uma chave só no kit (age) em vez de age + PGP |
| Kit com frase-senha opcional no navegador | O navegador gera o kit simples; `hangar-cofre kit protect` cifra com frase-senha (scrypt do age) | Fazer scrypt + ChaCha20 em JS seria muito código de cripto escrito à mão; o kit protegido é aberto pelo painel e pelo cofre |
| Teste de restauração em tmpfs | Container descartável (mesma imagem, sem rede) com volume de rascunho apagado ao fim | Um dump grande não cabe na memória de uma VPS pequena; o texto puro nunca toca o disco do hangard (vai do `pg_dump` direto para o teste e para o age) |
| `backup_policies.target_id`, `retention_json` | Todo backup vai para **todos** os destinos; agenda é `every_hours` + `at_minute`; retenção pelas pastas do bucket | O doc recomenda dois destinos; a limpeza já é do bucket, não do servidor |
| Trava de 30 dias para tudo | Trava = menor entre os dias do destino e o tempo da pasta (`diario/` 7, `semanal/` 35, `mensal/` 400, `wal/` 9, `painel/` 35) | Um backup diário não precisa de trava maior que o tempo em que ele existe |

Ficou para depois: Redis (`BGSAVE`), volumes de apps (`tar`), réplica do
bucket de mídia (`bucket_sync`), backup automático antes de deploy com
migração, lembrete mensal do simulado no Telegram (depende da Etapa 8) e
a linha "último simulado no seu computador" (o cofre não tem como avisar o
painel com credencial só leitura).

### Peças

- **Painel** — tela `/backups` (kit, destinos, bancos, histórico, regras do
  bucket) e aba **Backups** de cada Postgres (agenda, WAL, baixar,
  restaurar). Chaves e destinos: dono + sudo. Restaurar e baixar: admin +
  sudo. Tudo auditado.
- **Destino** — ao salvar, o painel grava um objeto de prova com trava, lê
  de volta e tenta apagar: se conseguir apagar, ou se o bucket não tiver
  Object Lock, o destino é recusado. Endpoint passa pelo filtro anti-SSRF
  (`[backup] allow_private_endpoints = true` só para MinIO de laboratório).
- **Restaurar** — até um minuto (base + WAL + `recovery_target_time`) ou de
  um `pg_dump`; num serviço novo (padrão) ou sobrescrevendo (backup do
  estado atual antes; se falhar, os dados antigos voltam). O kit sobe só na
  requisição e fica em memória durante a restauração.
- **`hangar-cofre`** (`just build-cofre-all`): `init`, `sync`, `list`,
  `decrypt`, `restore-local PROJETO/SERVIÇO -at "2026-10-15 14:32"`
  (também offline com `-from PASTA`), `test`, `kit check|protect`,
  `setup-bucket` (regras de ciclo de vida com a credencial de admin).
- **Desastre** — na VPS nova: `hangard restore -cofre cofre.toml`
  (painel, chave mestra, certificados; o que existia vai para o lado) e
  depois `sudo -u hangar hangard restore databases -cofre cofre.toml`
  (redes, cada Postgres até o último minuto, depois os serviços).

### Como foi testado

`go test -tags integration ./internal/backup/...` sobe um MinIO com bucket
travado (compliance) e um Postgres real: dump testado (contagem de linhas),
credencial do servidor sem conseguir apagar nem criar marcador de
exclusão, WAL ligado com redeploy, `DELETE` de tudo e restauração até o
instante anterior num serviço novo, a partir do dump e sobrescrevendo; e o
cofre com a credencial só leitura (simulado, `sync` e `restore-local`
offline até o mesmo minuto). Falta o ensaio real: bucket do Junior e
destruir/recriar a VPS cronometrando.
