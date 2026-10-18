# 24 — Operação (manual do dia a dia)

Tudo o que se faz **no servidor** para manter o Hangar de pé: instalar,
atualizar e voltar, trancar, ensaiar a restauração, trocar chaves, o que
vigiar, o que fazer em cada incidente e a migração do Easypanel.

Convenções deste documento:

- `$` é o seu computador; `vps$` é o servidor, com um usuário que tem sudo.
- Os comandos do Hangar rodam **como o usuário `hangar`** (`sudo -u hangar
  hangard ...`). Rodar como root é recusado de propósito: o SQLite criaria
  arquivos de root que o serviço não consegue abrir.
- `-config /etc/hangar/hangar.toml` é o padrão e foi omitido nos exemplos.

## 1. Mapa do servidor

| O quê | Onde |
|---|---|
| Binário | `/usr/local/bin/hangard` |
| Configuração | `/etc/hangar/hangar.toml` (root:hangar 0640) |
| Chave mestra | `/etc/hangar/master.key` (hangar 0400) — **cópia fora do servidor** |
| Token do GitHub (repositório privado) | `/etc/hangar/github-token` (hangar 0400) |
| Dados (banco, logs de deploy, staging de backup) | `/var/lib/hangar/` |
| Banco do painel | `/var/lib/hangar/hangar.db` (+ `-wal`, `-shm`) |
| Binários anteriores (volta da atualização) | `/var/lib/hangar/releases/` (os 3 últimos) |
| Cópia do banco antes de cada atualização | `/var/lib/hangar/backups/pre-update-*` |
| "Estou no ar" | `/var/lib/hangar/run/ready` (contém a versão) |
| Regras de firewall das portas | `/var/lib/hangar/firewall/desired.json` → `applied.json` |
| Caddy (edge) | contêiner `hangar_caddy` na rede `hangar_edge`, dados em `/var/lib/hangar/edge/` |

| Serviço systemd | Papel |
|---|---|
| `hangard` | o painel (usuário `hangar`, sem privilégio, sandbox) |
| `hangar-updater.path` / `.service` | aplica atualizações assinadas (root, só isso) |
| `hangar-firewall.path` / `.timer` / `.service` | aplica as regras de porta (`DOCKER-USER`) e o acesso do Caddy ao painel (`INPUT`) quando mudam e a cada 3 minutos (root, só isso) |

Logs: `journalctl -u hangard -f` (JSON, uma linha por evento). O journald
do Hangar tem limite próprio (`journald-hangar.conf`).

## 2. Instalar

Numa VPS **limpa** (Debian 13 ou Ubuntu 26.04):

```
vps$ curl -fsSL https://github.com/JuniorCarlini/hangar/releases/latest/download/install.sh | sudo bash
# o instalador mostra o endereço: https://hangar.<ip>.sslip.io
# abrir e criar a conta de dono em até 30 min (sudo systemctl restart hangard reabre)
```

O instalador confere a assinatura Ed25519 e o SHA-256 antes de instalar
qualquer coisa, cria o usuário `hangar`, instala o Docker (log com rotação,
`live-restore`), gera a chave mestra, escreve o `hangar.toml` (HTTPS e painel público
ligados quando as portas 80/443 estão livres) e mostra o endereço do painel. Rodar de novo é seguro: nunca apaga dados nem a chave.

**O que o instalador ainda NÃO faz** (fazer à mão):

1. SSH só por chave: `PasswordAuthentication no`, `PermitRootLogin no` em
   `/etc/ssh/sshd_config.d/10-hangar.conf`, `systemctl reload ssh`.
2. Firewall de entrada só 22 (ou a sua porta SSH), 80, 443/tcp e 443/udp.
3. `apt install unattended-upgrades` e `dpkg-reconfigure -plow unattended-upgrades`.
4. `chrony` ligado (TOTP e ACME dependem do relógio).
5. Se o SSH não for na 22: `[alerts] allowed_ports = [2222]` no
   `hangar.toml`, senão o painel alerta "porta aberta fora do painel".

Depois de instalar:

- [ ] Copiar `/etc/hangar/master.key` para fora do servidor (gerenciador de
      senhas ou pendrive). Sem ela, um backup do painel não se abre.
- [ ] Gerar o **Kit de recuperação** em Backups e confirmar as duas chaves.
- [ ] Cadastrar um destino de backup com Object Lock e um canal de alerta
      (Telegram) e clicar "testar".
- [ ] Ligar a 2FA da conta, se criou com `-no-2fa`.

## 3. Atualizar e voltar

**Normal:** aviso "Atualização disponível" → **Atualizar** (pede 2FA) →
o painel volta sozinho na versão nova. As lojas não caem: só o `hangard`
reinicia. Pela linha de comando: `sudo -u hangar hangard self-update stage`.

O `hangar-updater` confere tudo de novo como root, copia o banco
(`backups/pre-update-<versão>-<data>`), guarda o binário atual em
`releases/`, troca e espera o painel escrever `run/ready` com a versão
nova. **Se não subir em 90 s (ou cair 3 vezes seguidas), volta sozinho**
para o binário e o banco anteriores e manda alerta.

**Voltar à mão** (a versão nova sobe, mas tem um defeito):

```
vps$ ls /var/lib/hangar/releases/                 # hangard-v1.2.4, ...
vps$ sudo systemctl stop hangard
vps$ sudo install -m 0755 -o root -g root /var/lib/hangar/releases/hangard-v1.2.4 /usr/local/bin/hangard
vps$ sudo systemctl start hangard
vps$ cat /var/lib/hangar/run/ready                # v1.2.4
```

As migrações seguem "expandir → migrar → contrair", então a versão anterior
roda sobre o banco novo. Só se ela recusar o banco (raro) restaure também a
cópia de antes da atualização:

```
vps$ sudo systemctl stop hangard
vps$ cd /var/lib/hangar && sudo -u hangar mkdir -p estragado && sudo -u hangar mv hangar.db* estragado/
vps$ sudo -u hangar cp -p backups/pre-update-v1.2.4-*/hangar.db* .
vps$ sudo systemctl start hangard
```

Tudo que aconteceu no painel entre a atualização e a volta (deploys,
alterações) fica no banco "estragado"; os containers continuam rodando.

Deploy interrompido: se o painel morrer no meio de um deploy (kill,
queda, reboot, atualização), ao subir ele marca o deploy como falho
("interrupted"), remove o contêiner temporário e mantém a versão que estava
no ar. É só clicar **Deploy** de novo.

## 4. Trancar e destrancar (botão de pânico)

Quando: suspeita de sessão roubada, computador do operador infectado,
alerta de login estranho que você não reconhece.

- Pelo painel: menu da conta → **Trancar painel** (Cmd/Ctrl+Shift+L).
- Pelo servidor: `sudo -u hangar hangard lockdown`.

Efeito: todas as sessões caem (inclusive a sua), links públicos de status e
webhooks do Git param, e o painel só responde pelo próprio servidor (túnel
SSH). **As lojas continuam no ar.**

Investigar com o painel trancado:

```
$    ssh -L 7700:127.0.0.1:7700 usuario@vps    # pelo túnel ainda entra
vps$ sudo -u hangar hangard audit verify       # a auditoria foi adulterada?
```

Na tela de Auditoria: quem entrou, de qual IP, o que revelou ou mudou.
Antes de destrancar: trocar a senha (seção 6), refazer a 2FA se o celular
ou o app podem ter vazado (`hangard user totp -email ...`) e, se um
segredo foi revelado, trocar esse segredo na origem.

```
vps$ sudo -u hangar hangard lockdown status
vps$ sudo -u hangar hangard lockdown off
```

## 5. Ensaio de restauração (simulado mensal)

Um backup que nunca foi restaurado não é backup. Uma vez por mês:

**No seu computador (5 min):**

```
$ hangar-cofre sync ~/Backups/hangar      # baixa o bucket com a credencial só leitura
$ hangar-cofre test                       # abre o último backup de cada banco e confere
$ hangar-cofre restore-local minhaloja/postgres -at "2026-10-15 14:32"   # opcional: até um minuto
```

**Desastre completo (a cada 3 meses, numa VPS descartável), cronometrando:**

1. VPS nova, instalar como na seção 2 (sem criar usuário).
2. Copiar o `cofre.toml` (credencial só leitura + kit) para o servidor.
3. `sudo hangard restore -cofre cofre.toml` — recupera painel, chave
   mestra, configuração e certificados (o que existia vai para o lado).
4. `sudo systemctl start hangard` e entrar com o usuário de sempre.
5. `sudo -u hangar hangard restore databases -cofre cofre.toml` — redes,
   cada Postgres até o último minuto (WAL) e depois os serviços.
6. Apontar o DNS de teste para a VPS nova e abrir a loja.
7. Anotar o tempo total (meta: menos de 1 h) e apagar a VPS.

Pelo painel, num serviço Postgres: aba **Backups → Restaurar** (2FA;
padrão é restaurar num serviço novo, sobrescrever exige digitar o nome).

## 6. Trocar chaves, senhas e tokens

| O quê | Quando | Como |
|---|---|---|
| Senha de um usuário | esqueceu, vazou | `sudo -u hangar hangard user password -email ...` (desbloqueia e encerra as sessões) |
| 2FA | celular perdido, app comprometido | `sudo -u hangar hangard user totp -email ...` (novo QR) ou `totp-off` |
| Conta bloqueada (20 falhas) | | `sudo -u hangar hangard user unlock -email ...` |
| Chave mestra | `/etc/hangar` ou um backup antigo do painel caiu em mãos erradas | abaixo |
| Token do Git (credencial) | vazou, expirou | página **Credenciais Git** (ou Configurações do projeto) → **Trocar token**: vale para todos os serviços que usam a credencial no próximo deploy. Serviço com token próprio antigo: Configurações do serviço → **Trocar credencial** |
| Webhook do GitHub | URL vazou | Configurações → **gerar novo** webhook (2FA) e colar no GitHub |
| Segredos de app (`SECRET_KEY`, R2...) | vazou | trocar na origem, depois na aba Variáveis + Deploy |
| Credenciais do bucket | vazou | criar chave nova no provedor (sem permissão de apagar), cadastrar o destino de novo, apagar o antigo |
| Chaves do Kit de recuperação | perdeu uma | Backups → Kit → gerar a nova, confirmar, remover a perdida |
| Token do GitHub do updater | expirou | `install -m 0400 -o hangar -g hangar novo-token /etc/hangar/github-token` |
| Links públicos de status | vazou | Links de status → revogar (404 na hora) |

**Chave mestra (cifra todos os segredos do banco):**

```
vps$ sudo systemctl stop hangard                              # as lojas continuam no ar
vps$ sudo -u hangar hangard secrets rotate-key                # cifra tudo de novo, numa transação
vps$ sudo install -m 0400 -o hangar -g hangar /etc/hangar/master.key /etc/hangar/master.key.antiga
vps$ sudo install -m 0400 -o hangar -g hangar /var/lib/hangar/master.key.new /etc/hangar/master.key
vps$ sudo shred -u /var/lib/hangar/master.key.new
vps$ sudo systemctl start hangard
```

Depois: abrir uma variável secreta (revelar) para confirmar, rodar
**Backups → painel → agora**, copiar a chave nova para fora do servidor e
só então apagar a `.antiga` (os backups antigos do painel têm a chave
antiga dentro). Se o comando for interrompido antes do fim, nada mudou no
banco; se for interrompido depois, a chave certa é a `master.key.new`.

## 7. O que vigiar

O painel avisa sozinho (Telegram/e-mail/webhook). Os alertas de segurança
não podem ser desligados: login de IP novo, tentativas em série, conta
bloqueada, 2FA desligada, ação com sudo (revelar segredo, abrir porta,
domínio, conectar projetos...), usuário criado, porta aberta para qualquer
IP, **porta aberta fora do painel**, canal adicionado, atualização
aplicada ou desfeita, painel trancado/destrancado.

Uma olhada por semana:

| Onde | O que esperar |
|---|---|
| Visão geral | CPU/RAM/disco com folga; disco < 85 % |
| Backups | "tudo em dia"; WAL com atraso de segundos; último simulado < 31 dias |
| Atualizações | nenhum 🔴; 🟠 com plano |
| Portas abertas | só o que você lembra de ter aberto, com prazo |
| Auditoria → Verificar integridade | íntegra |
| `journalctl -u hangard -p warning --since -7d` | sem repetição estranha |
| `systemctl status hangard` | `Memory:` perto de 30–60 MB parado; picos de ~160 MB só durante login (argon2) |

Números de referência (teste de carga): o
painel parado usa ~20–30 MB; sob ~2 800 req/s chega a ~40 MB e volta.

## 8. Incidentes

### O painel não abre

1. `systemctl status hangard` e `journalctl -u hangard -n 100`.
2. Ativo e ouvindo? `curl -s http://127.0.0.1:7700/healthz` no servidor.
3. "421 unknown host": o túnel usa outro nome; use `localhost:7700` ou
   `127.0.0.1:7700` (são os de `[panel] hosts`).
4. 403 em tudo: painel trancado → seção 4.
5. Não sobe depois de atualização: o updater já deve ter voltado; senão
   seção 3 "voltar à mão".
6. Disco cheio: `df -h /var/lib/hangar` — o painel continua respondendo
   com erro e volta sozinho quando sobra espaço. Liberar: `docker system
   df`, imagens antigas (`docker image prune`), `journalctl --vacuum-size`,
   `backups/staging/` (só se nenhum backup estiver rodando).

As lojas **não dependem do painel**: com o `hangard` parado, contêineres e
Caddy continuam servindo.

### Uma loja caiu

1. Alerta "contêiner caiu" chega em menos de 1 min.
2. Aba do serviço → Logs. Contêiner parado por fora → **Iniciar**.
3. Deploy recente quebrou? **Deploys → voltar** (rollback para a imagem
   fixada, sem rebuild, < 30 s).
4. Banco: aba do Postgres, métricas de memória (OOM?) e logs.
5. Domínio sem HTTPS: Domínios dinâmicos → negados recentemente; a app
   respondeu ao `ask`? O DNS aponta para cá?

### Docker reiniciou ou ficou fora

O painel continua de pé (somente leitura para projetos) e volta a mandar
no Docker quando ele responde. Com `live-restore`, reiniciar o Docker não
derruba os contêineres. Depois: conferir Visão geral e Portas abertas
(as regras de firewall sobrevivem ao reinício do Docker).

### Suspeita de invasão

1. **Trancar** (seção 4). 2. `hangard audit verify`. 3. Auditoria: o que foi
revelado, aberto, criado. 4. Trocar senha + 2FA + segredos revelados +
chave mestra se houver indício de acesso ao disco (seção 6). 5. Portas
abertas e Domínios: fechar o que não reconhece. 6. Revogar links de status
e gerar webhooks novos. 7. Só então destrancar.

### Banco do painel travado ou corrompido

"database is locked" nos logs: alguém abriu o `hangar.db` com outra
ferramenta (sqlite3, backup copiando). Fechar essa ferramenta; o painel
espera 5 s por escrita, devolve erro e se recupera sozinho. Corrompido
(raro, disco com defeito): parar o painel e restaurar a cópia mais nova
entre `backups/pre-update-*`, `backups/painel/` (cópia feita antes de cada migração do banco) e o
backup do painel no bucket (`hangard restore`).

## 9. Migração do Easypanel (Etapa 12)

Um projeto de cada vez, **do menor risco para o maior; o mais crítico
por último**. Para cada projeto:

**Preparação (dias antes)**

1. VPS de produção nova, Hangar instalado (seção 2), checklist do host
   feito, `verify` da VPS passando, simulado de restauração (seção 5) com
   dados de teste.
2. No Hangar: criar o projeto, os serviços (Postgres/Redis pelos templates,
   a app pelo Git com o token só leitura), as variáveis (importar o `.env`
   do Easypanel pela prévia), domínios fixos e, se for o caso, domínios
   dinâmicos (o Django precisa da rota de verificação e do
   `HANGAR_DOMAIN_CHECK_SECRET`).
3. Backup do Postgres no Easypanel (`pg_dump -Fc`), restaurar no Hangar
   (aba Backups → Restaurar de um dump) e validar: contagem de linhas das
   tabelas principais, login na app por um domínio de teste.
4. Ligar backups (agenda + WAL) desse banco e esperar o primeiro "testado ✅".
5. **Baixar o TTL** dos registros DNS envolvidos para 60 s, **um dia antes**.

**Janela (fora do horário de pico, ~30 min)**

6. Aviso de manutenção na loja, se houver.
7. Congelar escrita no Easypanel (modo manutenção da app ou parar os
   workers e o web).
8. Último `pg_dump` no Easypanel → restaurar no Hangar **sobrescrevendo**
   (digitar o nome) → conferir contagens de novo.
9. Trocar o DNS (num SaaS multi-loja: `host.minhaloja.com.br` → IP novo; lojas
   com CNAME vão juntas).
10. Acompanhar: certificados emitidos (Domínios dinâmicos), logs da app,
    alertas, uma compra de teste.

**Depois**

11. **Easypanel continua ligado por 7 dias** como plano de volta (sem
    escrita). Voltar = DNS de volta + dump do Hangar restaurado lá.
12. Em 7 dias sem problema: subir o TTL de volta, último backup do
    Easypanel guardado fora, desligar a VPS antiga.
13. Anotar no fim deste documento: data, tempo de janela, problemas.

**Pronto quando:** projeto `minhaloja` em produção no Hangar, backups confirmados
(testado ✅ + WAL em dia + `hangar-cofre test` no Mac) e simulado de
restauração feito na VPS de produção.

### Registro das migrações

| Projeto | Data | Janela | Observações |
|---|---|---|---|
| | | | |
