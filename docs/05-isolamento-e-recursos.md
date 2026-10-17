# 05 — Isolamento e recursos

Objetivo: vários apps, vários Postgres, vários Redis na mesma VPS, cada um no
seu quadrado, sem um derrubar o outro.

## Hierarquia

```
Servidor
└── Projeto (ex.: "lojas", "site-institucional")
    ├── Serviço: app      (django)
    ├── Serviço: postgres (postgres-lojas)
    └── Serviço: redis    (redis-lojas)
```

- Projeto = rede Docker própria (`hangar_<slug>`, bridge com saída para a
  internet, porque apps chamam APIs de pagamento, frete etc.) + prefixo de
  nomes + labels.
  Projetos podem ser conectados entre si (ver "Rede e portas").
- Serviço = um container (ou dois, durante o deploy).
- Labels em tudo que o Hangar cria: `hangar.managed=true`,
  `hangar.project=<id>`, `hangar.service=<id>`, `hangar.deployment=<id>`.
  O Hangar **nunca** toca em container sem `hangar.managed=true`.

## Nomes e DNS interno

Igual ao Easypanel: `<projeto>_<serviço>`, por exemplo `minhaloja_postgres:5432`
e `minhaloja_redis:6379`. O painel mostra a URL de conexão interna pronta para
copiar (`postgres://user:senha@minhaloja_postgres:5432/db`).

## Padrões de hardening (aplicados a todo container criado)

| Opção | Padrão | Pode mudar? |
|---|---|---|
| `security_opt: no-new-privileges` | ligado | não |
| `cap_drop: ALL` + `cap_add` mínimo (CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, NET_BIND_SERVICE, KILL) | ligado | só capabilities de uma lista permitida; SYS_ADMIN, NET_ADMIN, SYS_PTRACE não existem |
| `init` (reaper de processos zumbis) | ligado | não |
| Seccomp | perfil padrão do Docker | não pode desligar pela interface |
| `privileged` | **proibido** | não |
| Montar `docker.sock` | **proibido** | não |
| Bind mount de caminho do host | proibido, exceto lista branca em `/srv/hangar-data/` | admin, com aviso |
| `pids_limit` | 512 | sim |
| Limite de memória | obrigatório (padrão 512 MiB app, template define para bancos) | sim |
| Limite de CPU (`nano_cpus`) | padrão 1 vCPU | sim |
| `read_only` rootfs | ligado em templates que suportam; opcional em apps | sim |
| `tmpfs /tmp` | quando read_only | sim |
| Usuário | não-root quando a imagem permite | sim |
| `restart` | `unless-stopped` | sim |
| Log driver | `local`, máx 50 MB × 3 arquivos | sim |
| Healthcheck | do template ou configurado pelo usuário | sim |

## `daemon.json` do Docker (instalador)

```json
{
  "log-driver": "local",
  "log-opts": { "max-size": "50m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false,
  "userland-proxy": false,
  "default-address-pools": [{ "base": "10.200.0.0/16", "size": 24 }]
}
```

- `live-restore`: atualizar/reiniciar o Docker não derruba os containers.
- `icc: false` na bridge padrão (nossas redes têm controle explícito).
- `userns-remap`: **opcional**, desligado por padrão — aumenta isolamento, mas
  quebra permissões de volumes de várias imagens. Documentar como avançado.

## Rede e portas — mesmo comportamento do Easypanel

O modelo de containers segue o do Easypanel (ver [ADR 0006](adr/0006-modelo-de-containers-easypanel.md)):
quem já usa o Easypanel não precisa reaprender nada. A diferença está só nas
proteções extras, que você pode desligar.

### Nomes

Igual ao Easypanel: o container de um serviço responde pelo nome
`<projeto>_<serviço>` (ex.: `minhaloja_postgres`, `minhaloja_redis`). O painel
mostra a URL de conexão interna pronta para copiar.

### Comunicação entre serviços

| Situação | Como funciona |
|---|---|
| Serviços do **mesmo projeto** | Sempre se enxergam (rede do projeto). |
| Serviços de **projetos diferentes** | Por padrão não se enxergam. Na aba "Rede" do projeto, **"Conectar com o projeto X"** (um clique) e os dois passam a se enxergar pelo nome, exatamente como no Easypanel. Desconectar é outro clique. |
| Modo "rede compartilhada" (opcional, nas configurações do servidor) | Todos os projetos numa rede só, 100% igual ao Easypanel. Para quem prefere não pensar nisso. |

### Expor porta (aba "Portas", igual ao Easypanel)

Para acessar o Postgres pelo DBeaver, fazer `pg_dump` da sua máquina, conectar
um sistema externo etc.:

| Campo | Exemplo | Observação |
|---|---|---|
| Porta publicada (host) | `5433` | O painel avisa se já estiver em uso |
| Porta do container | `5432` | |
| Protocolo | TCP / UDP | |
| **Quem pode acessar** | `Qualquer IP` / `Somente estes IPs: 200.1.2.3` / `Só localhost (túnel SSH)` | Ver abaixo |
| Expira em | `nunca` / `1 h` / `24 h` / `7 dias` | Opcional; padrão "nunca", como no Easypanel |

Ao salvar, a porta é publicada na hora (o container é recriado só se for
necessário, como no Easypanel).

O que o Hangar faz a mais, por baixo:

1. **O Docker ignora o UFW.** Uma porta publicada pelo Docker fica aberta para
   a internet mesmo com o UFW bloqueando. No Easypanel isso pega muita gente de
   surpresa. O Hangar escreve a regra na chain `DOCKER-USER` do nftables, então
   "Somente estes IPs" é respeitado de verdade.
2. **"Só localhost"** publica em `127.0.0.1:5433`. Fica acessível pelo túnel
   (`ssh -L 5433:127.0.0.1:5433 usuario@vps`) e invisível para a internet.
   O painel mostra o comando pronto.
3. Expor um **banco** para "Qualquer IP" mostra um aviso (não bloqueia):
   bancos expostos são alvo de varredura automática em minutos. Recomenda
   restringir por IP ou usar o túnel.
4. Toda porta exposta aparece numa tela única ("Portas abertas no servidor"),
   com quem abriu e quando, e fica registrada no audit log. Assim nenhuma porta
   fica esquecida aberta.

### Backup local (o caso de uso citado)

Três jeitos, em ordem de preferência:

1. **Botão "Baixar backup"** no serviço Postgres: o painel roda `pg_dump` e
   entrega o arquivo pelo navegador. Não precisa expor porta nenhuma.
2. Porta exposta em **"Só localhost"** + túnel SSH + `pg_dump` local.
3. Porta exposta para **o seu IP** + `pg_dump` local.

## Volumes

- Volume nomeado por serviço: `hangar_<projeto>_<serviço>_data`.
- Apagar serviço **não** apaga volume por padrão; apagar volume é ação
  separada, em modo sudo, digitando o nome para confirmar.
- Uso de disco por volume aparece no monitoramento.

## Reserva de recursos do host

O painel calcula e mostra a soma dos limites de memória vs. RAM do host e avisa
quando o overcommit passa de 150%. Reserva fixa para o sistema + Docker +
Caddy + `hangard` (padrão 512 MiB), que não pode ser alocada a serviços.

## Situação (Etapa 5)

- **Portas** na aba do serviço: porta do servidor, porta do container,
  TCP/UDP, quem pode acessar (qualquer IP, somente estes IPs ou só
  localhost) e prazo (nunca, 1 h, 24 h, 7 dias). Portas 22, 80, 443, 7700 e
  7701 são recusadas. Abrir ou fechar recria o container; com deploy em
  andamento, o painel recusa antes de gravar.
- **"Somente estes IPs" de verdade:** o painel (sem privilégio) grava o
  estado desejado em `/var/lib/hangar/firewall/desired.json`; a unit root
  `hangar-firewall` (disparada por `hangar-firewall.path`) valida de novo e
  carrega a chain `HANGAR-PORTS`, chamada pela `DOCKER-USER`. As regras só
  pegam conexões que passaram por porta publicada (`ctstate DNAT` +
  `ctorigdstport`), então o tráfego entre containers nunca é afetado, e o
  loopback é sempre liberado. Roda **antes do Docker** no boot, para nenhum
  container publicar porta sem a restrição; reiniciar o Docker não apaga as
  regras. O resultado fica em `applied.json`, e a tela avisa se falhou.
- **"Só localhost"** publica em `127.0.0.1`; a tela mostra o comando do
  túnel SSH.
- **Portas abertas no servidor** (menu "Portas"): todas as portas, com quem
  pode acessar e quando fecham. Tudo na auditoria (`port.open`,
  `port.close`); o prazo fecha a porta sozinho (verificado a cada minuto).
- **Projetos conectados** (seção no projeto): os containers entram na rede
  do outro projeto e se enxergam pelo nome completo
  (`<projeto>_<serviço>`), na hora, sem redeploy. O apelido curto continua só
  dentro do próprio projeto, para nomes não colidirem.
- **Volumes nomeados** `hangar_<projeto>_<serviço>_<nome>`; apagar o serviço
  não apaga o volume.
- **Baixar backup** no Postgres: `pg_dump -Fc` roda dentro do container e vai
  direto para o navegador, sem gravar nada no servidor e sem abrir porta.
  Exige 2FA e fica na auditoria.

Testado na VM com o Mac fazendo as conexões de fora: porta liberada só para
outro IP fica bloqueada (o `DROP` conta os pacotes), liberada para o IP do
Mac abre; só localhost não responde de fora; regras sobrevivem a reiniciar o
Docker e a VM.

**Etapa 12:** abrir porta passou a pedir sudo (2FA de novo) e gera alerta
de segurança; fechar continua sem sudo, para reduzir exposição num clique.
Uma vigia lê `/proc/net/tcp` a cada minuto e alerta qualquer porta aberta
para fora que não tenha vindo do painel (SSH e `[alerts] allowed_ports`
são esperados).

**Ficou para depois:** Docker com backend `nftables` (sem `DOCKER-USER`);
modo "rede compartilhada" de todos os projetos; apagar volume pela tela;
aviso de porta já ocupada por outro programa antes do deploy (hoje o deploy
falha e o erro aparece no histórico).

