# 15 — Painel público de status (link externo)

Objetivo: um **link** que você abre de qualquer lugar (celular, notebook, um
monitor de parede em casa) para ver como a VPS está: CPU, memória, disco, rede
e quais serviços estão consumindo mais. Tudo isso **sem login** e **sem
entregar informação útil para um atacante**.

Vem **desligado** por padrão. Você liga, configura o que aparece e pode
revogar a qualquer momento.

## Como é o link

```
https://status.seudominio.com/s/k7Qm9xV2...   (token de 32 bytes aleatórios)
```

- Pode haver **vários links**, cada um com sua configuração ("monitor de casa",
  "sócio", "cliente X"). Cada um pode ser revogado sozinho.
- O token é guardado só como hash. Ao criar, ele aparece uma vez. Se perder,
  gere outro.
- Opções por link:
  - Expiração (nunca / 24 h / 7 d / 30 d).
  - Senha extra (opcional).
  - Restringir por IP (ex.: só o IP da sua casa).
  - **Modo TV/quiosque**: tela cheia, fonte grande, fundo escuro, atualiza
    sozinha.

## O que aparece (e o que nunca aparece)

| Aparece | Nunca aparece |
|---|---|
| CPU, RAM, swap, disco, rede, load e uptime do servidor | IP do servidor, hostname, provedor |
| Ranking de serviços por consumo (CPU, RAM, rede) | Nome real do container, imagem, versão, tag |
| Estado de cada serviço: 🟢 rodando / 🟡 degradado / 🔴 parado | Domínios, portas, variáveis de ambiente |
| Gráficos de 1 h / 24 h / 7 d | Logs |
| Uptime dos serviços (% no período) | Versões do Docker, Caddy, Hangar, SO |
| Contagem de alertas ativos (sem detalhes) | Qualquer botão de ação |

### Nomes dos serviços: apelidos

Cada link escolhe como os serviços aparecem:

| Modo | Exemplo | Uso |
|---|---|---|
| **Apelido** (padrão) | "Loja principal", "Banco principal", "Cache" | Você define um apelido por serviço |
| **Genérico** | "Serviço A", "Serviço B", "Banco 1" | Nada revela o que é |
| Ocultar | Só os totais do servidor | Máxima discrição |

Também dá para escolher **quais serviços** entram em cada link.

## Como é protegido

- **Listener e rota separados** do painel. O handler público só tem acesso de
  leitura a um *snapshot* agregado das métricas, montado já sem os campos
  proibidos. Não existe caminho de código do link público até o Docker, o
  banco de segredos ou as rotas de ação.
- Resposta **cacheada por 10 s** (mil acessos = uma leitura das métricas) +
  rate limit por IP. Não serve para derrubar o servidor.
- Token inválido devolve 404 genérico, no mesmo tempo de um token válido
  (não dá para "adivinhar" tokens pela resposta).
- Sem cookies (exceto a senha opcional, em cookie próprio e isolado),
  `X-Robots-Tag: noindex`, `Referrer-Policy: no-referrer` (o token não vaza em
  links clicados) e CSP estrita.
- Pode ficar num domínio separado (`status.seudominio.com`), diferente do
  painel. Em modo bunker, o painel continua invisível e só o status fica
  público.
- Todo acesso conta no painel ("link 'monitor de casa': 312 acessos hoje,
  último de 189.x.x.x"). Um pico estranho gera alerta.

## Formatos

| Formato | Para quê |
|---|---|
| Página HTML (normal e modo TV) | Navegador, celular, monitor de parede |
| `.../s/<token>.json` | Seu próprio dashboard, widget de celular, Home Assistant |
| `.../s/<token>/metrics` (Prometheus) | Grafana em casa, com a mesma filtragem e os mesmos apelidos |

Exemplo do JSON:

```json
{
  "generated_at": "2026-10-15T18:42:10Z",
  "server": { "cpu_pct": 37.2, "mem_pct": 61.0, "disk_pct": 48.5,
              "net_rx_bps": 1840000, "net_tx_bps": 5230000, "uptime_s": 1209600 },
  "services": [
    { "label": "Loja principal", "state": "running", "cpu_pct": 22.1, "mem_pct": 54.0, "uptime_pct_24h": 100 },
    { "label": "Banco principal", "state": "running", "cpu_pct": 8.4,  "mem_pct": 71.3, "uptime_pct_24h": 100 }
  ],
  "alerts_active": 0
}
```

## Alternativa "empurrar" (pós-MVP)

Em vez de expor um link, o Hangar **envia** o snapshot a cada minuto para um
destino seu (webhook HTTPS com assinatura HMAC, ou push para um Prometheus /
Uptime Kuma). Assim nada fica aberto no servidor.


## Como ficou na Etapa 11

O que já funciona (pacote `internal/statuspage`, tela `/status-links`):

- Criar (Admin+, com sudo) com nome, modo de nomes (apelido, genérico,
  oculto), serviços escolhidos, expiração (nunca/24 h/7 d/30 d) e restrição
  por IP ou faixa. O endereço aparece **uma vez**; no banco fica só o
  SHA-256 do token (32 bytes aleatórios).
- Revogar (Admin+, com sudo): o link responde 404 na hora, em todos os
  formatos. Token desconhecido, revogado, expirado ou de IP não permitido
  dão a mesma resposta 404.
- Página HTML (com períodos 1 h/24 h/7 d), modo TV (`?tv=1`, escuro, fonte
  grande, recarrega a cada 30 s), `.json` e `/metrics` (Prometheus), todos a
  partir do mesmo *snapshot* `statuspage.Public`, que só tem números,
  estados e apelidos. Um teste procura nome de container, projeto, imagem,
  versão, IP e hostname nas quatro respostas e falha se achar.
- Cache de 10 s por link, rate limit de 60 acessos/min por IP, sem cookies,
  `X-Robots-Tag: noindex` e a mesma CSP do painel (sem script nenhum).
- Contagem de acessos (hoje e total) e último acesso com IP mascarado.
- Domínio separado: `[status] hosts = ["status.seudominio.com"]`. Esse host
  só alcança `/s/...` e `/assets/...`; qualquer outra rota responde 404.

Ainda não: senha extra por link, listener próprio (hoje as rotas `/s/` são
públicas no mesmo servidor do painel, isoladas por política e por host),
alerta de pico de acessos e a contagem de alertas ativos (fica 0 até a
Etapa 8 ligar `statuspage.AlertCounter`).
