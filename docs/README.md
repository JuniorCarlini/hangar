# Hangar — Documentação de Projeto

Hangar é um painel de hospedagem self-hosted (na linha de Easypanel, Coolify e
Dokploy) feito sob medida para uma necessidade que nenhum deles resolve bem:
**um SaaS multi-loja em que cada cliente aponta o próprio domínio para o
servidor e o sistema emite HTTPS para esse domínio automaticamente, sem
cadastro manual e sem abrir brecha de segurança.**

## Princípios

1. **Segurança por padrão** — tudo nasce fechado; abrir exige ação explícita.
2. **Leve** — um binário só, sem runtime extra; o painel ocioso usa poucas dezenas de MB de RAM.
3. **Simples de operar** — um comando instala; um comando atualiza; um arquivo de backup restaura.
4. **Sem mágica escondida** — tudo que o Hangar faz no Docker pode ser visto e auditado.
5. **Domínios dinâmicos como recurso de primeira classe**, não como gambiarra.

## Índice

| Documento | Conteúdo |
|---|---|
| [00 — Visão geral](00-visao-geral.md) | Problema, objetivos, o que está fora do escopo |
| [01 — Arquitetura](01-arquitetura.md) | Componentes, fluxo de requisição, redes |
| [02 — Stack e versões](02-stack-e-versoes.md) | Linguagem, bibliotecas, versões-alvo |
| [03 — Domínios customizados e TLS](03-dominios-customizados-tls.md) | **O coração do projeto**: on-demand TLS com autorização |
| [04 — Segurança](04-seguranca.md) | Modelo de ameaça e controles |
| [05 — Isolamento e recursos](05-isolamento-e-recursos.md) | Containers, redes, limites, hardening |
| [06 — Monitoramento e logs](06-monitoramento-e-logs.md) | Métricas por container, logs ao vivo, alertas |
| [07 — Deploy e builds](07-deploy-e-builds.md) | Git, Dockerfile, zero-downtime, rollback |
| [08 — Serviços (templates)](08-servicos-templates.md) | Postgres, Redis, etc. com um clique |
| [09 — Backups](09-backups.md) | Volumes, bancos, painel, destino externo |
| [10 — Modelo de dados](10-modelo-de-dados.md) | Tabelas do SQLite do painel |
| [11 — API](11-api.md) | Endpoints HTTP do painel |
| [12 — Padrões de código](12-padroes-de-codigo.md) | Layout do repositório, convenções, lint, testes |
| [14 — Atualizações e vulnerabilidades](14-atualizacoes-de-dependencias.md) | Aviso de bibliotecas/imagens desatualizadas ou vulneráveis (Telegram/e-mail) |
| [15 — Painel público de status](15-painel-publico-de-status.md) | Link externo para monitorar a VPS sem expor nomes nem detalhes |
| [17 — Telas, fluxos e segurança](17-telas-fluxos-e-seguranca.md) | **Plano completo**: cada tela, quem pode usar, proteção e fluxo; lista de 34 brechas e mitigações |
| [18 — Design system "Pista"](18-design-system.md) | Lógica do Railway + forma do Render + componentes do Tucano: tokens, canvas, drawer, componentes |
| [20 — Logs e retenção](20-logs-e-retencao.md) | Onde cada log mora, limites, agregação contra inchaço, retenção da auditoria |
| [21 — Atualização com um clique](21-atualizacao-do-painel.md) | Botão "Atualizar": release assinada, troca segura, volta automática |
| [22 — Idiomas e temas](22-idiomas-e-temas.md) | pt-BR e inglês (espanhol previsto antes da 1.0); tema escuro, claro e do sistema, por usuário |
| [24 — Operação](24-operacao.md) | Manual do dia a dia: instalar, atualizar e voltar, trancar, simulado de restauração, trocar chaves, o que vigiar, incidentes, migração do Easypanel |
| [27 — Criar serviços e importar compose](27-criar-servicos-e-compose.md) | Novo serviço com um nome só e opções avançadas recolhidas; importar um docker-compose com prévia: o que vira template, imagem ou build, o que é recusado, e o modelo Django + Postgres + Redis + Celery |
| [adr/](adr/) | Decisões de arquitetura registradas |

## Decisões principais (resumo)

| Tema | Decisão | ADR |
|---|---|---|
| Linguagem do painel | Go | [0001](adr/0001-linguagem-go.md) |
| Proxy de borda | Caddy (on-demand TLS) no lugar do Traefik | [0002](adr/0002-caddy-em-vez-de-traefik.md) |
| Banco do painel | SQLite (WAL), sem CGO | [0003](adr/0003-sqlite.md) |
| Orquestração | Docker Engine direto (sem Swarm/K8s) no MVP | [0004](adr/0004-docker-engine-sem-swarm.md) |
| Interface | HTML renderizado no servidor (templ + HTMX), embutido no binário | [0005](adr/0005-interface-server-side.md) |
| Containers | Mesmo modelo do Easypanel (nomes, portas expostas, projetos conectáveis) | [0006](adr/0006-modelo-de-containers-easypanel.md) |
| Backups | Cifra assimétrica (age) + storage imutável | [0008](adr/0008-backups-assimetricos-imutaveis.md) |
| Design | "Pista": lógica do Railway, forma do Render, componentes do Tucano | [0009](adr/0009-design-system-pista.md) |
