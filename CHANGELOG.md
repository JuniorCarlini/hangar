# Changelog

Tudo o que muda no Hangar e que você, usando o painel, vai perceber.
O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e as versões seguem o [Versionamento Semântico](https://semver.org/lang/pt-BR/).
Enquanto a versão começar com `0.`, uma versão nova pode mudar telas e
configurações.

As versões publicadas estão em
[Releases](https://github.com/JuniorCarlini/hangar/releases) e chegam ao
servidor pelo botão **Atualização** do painel.

## [Não lançado]

## [0.1.0] - 2026-10-17

Primeira versão pública.

### Adicionado

- **Projetos e serviços**: cada projeto tem a própria rede Docker. Um serviço
  nasce de uma imagem, de um repositório Git, de um template de um clique ou
  de um `docker-compose.yaml` colado. Serviços se ligam por referência
  (`${{db.DATABASE_URL}}`).
- **Templates**: PostgreSQL, MariaDB, MongoDB, Redis e Valkey (cache ou
  filas), RabbitMQ, Meilisearch, RustFS (S3), n8n, Uptime Kuma, pgAdmin e
  Adminer, já endurecidos. Os de administração nascem internos.
- **HTTPS automático**: cada porta pública ganha um link
  `projeto-servico.IP.sslip.io` com certificado de verdade, ou um subdomínio
  do seu domínio (curinga via DNS-01). Domínios próprios, e domínios dos
  clientes com HTTPS sob demanda autorizado pela app.
- **Deploy** sem downtime, rollback em segundos, build por Git com BuildKit,
  webhook do GitHub e comando pré-deploy.
- **Backups** cifrados com age, enviados para S3 com Object Lock, com WAL
  contínuo e kit de recuperação.
- **Segurança**: 2FA obrigatória, modo sudo para ações críticas, papéis,
  auditoria encadeada, alertas de segurança e botão **Trancar painel**. Nada
  vai para a internet sem senha confirmada.
- **Operação**: métricas e logs ao vivo, terminal no navegador, alertas por
  Telegram, e-mail e webhook, links públicos de status e monitor de
  vulnerabilidades.
- **Instalação de um comando** e **atualização com um clique**, com release
  assinada (Ed25519) e volta automática se a versão nova não subir.
- Português e inglês, tema claro, escuro ou do sistema.

[Não lançado]: https://github.com/JuniorCarlini/hangar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/JuniorCarlini/hangar/releases/tag/v0.1.0
