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

## [0.3.3] - 2026-10-17

### Adicionado

- A **Visão geral** e as métricas de cada serviço se atualizam sozinhas a
  cada 10 segundos, sem recarregar a página.

### Corrigido

- Em **Minha conta**, os botões de tema agora ocupam a largura toda, como
  em Marca.

## [0.3.2] - 2026-10-17

### Corrigido

- Em **Minha conta → Preferências**, o seletor de tema ficava desalinhado
  dos campos de nome e idioma.

## [0.3.1] - 2026-10-17

### Corrigido

- Um endereço que não existe no painel mostrava "404 page not found" em
  texto puro; agora aparece a página de erro do próprio Hangar, com um
  botão para voltar ao início. O mesmo vale para acesso negado e excesso
  de tentativas.

## [0.3.0] - 2026-10-17

### Adicionado

- **Painel na internet com HTTPS, sem SSH**: a instalação já liga o HTTPS e
  mostra o endereço do painel, `https://hangar.<seu-ip>.sslip.io`, com
  certificado de verdade e sem precisar de domínio. Com domínio:
  `[panel] public_host`. Se as portas 80/443 estiverem ocupadas, o painel
  fica pelo túnel SSH, como antes.

### Alterado

- O primeiro acesso não pede mais código: a tela de criar a conta de dono
  fica aberta por **30 minutos** depois que o Hangar liga. Passou do prazo,
  `sudo systemctl restart hangard` abre mais 30.

## [0.2.0] - 2026-10-17

### Adicionado

- **Primeiro acesso pelo navegador**: na primeira visita ao painel aparece
  **Criar a conta de dono** (e-mail, senha e verificação em duas etapas
  opcional, que já vem marcada). Para ninguém mais criar a conta antes de
  você, a tela pede o **código de configuração** que o instalador mostra no
  fim; ela some assim que o dono existe. `hangard user create` continua
  funcionando.

### Alterado

- A verificação em duas etapas passa a ser opcional por padrão em novas
  instalações (`require_2fa = false`): cada conta liga em **Minha conta**, e
  quem está sem ela vê um aviso no topo. Instalações existentes não mudam.

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

[Não lançado]: https://github.com/JuniorCarlini/hangar/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/JuniorCarlini/hangar/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/JuniorCarlini/hangar/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/JuniorCarlini/hangar/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/JuniorCarlini/hangar/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/JuniorCarlini/hangar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/JuniorCarlini/hangar/releases/tag/v0.1.0
