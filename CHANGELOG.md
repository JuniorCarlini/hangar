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

## [0.5.3] - 2026-10-18

### Corrigido

- O **histórico de atualizações** ficava vazio: o resultado de cada
  atualização não chegava a ser registrado. Agora é registrado, e o
  histórico mostra também as atualizações feitas antes desta correção.
- O ícone de **Equipe** na barra lateral ganhou animação, como os outros.

## [0.5.2] - 2026-10-18

### Alterado

- O **código de confirmação do kit** agora tem máscara: os traços entram
  sozinhos (XXXX-XXXX-XXXX) e não passa de 12 caracteres.

## [0.5.1] - 2026-10-18

### Corrigido

- Em **Equipe**, sem nenhum projeto criado, a escolha de projetos mostra o
  aviso no mesmo estilo das outras telas vazias.

## [0.5.0] - 2026-10-18

### Adicionado

- **Equipe** (só para o dono): convide pessoas por um link de uso único
  (24 h), escolha o papel (Admin, Operador ou Leitor) e, para Operador e
  Leitor, quais projetos a pessoa vê. Quem fica limitado a alguns projetos
  vê só esses projetos e a própria conta: os outros projetos e as telas
  do servidor somem da barra lateral, da busca e da visão geral, e não
  abrem nem pelo endereço. Mudar o acesso ou remover alguém encerra as
  sessões da pessoa na hora; o último dono não pode ser removido.

### Corrigido

- Depois de clicar em **Atualizar**, a tela travava (às vezes na página de
  "fora do ar"). Agora ela espera o painel reiniciar e se recarrega
  sozinha quando a versão nova está no ar.

## [0.4.5] - 2026-10-18

### Alterado

- Para confirmar o Kit de recuperação e para restaurar um backup, o
  arquivo do kit agora é escolhido numa área de arrastar e soltar (ou
  clicar), com o nome do arquivo escolhido embaixo. Na confirmação, o
  código se preenche sozinho logo abaixo.

## [0.4.4] - 2026-10-18

### Corrigido

- O **histórico de atualizações** mostrava só a última; agora lista todas
  as atualizações feitas pelo painel, da mais nova para a mais antiga.

## [0.4.3] - 2026-10-18

### Corrigido

- A **versão em papel do Kit de recuperação** saía deslocada, estreita, sem
  o logo e com uma segunda página em branco. Agora ocupa uma página A4
  inteira, com o QR code ao lado das chaves e o aviso com um ícone.

### Alterado

- O arquivo **hangar-kit.txt** ficou mais claro, na mesma ordem do papel:
  os dados da chave, o que ela é, como usar, o aviso e, por último, a
  chave secreta.

## [0.4.2] - 2026-10-18

### Alterado

- A **versão em papel do Kit de recuperação** ganhou um layout de verdade:
  cabeçalho, nome, data e código de confirmação, o QR code ao lado da chave
  secreta (em grupos de quatro, fácil de ler), três passos de como usar e
  um aviso para não fotografar nem enviar por mensagem.

## [0.4.1] - 2026-10-18

### Corrigido

- No rodapé da barra lateral, a versão aparece sozinha e centralizada; um
  clique abre a tela de atualização.

## [0.4.0] - 2026-10-17

### Adicionado

- **Lembrete do Kit de recuperação**: a cada 5 meses o painel pergunta se o
  kit ainda está guardado (uma faixa no topo, só para o dono). Basta
  escolher o arquivo do kit ou digitar o código de confirmação de novo.
- Em **Backups**, um quadro **O que é salvo e quando**: o painel todo dia e
  depois de mudanças, os PostgreSQL no intervalo que você escolher, e por
  quanto tempo cada cópia fica guardada. MariaDB, MongoDB, Redis e os
  arquivos dos apps ainda não têm backup automático, e o quadro diz isso.

### Alterado

- As notas de cada versão, na tela de atualização, agora são o texto do
  CHANGELOG, em português e sem marcação.
- O instalador não pede mais para copiar a chave mestra pelo SSH: o Kit de
  recuperação, gerado no painel, já cobre o backup do painel com a chave.
- Os passos para ligar os backups foram reescritos em palavras simples,
  inclusive por que o bucket é criado por você, e não pelo Hangar.
- O rodapé da barra lateral mostra só o IP do servidor e a versão do
  Hangar, com o aviso de versão nova. CPU e memória ficam na Visão geral.

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

[Não lançado]: https://github.com/JuniorCarlini/hangar/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/JuniorCarlini/hangar/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/JuniorCarlini/hangar/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/JuniorCarlini/hangar/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/JuniorCarlini/hangar/compare/v0.4.5...v0.5.0
[0.4.5]: https://github.com/JuniorCarlini/hangar/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/JuniorCarlini/hangar/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/JuniorCarlini/hangar/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/JuniorCarlini/hangar/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/JuniorCarlini/hangar/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/JuniorCarlini/hangar/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/JuniorCarlini/hangar/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/JuniorCarlini/hangar/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/JuniorCarlini/hangar/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/JuniorCarlini/hangar/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/JuniorCarlini/hangar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/JuniorCarlini/hangar/releases/tag/v0.1.0
