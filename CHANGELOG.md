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

## [0.5.22] - 2026-10-28

### Novo

- **Memória e CPU editáveis**: o card Recursos, em Configurações, muda os
  limites de um serviço depois de criado (antes só dava para escolher na
  criação). Vale no próximo deploy.
- **Workers sem porta**: no mesmo card, a porta interna pode mudar ou ir a
  0. Um serviço de repositório sem `EXPOSE` nascia na porta 8000, e o
  deploy de um worker (que não abre porta) esperava até dar erro. Com 0, o
  deploy só confere que o container segue rodando.
- **Atualizar a lista de repositórios**: um botão na aba Meus repositórios
  busca de novo no GitHub, sem esperar o cache, depois de você mudar o
  acesso do token por lá.
- **Aviso de token só com públicos**: quando a credencial não enxerga
  nenhum repositório privado, o painel diz qual permissão falta
  (Contents: Read-only, ou o escopo repo num token clássico).

## [0.5.21] - 2026-10-27

### Segurança

Mais defesas da auditoria de segurança.

- **Desligar a 2FA pede a senha**, como já acontecia ao ligar: um código de
  recuperação vazado não basta mais.
- **O painel nunca fica sem dono**: dois donos rebaixando um ao outro ao
  mesmo tempo podiam deixar o painel sem nenhum.
- **Segredo dos domínios dos clientes protegido**: uma variável com o mesmo
  nome não substitui mais o segredo que o Hangar usa para assinar a
  checagem.
- **Backups mais robustos**: o arquivamento contínuo do PostgreSQL funciona
  com caminhos de disco que tenham espaço ou símbolos, e backups com links
  forjados são recusados.
- **Ajustes de sistema mais seguros**: as tarefas que rodam como root
  (atualização, firewall, permissões) não seguem mais atalhos (symlinks)
  dentro da pasta do Hangar.
- **Outras**: a checagem de versões de imagem só segue redirecionamentos
  HTTPS; logos de templates com animações em links são recusados.

### Interno

- As actions do CI e do release ficam fixadas por commit, e o Dependabot
  propõe as versões novas toda semana.

## [0.5.20] - 2026-10-27

### Novo

- **Backup no modo simples**: basta cadastrar um destino para os backups
  começarem, sem gerar o kit de recuperação antes. O servidor guarda a
  chave e entrega os arquivos já abertos no download. O kit continua
  disponível para quem quer que só você consiga abrir os backups.
- **Conector de variáveis**: um cartão liga uma variável de um serviço à de
  outro (o endereço do banco, a senha do cache…). Cada serviço oferece os
  próprios nomes e endereços, e quem recebe escolhe como chamar.
- **Trocar a imagem inteira de um serviço** pelas configurações, com
  confirmação.
- **Um diálogo para os discos**: adicionar, editar e remover no mesmo lugar.
  Ao excluir um serviço, os discos dele podem ir junto.
- **Deploy automático com um switch**: o painel acompanha o branch e faz o
  deploy quando ele muda, sem precisar configurar webhook.
- **Editar a porta publicada** no mesmo formulário que a abre.

### Mudado

- **Variáveis num cartão só**: o arquivo `.env` é a fonte da verdade, com
  comentários, seções e ordem preservados, e um botão de copiar em cada
  valor.
- **Telas mais simples** de alertas (histórico e configuração em abas),
  backups (rotinas como lista, restaurações com cartão próprio) e equipe
  (a lista de pessoas, com a confirmação de senha no diálogo).
- **Abas Configurações e Deploy enxutas**: manutenção virou um botão no
  topo do deploy, e o repositório é editado direto no cartão dele.
- **Aba Rede mais limpa**: os domínios do serviço viram uma tabela só (link
  automático e domínios fixos), sem os textos longos. As explicações ficam
  no **?** ao lado do título.
- **Domínios dos clientes num modal**: aceitar domínios, o TXT de posse, a
  rota da app, o segredo e o kit do desenvolvedor saíram da aba e ficam no
  botão **Configurar**, ao lado de "Adicionar domínio". Depois de mudar
  algo, o modal reabre com o resultado. O segredo da app aparece direto
  para administradores, com botão de copiar, sem precisar confirmar a senha
  para ver.

### Corrigido

- **TXT de posse aceito na hora**: quando o cliente abria o domínio antes de
  criar o `_hangar.<domínio>`, o servidor guardava o "não existe" e seguia
  recusando por até 30 minutos depois de o registro ser criado. Agora o
  Hangar pergunta direto aos nameservers do domínio e aceita assim que o
  registro existe.

### Segurança

Correções de uma auditoria de segurança do código. Recomendado atualizar.

- **Projetos separados de verdade**: todo serviço com domínio ficava numa
  rede compartilhada, e de lá alcançava qualquer porta de serviços com
  domínio de outros projetos, sem passar pelo Caddy nem pelo vínculo entre
  projetos. Agora cada serviço fica só na rede do seu projeto, e o Caddy
  entra na rede de cada projeto que ele atende. A mudança é automática ao
  atualizar: o Caddy é recriado uma vez, e nenhum site perde a rota.
- **Ativar a 2FA pede a senha**: antes bastava estar logado. Quem achasse
  um navegador aberto podia cadastrar um celular próprio, passar pela
  confirmação de senha com esse código e trancar o dono fora.
- **Backup do painel só para o dono**: no modo simples, um administrador
  conseguia baixar o backup do painel já aberto, com a chave mestra e o
  banco inteiro, e com eles ler os segredos que são só do dono.
- **Trocar a chave mestra cobre os arquivos .env**: o texto do editor de
  .env (com os valores secretos) ficava na chave antiga depois da troca.
  Quem tinha a chave vazada continuava abrindo, e o painel deixava de ler.
- **hangar-cofre não roda imagem desconhecida**: a restauração usava a
  imagem Docker escrita nos metadados do backup, que não são protegidos
  pela criptografia. Agora só a imagem oficial do postgres é usada
  automaticamente; outra precisa de `-image`.
- **Nomes de outros projetos escondidos**: quem só vê alguns projetos não
  vê mais, na página do serviço, o nome do projeto que recebe domínios dos
  clientes.
- **Defesas extras**: alertas por e-mail não conectam mais em endereços
  internos do servidor; os textos da marca não conseguem rodar comandos
  nas páginas de erro; o redirecionamento depois do login recusa
  caracteres de controle; o logo dos templates abre isolado.

## [0.5.19] - 2026-10-26

### Corrigido

- **Textos que cresciam e voltavam ao trocar de tela**: a fonte era baixada
  de novo a cada página, e o texto aparecia por um instante na fonte do
  sistema. Agora ela fica guardada no navegador como o resto do estilo.
- **Botão Atualizar que "não atualizava a página"**: logo depois do clique a
  página às vezes voltava a mostrar o botão e parava de esperar, enquanto a
  atualização seguia por trás. Agora ela espera até a versão nova responder.
  A atualização para esta versão ainda é aplicada pela versão anterior,
  então pode acontecer uma última vez.

### Segurança

- Go 1.27.3: corrige a vulnerabilidade GO-2026-6809 em `crypto/x509`, que o
  painel alcançava. Recomendado atualizar.

### Interno

- O CI volta a passar por inteiro (testes de navegador acompanham as telas
  atuais).

## [0.5.18] - 2026-10-26

### Novo

- **Domínios dos clientes com Cloudflare**: domínio com a nuvem laranja
  agora é aceito (antes caía em "DNS não aponta para cá"). A tela Domínios
  mostra o caminho de cada pedido: direto ou via Cloudflare. O IP real do
  visitante chega à app (o Hangar só confia no `CF-Connecting-IP` vindo do
  Cloudflare).
- **TXT de posse (opcional)**: com o switch ligado no serviço, um domínio
  novo só recebe certificado se `_hangar.<domínio>` tiver o código que a app
  mostra ao cliente. Domínios que já têm certificado continuam renovando.
- **Limite por hora no painel**: o número de domínios novos por hora é
  ajustado na tela Domínios (1 a 1000), com o uso da hora e aviso perto do
  limite.
- **Endereço dos clientes**: a tela Domínios mostra para onde os clientes
  apontam (`entrada.…`) e avisa se ele estiver com a nuvem laranja.
- **Kit do desenvolvedor**: chamada assinada, código do TXT em
  Python/Node/PHP, texto pronto para o cliente e um teste que confere DNS,
  TXT e a resposta da app sem gravar nem emitir nada.

### Corrigido

- O CI voltou a passar no lint (dois avisos do gosec).

## [0.5.17] - 2026-10-26

### Corrigido

- **Apps de Git com usuário sem privilégio não subiam**: o código baixado do
  Git chegava à imagem legível só pelo root, e um app que roda como usuário
  comum (`USER 10001`, o recomendado) não conseguia ler os próprios arquivos.
  Agora o código mantém as permissões normais do Git.
- O coringa do domínio base em escala aparecia como "por subdomínio, sob
  demanda"; agora mostra o certificado único obtido pelo DNS.

## [0.5.16] - 2026-10-26

### Novo

- **Conectar serviços pelo que eles oferecem**: arrastar de um card a outro
  no canvas, ou **Conectar a…** na aba Variáveis, abre uma janela com o que
  o outro serviço oferece e, para cada valor, a variável do seu app que o
  recebe. O nome sugerido é um que o app já usa ou que o `.env.example` dele
  documenta (`PGHOST`, `POSTGRES_PASSWORD`, `DB_NAME`…), e dá para trocar.
  A variável conectada aparece como "de db · DATABASE_URL", com
  **Desconectar**.
- **Serviço feito por imagem ou Git também oferece valores**: marque a
  variável com o ícone de cabo e os outros serviços podem se conectar a ela.
- **Projetos fixados**: passe o mouse num projeto do menu e fixe no topo. É
  de cada pessoa.
- **Painel no celular**: menu lateral num painel que abre pelo ☰, botões
  em largura total e na proporção do texto, nada passando da tela, canvas
  ajustado à tela ao abrir.

### Corrigido

- Conectar a um serviço que não oferece nada salvava uma variável vazia;
  agora o painel avisa e não salva.
- Trocar a senha do banco deixava os apps com a senha antiga sem aviso;
  agora o que ele oferece se atualiza e os apps mostram "alterações para
  aplicar".
- Uma referência em cadeia (app → api → banco) chegava ao app como texto;
  agora é resolvida, e um ciclo vira aviso.
- Apagar um serviço usado por outros avisa quem vai quebrar.
- A bolinha de status dos logs sumia quando o streaming começava.
- A tela de login não mostra mais o aviso sobre recuperar a senha.

## [0.5.15] - 2026-10-20

### Novo

- **Tema vermelho e logo novo**: o painel ganha o vermelho do logo novo, a
  porta de um hangar, no login, na barra de cima, no ícone da aba e no kit
  de recuperação impresso. A cor padrão da Marca e das páginas de erro dos
  sites acompanha; o roxo antigo continua entre as cores para escolher.

### Mudou

- **Projetos sobem no menu**: logo abaixo da Visão geral, antes de Acesso,
  Operação e Sistema.

## [0.5.14] - 2026-10-20

### Novo

- **Níveis de segurança**: em **Minha conta → Nível de segurança** (só o
  dono), você escolhe quando o painel pede a senha de novo depois do login.
  - **Básico**: só no login. Ações perigosas continuam com a confirmação de
    sempre (digitar o nome). Fica logado até 12 h, mesmo parado.
  - **Médio** (padrão): só no que não tem volta ou mostra segredos (apagar
    projeto, serviço ou disco; restaurar ou baixar backup; ver senhas e
    tokens; terminal; equipe). Vale por 30 min; sai depois de 2 h parado.
  - **Avançado**: toda ação sensível pede, por 5 min; sai depois de 30 min
    parado (era o comportamento de antes).

  Mudar o nível sempre pede a senha e vira alerta de segurança.
- **Copiar o nome na confirmação**: ao apagar projeto ou serviço e ao
  sobrescrever numa restauração, o nome aparece com um botão de copiar; é só
  colar no campo.
- **Novo projeto com um campo só**: você digita o nome e o identificador
  (`noticias-portal`) sai dele, com a prévia na hora.

### Corrigido

- **Botões aceitavam vários cliques**: verificar vulnerabilidades, deploy,
  iniciar/parar/reiniciar, backup agora, baixar e restaurar backup e
  atualizar o Hangar agora fazem uma coisa por clique. O botão mostra que
  está trabalhando e libera quando termina; a página se atualiza sozinha só
  no fim.
- **Atualizar Hangar**: não oferece mais "nova versão" a um painel mais novo
  que a última publicada, não fica preso em "Aplicando a atualização…" onde
  nada aplica a atualização e não diz mais "já atualizado" a um segundo
  clique.
- **Avisos atrás do painel lateral**: as notificações ficam sempre na frente,
  nítidas.
- **Card do canvas "se mexendo"**: ao abrir um serviço, o card só fica
  destacado, sem piscar.
- **Vulnerabilidades**: achados antigos ganham a classificação certa logo
  depois de atualizar, e a coluna de ação não quebra mais o texto.
- O ícone da **Equipe** faltava na busca (⌘K).
- As escolhas de uma opção usam o quadradinho com check, como o resto do
  painel.

## [0.5.13] - 2026-10-19

### Novo

- **Atualizações e vulnerabilidades pelo que fazer**: a página separa as
  pendências em "Resolve com deploy", "Trocar a versão", "No seu código" e
  "Aguardando correção". O painel examina a imagem nova no registro antes de
  dizer que um deploy resolve. Cada pacote vira uma linha ("58 falhas"), e há
  botão só onde o painel resolve: **Fazer deploy**, **Trocar para …** e
  **Atualizar Hangar**. Para bibliotecas da sua app, mostra o comando do seu
  gerenciador (`uv`, `poetry`, `npm`, `go get`…).
- **Trocar a imagem de um serviço**: cartão "Imagem" nas configurações (e o
  botão da página de atualizações). Pede a sua senha e, se a versão nova não
  subir, volta sozinho para a anterior.
- **Discos com uso e limite**: cada disco mostra quanto usa; com limite, uma
  barra ("3,2 GB de 20 GB"), aviso aos 80% e aos 95% e o botão **Aumentar**,
  sem parar o serviço. O limite é opcional e real: o disco não passa do
  tamanho e não lota o servidor. Templates de banco e de armazenamento já vêm
  com um tamanho sugerido.
- **Templates mais completos**: o tempo de desligamento (`stop_grace_period`,
  até 2 min), discos só leitura (`:ro`) e um disco compartilhado entre os
  serviços do mesmo template.

### Corrigido

- **Bancos eram derrubados sem aviso ao parar**: PostgreSQL, Redis e
  qualquer app que troca de usuário não recebiam o sinal de desligar e eram
  encerrados na hora. Agora desligam certinho (o PostgreSQL faz o checkpoint,
  o Redis salva os dados).
- O primeiro boot de um serviço lento (apps Java, bancos importando dados)
  podia ser derrubado depois de 2 min mesmo com o template pedindo mais; o
  Hangar agora espera o que o healthcheck declara (até 15 min).
- Dois painéis no mesmo Docker podiam mexer nos containers um do outro. Cada
  painel agora só toca no que criou; o que já roda é reconhecido na
  atualização.
- "Último acesso" na Equipe dizia "nunca entrou" para quem já tinha saído;
  agora fica guardado na conta.
- O uso de disco por serviço (aba Métricas) aparecia vazio em versões novas do
  Docker.
- **Depois de reiniciar o servidor, o proxy de borda podia não voltar**: outro
  container pegava o endereço fixo dele durante o boot e todos os sites
  ficavam fora. O painel agora libera o endereço antes de subir a borda.
- O instalador passa a instalar o `e2fsprogs` quando falta (usado pelo limite
  de disco).

## [0.5.12] - 2026-10-18

### Novo

- **Catálogo de templates que se atualiza sozinho**: o painel passa a baixar
  uma vez por dia o catálogo assinado de
  [hangar-templates](https://github.com/JuniorCarlini/hangar-templates). Um
  robô sobe cada template para a imagem estável mais nova que a regra dele
  permite (bancos de dados não pulam de versão major), confere tudo com as
  regras do painel e assina. Templates novos chegam sem precisar de versão
  nova do Hangar.
- **Filezam no catálogo**: gestor de arquivos na web, o primeiro template de
  terceiros.

### Melhorado

- **Proxy de borda atualizado**: Caddy 2.11.7 com as correções mais novas;
  a verificação de vulnerabilidades da borda vai de 6 avisos para nenhum.
  Nesta atualização a borda é recriada uma vez (alguns segundos fora do ar).
- Dependências atualizadas (bibliotecas Go, ferramentas de verificação) e
  RustFS 1.0.3 no template.

## [0.5.11] - 2026-10-18

### Melhorado

- **Vulnerabilidades em todas as linguagens**: o painel passa a analisar a
  imagem de cada serviço com o OSV-SCALIBR (do Google, a mesma equipe do
  OSV.dev). Além de Python, npm e PHP, agora entram Go (inclusive direto do
  binário), Java/Kotlin, Rust, Ruby, .NET, yarn, pnpm, bun, Dart, Elixir e
  outras, e os pacotes de Red Hat, Rocky, Arch e mais sistemas.
- **A borda (Caddy) também é verificada**: as bibliotecas Go do proxy que
  protege todos os sites passam a gerar aviso quando tiverem falha.
- A análise lê a imagem, não o container em execução; continua saindo do
  servidor só o nome e a versão de cada pacote. Imagens acima de 3 GB, ou sem
  espaço em disco suficiente, usam o método anterior.

## [0.5.10] - 2026-10-18

### Melhorado

- **O painel não depende mais de SSH para se recuperar**:
  - As permissões da configuração, da chave mestra e da pasta de dados são
    conferidas e corrigidas a cada início do painel.
  - Se o Docker ou o proxy de borda (Caddy) não subirem no boot, o painel
    tenta de novo sozinho e confere o Caddy a cada minuto.
  - O Caddy só guarda como configuração de boot uma que ele aceitou; se a
    completa for recusada, ele sobe com a última boa ou com uma mínima que
    serve o painel.
  - O certificado do próprio painel nunca depende do token do DNS.
  - As regras de firewall do painel são reaplicadas a cada 3 minutos.
  - A porta 7702 do painel fica reservada.
- **Atualização mais segura**: antes de parar o painel, ela confere se a
  versão nova consegue ler a configuração e se há espaço em disco; se não,
  nem começa. Na volta automática, espera a versão anterior subir de verdade.
  Cópias antigas do banco são apagadas (ficam as 3 mais novas).
- **Bloqueio por senha errada é temporário**: 15 minutos, dobrando até 24 h.
  Quem digita a senha certa vê até quando a conta está bloqueada, e as
  sessões já abertas continuam valendo.
- **Modal "Adicionar domínio" mais simples**: "Normal", "Coringa limitado"
  (até 50 novos por semana, sem token) e "Coringa ilimitado" (com o token do
  DNS), cada um explicado em uma frase.

### Corrigido

- O modo "Coringa ilimitado" é recusado com uma mensagem clara se o proxy de
  borda não tiver o módulo de DNS, e desfaz o que salvou se o domínio não
  puder ser adicionado.

## [0.5.9] - 2026-10-18

### Novo

- **Como o domínio funciona, escolhido na hora de adicionar**: o modal
  **Adicionar domínio** tem três modos, cada um explicado em linguagem simples:
  - **Normal**: um endereço só, como hoje.
  - **Coringa**: `*.seudominio`, cada subdomínio ganha o próprio certificado
    na primeira visita. Não precisa de token.
  - **Em escala**: um certificado coringa único cobre todos os subdomínios,
    obtido pelo DNS com o token do provedor (Cloudflare). Antes isso exigia
    editar o `hangar.toml` pelo SSH; agora é tudo pelo painel.
- **Token do DNS protegido**: o painel testa o token na Cloudflare antes de
  salvar e recusa se ele não enxergar a zona do domínio (por isso "Em escala"
  só vale para um domínio cujo DNS é seu; para o domínio de um cliente, use
  Normal ou Coringa). O token fica cifrado, nunca é mostrado de volta e só
  um admin, confirmando a senha, troca. Trocar o domínio base pede
  confirmação, porque os links automáticos mudam junto.

### Melhorado

- **Caddy com o módulo de DNS já embutido**: a borda passa a usar a imagem
  `hangar-caddy`, publicada a cada versão e fixada no binário assinado. Ela só
  muda quando o próprio Caddy muda, então atualizar o Hangar não reinicia a
  borda à toa. Na primeira atualização para esta versão a borda é recriada
  uma vez (alguns segundos).

## [0.5.8] - 2026-10-18

### Corrigido

- **Confirmar senha (sudo)**: senha errada numa conta sem 2FA agora diz
  "Senha incorreta" (antes aparecia a mensagem do código de 2FA), o erro
  volta para o próprio formulário em vez de uma página de texto, e páginas
  abertas em outras abas continuam funcionando depois da confirmação (antes
  davam "Requisição recusada").
- **Certificado coringa do domínio base**: um domínio `*.seudominio` cadastrado
  à mão não passa mais na frente do certificado coringa (DNS-01) do domínio
  base, o que fazia cada subdomínio pedir um certificado próprio e gastar o
  limite do Let's Encrypt. Endereços de webhook no domínio base também não
  pedem mais um certificado repetido.

## [0.5.7] - 2026-10-18

### Melhorado

- **Atualizações e vulnerabilidades com páginas**: a lista de pendências
  mostra 25 itens por vez, com paginação no rodapé. Os cartões do topo
  continuam contando tudo.

### Corrigido

- **Falsos "críticos" em imagens Debian e Alpine**: o painel oferecia a uma
  imagem Debian 13 a correção que só existe no Debian 14 (e ao Alpine 3.23 a
  do 3.24). Agora a correção sugerida é a da versão do sistema que roda no
  container; quando ela ainda não existe, o aviso aparece como "Segurança",
  sem correção, em vez de "Crítico". Clique em **Verificar agora** depois de
  atualizar para refazer a lista.
- **Prévia do compose escondida**: ao clicar em **Analisar**, a janela agora
  rola até a prévia, que ficava abaixo do botão e parecia não ter aparecido.
- **Convite repetido para o mesmo e-mail**: um convite novo substitui o que
  estava aberto para o mesmo endereço, e criar a conta encerra os outros
  links dela. Convites antigos que sobraram podem ser cancelados em
  **Equipe**.

## [0.5.6] - 2026-10-18

### Corrigido

- **Redis reiniciando sem parar**: a imagem `redis:8` passou a trocar de
  usuário com `setpriv`, que precisa de uma permissão a mais (`SETPCAP`). Os
  templates Redis (cache e filas) agora dão essa permissão, e os Redis já
  criados são corrigidos na atualização: basta clicar em **Deploy** no
  serviço. O Redis continua rodando como usuário comum e sem nenhuma
  permissão especial depois de iniciar.

## [0.5.5] - 2026-10-18

### Melhorado

- **Painel mais rápido pela internet**: as páginas do painel agora vão
  comprimidas (a do canvas cai de ~165 KB para ~20 KB), e abrir um serviço
  no canvas baixa só o painel lateral dele (12 KB em vez de 174 KB). O
  cartão clicado pisca enquanto o painel chega.

### Corrigido

- No **Terminal**, o botão Reconectar ficou da mesma altura do seletor
  bash/sh, e o botão dos comandos se chama "Novo comando".

## [0.5.4] - 2026-10-18

### Corrigido

- Logo depois de ligar o **Público**, abrir o link mostrava um erro do
  navegador enquanto o certificado ainda não tinha saído. Agora o botão
  de abrir leva à página "Ativando a conexão segura", que entra sozinha no
  site quando o certificado fica pronto, e o selo muda para "HTTPS ativo"
  sem precisar recarregar.

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

[Não lançado]: https://github.com/JuniorCarlini/hangar/compare/v0.5.22...HEAD
[0.5.22]: https://github.com/JuniorCarlini/hangar/compare/v0.5.21...v0.5.22
[0.5.21]: https://github.com/JuniorCarlini/hangar/compare/v0.5.20...v0.5.21
[0.5.20]: https://github.com/JuniorCarlini/hangar/compare/v0.5.19...v0.5.20
[0.5.19]: https://github.com/JuniorCarlini/hangar/compare/v0.5.18...v0.5.19
[0.5.18]: https://github.com/JuniorCarlini/hangar/compare/v0.5.17...v0.5.18
[0.5.17]: https://github.com/JuniorCarlini/hangar/compare/v0.5.16...v0.5.17
[0.5.16]: https://github.com/JuniorCarlini/hangar/compare/v0.5.15...v0.5.16
[0.5.15]: https://github.com/JuniorCarlini/hangar/compare/v0.5.14...v0.5.15
[0.5.14]: https://github.com/JuniorCarlini/hangar/compare/v0.5.13...v0.5.14
[0.5.13]: https://github.com/JuniorCarlini/hangar/compare/v0.5.12...v0.5.13
[0.5.12]: https://github.com/JuniorCarlini/hangar/compare/v0.5.11...v0.5.12
[0.5.11]: https://github.com/JuniorCarlini/hangar/compare/v0.5.10...v0.5.11
[0.5.10]: https://github.com/JuniorCarlini/hangar/compare/v0.5.9...v0.5.10
[0.5.9]: https://github.com/JuniorCarlini/hangar/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/JuniorCarlini/hangar/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/JuniorCarlini/hangar/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/JuniorCarlini/hangar/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/JuniorCarlini/hangar/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/JuniorCarlini/hangar/compare/v0.5.3...v0.5.4
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
