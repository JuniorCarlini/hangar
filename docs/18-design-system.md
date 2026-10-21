# 18 — Design system: "Pista"

> **A lógica do Railway, a forma do Render, os componentes do Tucano.**
>
> - **Railway** → *como* a interface funciona: o projeto é um **canvas**,
>   cada serviço é um cartão, as conexões aparecem como linhas, e o serviço
>   abre num **painel lateral** sem sair do canvas.
> - **Render** → *como* ela parece: **quadrada**, limpa, plana, borda de 1 px
>   em vez de sombra, tipografia firme, tabelas densas e legíveis.
> - **Tucano** (biblioteca própria) → *com o que* ela é feita: os componentes
>   interativos (select, modal, drawer, toast, tabs, slider, datepicker…),
>   **com o visual do Tucano trocado pelo nosso** via tokens.

Nome do sistema: **Pista** (o hangar abriga, a pista é por onde tudo sai).

---

## 1. Princípios

1. **Quadrado e calmo.** Cantos de 4 px, nada de pílulas, nada de gradiente.
   A cor aparece só onde significa algo (estado, ação principal, perigo).
2. **Borda, não sombra.** Profundidade com borda de 1 px e um degrau de fundo.
   Sombra só no que flutua (modal, menu, toast).
3. **Denso, mas respirando.** Painel de operação: muita informação por tela,
   grade de 4 px, alinhamento rigoroso.
4. **O estado é sempre visível.** Todo serviço, deploy, porta e backup tem
   indicador de estado legível sem ler texto (cor + forma + rótulo).
5. **Perigo tem cara de perigo.** Ações destrutivas vivem na "Zona de perigo",
   em vermelho, com confirmação. Nunca ao lado de um botão comum.
6. **Teclado primeiro.** `Ctrl/⌘ + K` abre tudo; atalhos em todas as telas.
7. **Tema escuro, claro ou do sistema**, escolhido por usuário ([22](22-idiomas-e-temas.md)). Os dois com contraste AA.

---

## 2. Tokens

Todos os valores vivem em variáveis CSS. **Nenhum componente usa cor ou
medida fixa.**

### 2.1 Cor: neutros

Escala neutra levemente fria (como o Render), base para tudo:

| Token | Escuro | Claro | Uso |
|---|---|---|---|
| `--p-bg` | `#0B0D10` | `#FFFFFF` | Fundo da aplicação |
| `--p-bg-canvas` | `#0E1014` | `#F7F8FA` | Fundo do canvas (com grade de pontos) |
| `--p-surface` | `#13161B` | `#FFFFFF` | Cartões, painéis, tabelas |
| `--p-surface-2` | `#1A1E24` | `#F2F4F7` | Cabeçalho de tabela, hover, campo |
| `--p-border` | `#262B33` | `#E3E6EB` | Borda padrão (1 px) |
| `--p-border-strong` | `#353B45` | `#C9CED6` | Borda de foco/seleção neutra |
| `--p-fg` | `#E8EAED` | `#0F1216` | Texto principal |
| `--p-fg-muted` | `#9AA2AE` | `#5B6472` | Texto secundário |
| `--p-fg-subtle` | `#6B7380` | `#8A93A0` | Rótulos, placeholders |

### 2.2 Cor: destaque e estados

| Token | Escuro | Claro | Uso |
|---|---|---|---|
| `--p-accent` | `#D93235` | `#D93235` | Ação principal, seleção, link, foco |
| `--p-accent-hover` | `#C62A2D` | `#B8262A` | |
| `--p-accent-soft` | `#E5383B24` | `#E5383B14` | Fundo de item selecionado |
| `--p-success` | `#3DD68C` | `#11845B` | Rodando, saudável, backup ok |
| `--p-warning` | `#F5B83D` | `#A86400` | Degradado, reiniciando, atenção |
| `--p-danger` | `#FF6369` | `#D1242F` | Parado, falhou, perigo (texto) |
| `--p-danger-fill` | `#E5484D` | `#D1242F` | Botão destrutivo (preenchimento) |
| `--p-info` | `#4CB3FF` | `#0969DA` | Em andamento (build, deploy) |
| `--p-*-soft` | cor + `1F` de alfa | cor + `14` | Fundo de etiqueta/alerta do tom |

> O destaque (`--p-accent`) é configurável. O padrão é o vermelho do logo (a porta do hangar); trocar é
> mudar uma variável.

### 2.3 Tipografia

| Token | Valor |
|---|---|
| `--p-font` | **Space Grotesk**, system-ui, sans-serif (SIL OFL, embutida no binário, pesos 300–700) |
| `--p-font-mono` | ui-monospace (a do sistema), monospace |

| Estilo | Tamanho / altura / peso | Uso |
|---|---|---|
| `display` | 24 / 32 / 600 | Título de página |
| `title` | 16 / 24 / 600 | Título de painel, nome do serviço |
| `body` | 14 / 20 / 400 | Texto padrão |
| `body-strong` | 14 / 20 / 500 | Valores, links |
| `small` | 13 / 18 / 400 | Tabelas densas, metadados |
| `caption` | 12 / 16 / 500, `letter-spacing: .02em` | Rótulos, cabeçalho de tabela (MAIÚSCULAS opcionais) |
| `mono` | 13 / 20 / 400 | Logs, variáveis, IDs, commits, comandos |

Números em tabelas e métricas: `font-variant-numeric: tabular-nums`.

### 2.4 Forma, espaço e profundidade

| Token | Valor | Observação |
|---|---|---|
| `--p-radius-xs` | `2px` | Etiquetas, checkbox |
| `--p-radius` | `4px` | **Padrão**: botões, campos, cartões |
| `--p-radius-lg` | `6px` | Modal, drawer, menus. Teto: nada passa disso |
| `--p-border-width` | `1px` | |
| `--p-space-*` | `4, 8, 12, 16, 20, 24, 32, 40, 48` | Grade de 4 px |
| `--p-control-h` | `32px` (`28px` compacto, `40px` toque) | Botões e campos |
| `--p-row-h` | `40px` | Linha de tabela |
| `--p-shadow-pop` | `0 8px 24px -4px rgb(0 0 0 / .35)` | Só modal, menu, toast |
| `--p-ring` | `0 0 0 2px var(--p-bg), 0 0 0 4px var(--p-accent)` | Foco visível |
| `--p-duration` | `120ms` | |
| `--p-ease` | `cubic-bezier(.2, 0, 0, 1)` | |

`prefers-reduced-motion` zera as transições.

### 2.5 Alinhamento de ícones

Ícone, ponto de estado ou botão ao lado de um bloco de texto fica
**centralizado na vertical em relação ao bloco inteiro** (`align-items:
center`), mesmo quando o texto quebra em duas ou mais linhas. Nunca grudado
no topo da primeira linha. Vale para avisos, itens de lista, linha do tempo,
cartões e toasts.

**Sem barras coloridas na lateral** de itens, cartões ou avisos. Seleção e
estado se mostram por fundo, borda de 1 px em volta, ponto de estado e texto.

### 2.6 Ícones

**Lucide** (licença ISC), sprite SVG embutido, 16 px, traço 1.5. Cor herda
do texto. Nada de ícone colorido, exceto o indicador de estado.

---

## 3. Layout da aplicação

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ✈ Hangar  ▸ minhaloja ▸ web          [⌘K Buscar ou executar…]   🔔  🔒  JC ▾ │ 48px
├────────┬─────────────────────────────────────────────────┬───────────────────┤
│ PROJE- │ ┌ minhaloja ─────────────── [Canvas|Lista] [+ Novo]                  │
│ TOS    │ │ · · · · · · · · · · · · · · · · · · · · · · ·  │ PAINEL DO SERVIÇO │
│ ▣ theme│ │ ┏━━━━━━━━━━━━━━┓      ┏━━━━━━━━━━━━━━┓        │ (abre ao clicar   │
│   shop │ │ ┃● web      ×3 ┃──┬──▶┃● postgres    ┃        │  num cartão)      │
│ ▢ site │ │ ┃ a1b2c3 · 2h  ┃  │   ┃ 18 · 2,1 GB  ┃        │                   │
│        │ │ ┃ 🌐 + 214 dom.┃  │   ┗━━━━━━━━━━━━━━┛        │ 560px, redimen-   │
│ ────── │ │ ┗━━━━━━━━━━━━━━┛  │   ┏━━━━━━━━━━━━━━┓        │ sionável          │
│ SERVI- │ │ ┏━━━━━━━━━━━━━━┓  └──▶┃● redis-filas ┃        │                   │
│ DOR    │ │ ┃● worker   ×2 ┃──────▶┗━━━━━━━━━━━━━━┛        │                   │
│ Visão  │ │ ┗━━━━━━━━━━━━━━┛                               │                   │
│ Domín. │ │ · · · · · · · · · · · · · · · · · · · · · · ·  │                   │
│ Portas │ └────────────────────────────────────────────────┘                   │
│ Backup │                                                  │                   │
│ Atual. │                                                  │                   │
│ ⚙ Adm. │                                                  │                   │
└────────┴─────────────────────────────────────────────────┴───────────────────┘
  220px              área principal (fluida)                     drawer
```

- **Barra superior (48 px):** logo, trilha (breadcrumb), busca/comandos
  (`⌘K`), alertas, botão **Trancar**, conta.
- **Barra lateral (220 px, recolhível para 56 px):** projetos no topo; itens do
  servidor embaixo. Item ativo: fundo `--p-surface-2` + borda de 1 px
  `--p-border` em volta + texto `--p-fg` peso 500. Quadrado, sem pílula e
  **sem barra colorida na lateral** (fica com cara de template genérico).
- **Área principal:** canvas do projeto (padrão) **ou** lista (alternável,
  para quem prefere tabela; a escolha fica lembrada).
- **Drawer do serviço (direita):** abre sem sair do canvas, como no Railway.
  O URL muda (`/p/minhaloja/s/web/deploys`), então o link funciona e o botão
  voltar do navegador fecha o drawer. Em tela pequena, vira página inteira.

---

## 4. O canvas (lógica do Railway, forma do Render)

### Cartão de serviço

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓   240 × 88 px, raio 4 px, borda 1 px
┃ ▭ web               ×3  ┃   ▭ ícone do tipo: App, Postgres, Redis, etc.
┃   App · main · a1b2c3   ┃   ×3 réplicas (só se > 1)
┃   ■ Ao vivo · há 2 h    ┃   ■ quadradinho de estado + texto na cor do estado
┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Sem faixa colorida na lateral: o estado aparece no quadradinho e no texto da
última linha, para o canvas não virar um arco-íris.

| Estado | Quadradinho e texto | Rótulo |
|---|---|---|
| Rodando | `--p-success` | — |
| Em deploy/build | `--p-info`, pulsando | "Deploy em andamento" |
| Degradado / reiniciando | `--p-warning` | "3 reinícios" |
| Parado / falhou | `--p-danger` | "Falhou: healthcheck" |
| Alterações pendentes | contorno tracejado `--p-accent` | "Aplicar alterações" |

- **Hover:** borda `--p-border-strong`. **Selecionado:** borda `--p-accent` +
  fundo `--p-accent-soft`.
- **Clique direito** (ContextMenu do Tucano): Deploy, Reiniciar, Logs,
  Copiar URL interna, Abrir terminal 🔒.

### Conexões

- Linhas **ortogonais** (cotovelos em 90°, cantos de 4 px), não curvas: é o
  "quadrado" do Render aplicado à lógica do Railway.
- Desenhadas a partir das **referências reais** (`${{postgres.DATABASE_URL}}`
  no web → linha web → postgres). Não é desenho manual: o canvas mostra a
  verdade.
- Conexão com **outro projeto**: linha tracejada até um cartão "fantasma"
  com o nome do projeto.
- Domínios públicos: um "pino" 🌐 no topo do cartão, ligado à borda do canvas
  (mostra o que está exposto à internet).
- **Porta exposta**: etiqueta `⚠ 5433 aberta` no cartão. Uma porta aberta nunca
  fica escondida.

### Interação

- Arrastar cartões (posição salva por projeto); `Organizar` alinha
  automaticamente em grade de 8 px.
- Zoom e pan (roda/pinça, `+`/`-`, `0` centraliza).
- **Teclado:** `Tab` percorre os cartões, setas movem a seleção para o
  vizinho mais próximo, `Enter` abre o drawer, `D` deploy, `L` logs.
- Leitor de tela: o canvas tem uma **lista equivalente** (`role="list"`) com
  estado e conexões em texto.
- Implementação: SVG próprio para as linhas + cartões em HTML posicionados
  (sem biblioteca de grafo; são dezenas de nós, não milhares).

---

## 5. Drawer do serviço

```
┌──────────────────────────────────────────────────────────┐
│ ● web                                  [Deploy ▾]  [✕]   │ título + ação principal
│ App · Git acme/minhaloja@main · ×3                       │
├──────────────────────────────────────────────────────────┤
│ Visão  Variáveis  Rede  Logs  Configurações  (Backups)   │ Tabs (Tucano), sublinhado 2px
├──────────────────────────────────────────────────────────┤
│                                                          │
│  (conteúdo da aba)                                       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Abas: **Visão** (métricas + histórico de deploys) · **Variáveis** (+ "Oferece
aos outros") · **Rede** (domínios, com o curinga e os domínios dos lojistas, +
portas) · **Logs** · **Configurações** (Git, deploy, discos, recursos, **Zona
de perigo** no fim, separada por borda vermelha) · **Backups** só em bancos.
Links antigos (`?tab=deploys`, `metrics`, `connection`, `domains`, `ports`,
`terminal`) caem na aba onde o conteúdo mora agora.

Listas ficam na aba; **adicionar abre um modal** do Tucano (`tuc-modal`, por
cima da página toda): nova variável, adicionar domínio, abrir porta,
adicionar disco. O **Terminal** é um botão no topo do drawer, ao lado de
Fazer deploy / Reiniciar / Parar: abre um modal quase em tela cheia com a
página `/p/{p}/s/{s}/terminal` num frame (a única que o painel pode
enquadrar e a única com estilo inline, por causa do xterm.js): escolha de
shell (bash, sh ou comando personalizado) e comandos salvos do serviço.

### Padrões dentro do drawer

**Linha do tempo de deploys** (Timeline do Tucano, quadrada):

```
●  #48  Ao vivo        a1b2c3  fix frete            há 2 h · Junior     [Log]
│
○  #47  Substituído    9f8e7d  checkout            ontem · webhook     [↩ Voltar]
│
✕  #46  Falhou         —       healthcheck timeout ontem · webhook     [Log]
```

**Editor de variáveis** (tabela chave/valor em mono):

```
NOME                     VALOR
DJANGO_SETTINGS_MODULE   config.settings.production
DATABASE_URL             🔗 postgres.DATABASE_URL
SECRET_KEY               ●●●●●●●●●●●●  🔐            [Revelar 🔒]
[+ Variável]  [Editar como .env]          ──  2 alterações · [Aplicar e fazer deploy]
```

**Logs** (mono 13 px, fundo `--p-bg`, linha clicável copia, nível colorido
só no rótulo):

```
18:42:01  INFO   POST /checkout/confirmar 200 182ms
18:42:03  WARN   frete: timeout correios (2s), usando tabela
[● Ao vivo]  [stdout ✓] [stderr ✓]  [Filtrar…]           [⏸] [⬇]
```

**Métricas:** gráficos uPlot com linhas de 1.5 px, sem preenchimento
pesado, grade discreta `--p-border`, cursor sincronizado entre os gráficos
(CPU, RAM, rede).

---

## 6. Componentes

### 6.1 Vindos do Tucano (comportamento dele, visual nosso)

| Componente Tucano | Onde usamos no Hangar |
|---|---|
| `.tuc-btn`, `.tuc-btn-group` | Todos os botões; grupo "Canvas \| Lista" |
| `Select` | Imagem/template, servidor, filtros, papéis |
| `Modal` | Confirmações, **reautenticação (sudo)**, apagar com digitação do nome |
| `Drawer` | **Painel do serviço** (borda direita), menu mobile |
| `Tabs` | Abas do drawer e das páginas |
| `Toast` | "Deploy iniciado", "Variável salva", erros (gatilhos HTMX) |
| `Tooltip` | Ícones, valores truncados, explicação de campos |
| `Dropdown` | Menu "Deploy ▾", menu da conta |
| `ContextMenu` | Clique direito no cartão do canvas |
| `Table` + `Pagination` | Auditoria, domínios dinâmicos, portas, atualizações |
| `Timeline` | Deploys, histórico de backups, eventos do serviço |
| `Slider` | **Recursos**: CPU e memória do serviço |
| `DatePicker` (data + hora) | **Restaurar até o minuto** (WAL), filtros de auditoria/logs |
| `Mask` (campo sensível) | Entrada de segredos, token do Git, código 2FA |
| `Upload` | Kit de recuperação na restauração, importar `.env` |
| `Accordion` | Configurações avançadas, ajuda contextual |
| `.tuc-switch`, `.tuc-check`, `.tuc-radio` | Opções (aceitar domínios dinâmicos, acesso da porta…) |
| `.tuc-alert`, `.tuc-badge` | Avisos e etiquetas de estado |
| `.tuc-spinner`, `.tuc-skeleton` | Carregamento |
| `.tuc-label`, `.tuc-hint`, `.tuc-error` | Formulários |

**Não usamos** o `Editor` do Tucano: ele grava `style` em atributo, o que a
CSP estrita do painel ([17](17-telas-fluxos-e-seguranca.md)) bloqueia, e o
painel não precisa de texto rico. Todo o resto é compatível com a CSP:
o Tucano não tem dependências e só usa CSSOM, que a CSP permite.

Versão fixada (`tucano@0.38.0` hoje), arquivos `dist/` **embutidos no
binário** (nada de CDN, por causa da CSP `'self'`). Atualizar o Tucano é
um PR com changelog lido, como qualquer dependência.

### 6.2 Construídos no Hangar

| Componente | Descrição |
|---|---|
| `Canvas` | Cartões + linhas SVG + pan/zoom + teclado (seção 4) |
| `ServiceCard` | Cartão do canvas |
| `StatusDot` | Indicador de estado: quadradinho de 7–8 px, raio 1–2 px, + texto (`aria-label`) |
| `CommandPalette` (`⌘K`) | Busca projetos/serviços/ações; ações 🔒 mostram o cadeado e pedem sudo |
| `LogViewer` | Stream SSE, virtualizado (milhares de linhas sem travar), escape seguro |
| `MetricChart` | Wrapper do uPlot com os tokens |
| `Terminal` | Wrapper do xterm.js com os tokens, cabeçalho "sessão gravada · tempo restante" |
| `EnvEditor` | Tabela chave/valor + modo `.env` + referências 🔗 |
| `CopyField` | Valor em mono + botão copiar (URL interna, comando de túnel) |
| `KeyValueList` | Metadados do serviço |
| `DangerZone` | Bloco com borda `--p-danger`, ações destrutivas |
| `SudoGate` | Modal de reautenticação que retoma a ação após o 2FA |
| `EmptyState` | Ícone + uma frase + uma ação ("Nenhum serviço. [+ Criar o primeiro]") |
| `SecurityBanner` | Faixa no topo para avisos que não somem (porta aberta para qualquer IP, backup atrasado) |

### 6.3 Botões

| Variante | Visual | Uso |
|---|---|---|
| Primário | Fundo `--p-accent`, texto branco | Uma por tela: Deploy, Criar, Salvar |
| Secundário | Fundo `--p-surface`, borda `--p-border` | Ações comuns |
| Fantasma | Sem fundo/borda; hover `--p-surface-2` | Ações em linha, ícones |
| Perigo | Fundo `--p-danger-fill`, texto branco | **Só na Zona de perigo e em modais de confirmação** |

Todos com raio 4 px, altura 32 px, peso 500, ícone 16 px à esquerda.
Ações 🔒 mostram um cadeado pequeno depois do rótulo.

---

## 7. Ligação com o Tucano (tema)

O Tucano lê variáveis `--tuc-*`. Mapeamos uma vez, e todo componente dele
nasce com a cara do Pista:

```css
:root {
  /* Pista → Tucano */
  --tuc-font:           var(--p-font);
  --tuc-bg:             var(--p-surface);
  --tuc-fg:             var(--p-fg);
  --tuc-muted:          var(--p-fg-muted);
  --tuc-subtle:         var(--p-fg-subtle);
  --tuc-border:         var(--p-border);
  --tuc-hover:          var(--p-surface-2);
  --tuc-elevated:       var(--p-surface);
  --tuc-accent:         var(--p-accent);
  --tuc-accent-hover:   var(--p-accent-hover);
  --tuc-accent-soft:    var(--p-accent-soft);
  --tuc-success:        var(--p-success);
  --tuc-warning:        var(--p-warning);
  --tuc-danger:         var(--p-danger);
  --tuc-danger-fill:    var(--p-danger-fill);
  --tuc-info:           var(--p-info);

  --tuc-radius:         var(--p-radius-lg);  /* painéis flutuantes: 6px */
  --tuc-radius-md:      var(--p-radius);     /* controles: 4px */
  --tuc-radius-sm:      var(--p-radius);
  --tuc-radius-xs:      var(--p-radius-xs);
  --tuc-border-width:   var(--p-border-width);
  --tuc-control-height: var(--p-control-h);
  --tuc-shadow:         var(--p-shadow-pop);
  --tuc-ring:           var(--p-ring);
  --tuc-duration:       var(--p-duration);
  --tuc-ease:           var(--p-ease);
}
```

O tema escuro do Pista é o padrão, aplicado com a classe `.dark` no `<html>`
(a mesma convenção do Tucano). A preferência do usuário (escuro, claro ou
sistema) fica salva na conta.

---

## 8. Tom de escrita

- Português, curto, direto. Verbo no botão: "Fazer deploy", "Expor porta",
  "Restaurar".
- Erros dizem **o que aconteceu e o que fazer**: "Healthcheck não respondeu em
  120 s. Veja o log do deploy #46."
- Avisos de segurança explicam o risco em uma frase, sem drama.
- Nada de jargão quando existe palavra comum; termos técnicos (deploy, WAL,
  healthcheck) ficam como são, com tooltip na primeira vez.

---

## 9. Acessibilidade

- Contraste AA em texto (4.5:1) e em componentes (3:1), nos dois temas.
- Estado nunca só por cor: quadradinho + texto do estado.
- Foco sempre visível (`--p-ring`), ordem de tabulação lógica, `Esc` fecha
  drawer/modal.
- Canvas com lista equivalente para leitor de tela.
- Alvos de toque de 40 px no modo compacto/mobile.

---

## 10. Onde fica no código

```
internal/web/assets/
├── css/
│   ├── tokens.css        # --p-* (escuro e claro) + mapeamento --tuc-*
│   ├── base.css          # reset, tipografia, layout
│   └── components/       # canvas, card, log-viewer, command-palette…
├── vendor/
│   ├── tucano/           # dist/ fixado (tucano.min.css / .min.js)
│   ├── htmx/  uplot/  xterm/
├── fonts/                # Space Grotesk (woff2) + OFL.txt
└── icons/lucide.svg      # sprite
```

Protótipo visual para aprovação: https://claude.ai/artifact/13J7FdjS9RqfDLeMFEwQev

Uma página `/_pista` (só em build de desenvolvimento) mostra todos os tokens
e componentes. É o catálogo vivo, e serve de base para testes visuais.
