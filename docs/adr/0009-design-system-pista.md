# ADR 0009 — Design system "Pista": lógica do Railway, forma do Render, componentes do Tucano

- Status: Aceito
- Data: 2026-10-15

## Contexto

O operador quer a experiência do Railway (projeto como canvas, serviço em
painel lateral) com o visual mais quadrado e limpo do Render. Já existe uma
biblioteca própria, o Tucano (sem dependências, compatível com HTMX, tema por
variáveis CSS), com boa parte dos componentes interativos necessários.

## Decisão

- Interação no modelo do Railway: canvas com cartões e conexões derivadas das
  referências reais entre serviços; drawer lateral com abas.
- Visual próprio ("Pista"), inspirado no Render: raio de 4 px (máx. 6 px),
  borda de 1 px, sem gradientes, sombra só em elementos flutuantes, tipografia
  Geist, escuro por padrão.
- Componentes interativos do Tucano (versão fixada e embutida), com o tema
  trocado pelo mapeamento `--p-*` → `--tuc-*`. O `Editor` do Tucano não é
  usado, por incompatibilidade com a CSP estrita.
- Alpine.js sai da stack: Tucano + HTMX + JS pontual próprio cobrem a
  interatividade (substitui essa parte do [ADR 0005](0005-interface-server-side.md)).

## Consequências

- Uma dependência a menos (Alpine) e componentes que o próprio autor mantém.
- Melhorias feitas no Tucano para o Hangar beneficiam os outros projetos.
- Canvas, LogViewer, CommandPalette e Terminal são construídos no Hangar.
