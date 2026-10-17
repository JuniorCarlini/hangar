# ADR 0005 — Interface renderizada no servidor

- Status: Aceito (parte de interatividade atualizada pelo [ADR 0009](0009-design-system-pista.md): Tucano no lugar do Alpine.js)
- Data: 2026-10-15

## Contexto

Queremos leveza, CSP estrita e nenhum Node em produção.

## Decisão

HTML gerado no servidor com `templ`, interatividade com HTMX e Alpine.js
(build CSP), atualizações ao vivo por SSE, gráficos com uPlot, terminal com
xterm.js. Tudo vendorizado e embutido no binário. Tailwind v4 só em build.

## Consequências

- Sem SPA, sem API duplicada para o front, sem CDN externo.
- CSP `default-src 'self'` sem `unsafe-inline`/`unsafe-eval`.
- Telas muito dinâmicas (terminal, gráficos) usam JS pontual.
