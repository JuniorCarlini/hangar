# ADR 0003 — SQLite como banco do painel

- Status: Aceito
- Data: 2026-10-15

## Contexto

O painel guarda configuração, usuários, auditoria e métricas agregadas de um
servidor. Volume de escrita baixo, um único processo escritor.

## Decisão

SQLite em modo WAL, driver `modernc.org/sqlite` (puro Go, sem CGO), queries
geradas com `sqlc`, migrações com `goose` embutidas.

## Consequências

- Nenhum serviço extra para instalar, monitorar ou proteger.
- Backup consistente com `VACUUM INTO`.
- Se um dia houver vários painéis/escritores (Fase 4), reavaliar (Postgres).
