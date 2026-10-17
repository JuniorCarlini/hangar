# ADR 0001 — Go como linguagem do painel

- Status: Aceito
- Data: 2026-10-15

## Contexto

O painel precisa ser leve (quase nada de RAM/CPU ocioso), fácil de instalar,
seguro e ficar pronto rápido (urgência). Precisa falar intensamente com a API
do Docker e configurar o proxy.

## Opções

| Opção | RAM ociosa típica | Distribuição | Ecossistema Docker/proxy | Velocidade de desenvolvimento |
|---|---|---|---|---|
| **Go** | ~20–40 MB | 1 binário estático | Nativo (Docker, Caddy, Traefik são Go) | Alta |
| Rust | ~5–15 MB | 1 binário | Bom (bollard) | Média/baixa |
| Node/Bun (TS) | ~80–150 MB | Runtime + node_modules | Bom | Alta |
| PHP/Laravel (Coolify) | centenas de MB + serviços | Vários containers | Médio | Alta |

## Decisão

Go. Melhor equilíbrio entre leveza, segurança de memória, simplicidade de
distribuição e velocidade de entrega. Rust seria um pouco mais leve, mas a
diferença de dezenas de MB não compensa o tempo extra num projeto urgente.

## Consequências

- Um binário (`hangard`) com interface e assets embutidos (`embed`).
- Cross-compile trivial para amd64 e arm64.
- Time precisa seguir os padrões de [12](../12-padroes-de-codigo.md).
