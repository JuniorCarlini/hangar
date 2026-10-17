# ADR 0004 — Docker Engine direto, sem Swarm

- Status: Aceito
- Data: 2026-10-15

## Contexto

Easypanel e Dokploy usam Docker Swarm. Swarm adiciona camada de overlay,
service discovery próprio e comportamentos menos previsíveis (ex.: routing
mesh publicando portas em todos os nós), útil só com vários nós.

## Decisão

Usar a API do Docker Engine diretamente (containers, redes bridge, volumes).
O Hangar implementa o que precisa de orquestração: deploy blue/green,
healthcheck, reconciliação.

## Consequências

- Comportamento simples e previsível; isolamento por redes bridge internas.
- Zero-downtime implementado por nós (ver [07](../07-deploy-e-builds.md)).
- Multi-servidor, quando vier, será via agente por servidor, não via Swarm.
