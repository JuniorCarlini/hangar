# ADR 0006 — Modelo de containers igual ao do Easypanel

- Status: Aceito
- Data: 2026-10-15

## Contexto

O operador já usa o Easypanel e considera o modelo de containers dele ideal:
projetos e serviços, nomes `<projeto>_<serviço>`, aba para expor portas,
serviços que se enxergam pelo nome. O problema do Easypanel está só no proxy
(domínios dinâmicos), não na forma de gerenciar containers.

Necessidades reais citadas: expor a porta de um banco para fazer backup local
ou acessar de fora; às vezes um serviço precisa falar com outro projeto.

## Decisão

Reproduzir o modelo do Easypanel na interface e no comportamento:

- Nomes `<projeto>_<serviço>`.
- Aba "Portas" para publicar qualquer porta de qualquer serviço, sem expiração
  obrigatória.
- Projetos podem ser conectados com um clique; um modo opcional de rede
  compartilhada deixa tudo igual ao Easypanel.

E acrescentar proteções **que não atrapalham o fluxo**:

- Opções de acesso por IP e "só localhost", aplicadas no `DOCKER-USER` (o
  Docker passa por cima do UFW).
- Aviso, sem bloqueio, ao expor banco para qualquer IP.
- Tela única de portas abertas + audit log.
- Botão "Baixar backup", para não precisar expor porta só para isso.

## Consequências

- A migração do Easypanel é direta (mesmos nomes, mesmas URLs internas).
- A segurança extra é opcional e explícita, não uma trava.
- Rede por projeto continua sendo o padrão, para que um app comprometido não
  alcance os bancos de todos os outros projetos sem você ter conectado.
