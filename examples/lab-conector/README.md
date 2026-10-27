# Laboratório do conector

App Django mínima para testar o **conector** do Hangar: ela lê o banco e o
cache com nomes **próprios**, diferentes dos que os templates oferecem, e a
ponte entre um nome e outro é feita no conector.

| A app lê | Ligue no conector a |
|---|---|
| `DB_HOST` | `HOST` do Postgres |
| `DB_PORT` | `PORT` do Postgres |
| `DB_NAME` | `DATABASE` do Postgres |
| `DB_USER` | `USER` do Postgres |
| `DB_PASS` | `PASSWORD` do Postgres |
| `CACHE_URL` | `REDIS_URL` do Redis |

A página mostra quais variáveis chegaram e se o Postgres e o Redis respondem.
Cada visita grava nos dois (uma linha na tabela `visitas` e um contador no
Redis), então "conectado" prova a ligação de ponta a ponta.

## Como usar no Hangar

1. Crie um projeto com um Postgres e um Redis pelos templates.
2. Crie um serviço pelo Git: repositório `https://github.com/JuniorCarlini/hangar`,
   pasta `examples/lab-conector`, porta `8000`, healthcheck `/healthz`.
3. Nas Variáveis do serviço, use o conector para ligar cada nome da tabela.
4. Faça o deploy e abra o link do serviço.

Sem o Hangar: `docker build -t lab-conector:dev .` e rode com as seis
variáveis apontando para um Postgres e um Redis.
