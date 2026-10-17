# Laboratório de domínios dinâmicos

App Django mínima, no formato de um SaaS multi-loja (uma loja por domínio), para testar
os domínios dinâmicos do Hangar **sem tocar em nenhum projeto real**.

- Cada domínio em `LAB_DOMAINS` (separados por vírgula) vira uma loja ativa.
- `/.well-known/hangar/domain-check?domain=...` responde 200 só para domínio
  de loja ativa, e só se a assinatura HMAC do Hangar bater (janela de 60 s).
  O segredo chega sozinho na variável `HANGAR_DOMAIN_CHECK_SECRET`.
- Host desconhecido recebe 404.

## Como usar no Hangar

```sh
docker build -t lab-multidominio:dev examples/lab-multidominio
```

1. Crie o projeto `lab` e o serviço `web` com a imagem `lab-multidominio:dev`
   e porta `8000`.
2. Variável `LAB_DOMAINS=loja1.seudominio.com,loja2.seudominio.com`.
3. Na seção Domínios do serviço, ligue os domínios dinâmicos e faça deploy.
4. Aponte o DNS dos domínios para o servidor e abra no navegador.

## Com Postgres e deploy sem downtime (Etapa 6)

1. No projeto `lab`, crie um Postgres pelo template (nome `db`).
2. No serviço `web`, variável `DATABASE_URL=${{db.DATABASE_URL}}`.
3. Em "Deploy": comando pré-deploy
   `sh -c 'python manage.py migrate --noinput && python manage.py seed'` e
   caminho do healthcheck `/healthz`.
4. Cada deploy roda o `migrate` uma vez só (a tabela `DeployMark` ganha uma
   linha por deploy) e a página mostra a versão (`LAB_VERSION`) que respondeu.
