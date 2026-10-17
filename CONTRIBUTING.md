# Contribuindo com o Hangar

Guia curto do que se espera de uma mudança. As regras completas estão em
[docs/12 — Padrões de código](docs/12-padroes-de-codigo.md).

## Preparar o ambiente

Requisitos: Go (versão do `go.mod`), [just](https://just.systems),
golangci-lint v2, sqlc e Docker. Node LTS só para os testes E2E.

```bash
just run      # painel local em http://127.0.0.1:7710 (hangar.dev.toml, dados em .data/)
./bin/hangard user create -config hangar.dev.toml -email voce@exemplo.com
```

Nada de testar contra projetos reais: use o painel local, o
[`examples/lab-multidominio`](examples/lab-multidominio/README.md) e os
testes descartáveis (`just test-integration`, `just e2e`).

## Antes de abrir o PR

- [ ] `just check` passa (lint, testes com `-race`, govulncheck, `sqlc diff`,
      templ e CSS em dia — o mesmo que o CI).
- [ ] Mexeu em `.sql` de queries, em `.templ` ou em classes Tailwind? Rode
      `just generate` e inclua o código gerado no commit.
- [ ] Mexeu em fluxo de tela? Rode `just e2e` (ou o spec da área:
      `just e2e tests/<arquivo>.spec.ts`).
- [ ] Comportamento novo tem teste; correção de bug tem o teste que falhava.
- [ ] Docs em `docs/` atualizados quando a mudança altera o que eles dizem.

## Padrões

- **Código e comentários em inglês**: nomes, comentários, mensagens de teste,
  logs, auditoria, rotas e valores gravados no banco.
- **Texto que o usuário lê, via i18n**: nunca escrito direto no template ou no
  handler. Chave em inglês nos catálogos `internal/i18n/locales/pt-BR.toml` e
  `en.toml` — os dois sempre completos (um teste falha se faltar ou sobrar
  chave). Erros para o usuário são `i18n.E("chave", ...)`. Ver
  [docs/22](docs/22-idiomas-e-temas.md).
- **Interface**: templ renderizado no servidor, Tailwind, componentes
  **Tucano** e ícones **Lucide**, seguindo o design system "Pista"
  ([docs/18](docs/18-design-system.md)). Sem estilo nem script inline (a CSP
  bloqueia e um teste confere).
- **Banco**: migração nova é um arquivo **goose** numerado em
  `internal/store/migrations/` (nunca edite uma migração já publicada; siga
  "expandir → migrar → contrair" para a versão anterior continuar rodando).
  Queries em `internal/store/queries/`, geradas pelo **sqlc** em `dbq/` (não
  editar à mão).
- **Segurança**: ação crítica (revelar segredo, abrir porta, domínio, conectar
  projetos) exige sudo e auditoria; toda rota declara sua política. Veja
  [docs/17](docs/17-telas-fluxos-e-seguranca.md).
- **Dependências**: só se não der para fazer com a stdlib em poucas linhas;
  sempre na versão estável mais nova, fixada.
- Decisão de arquitetura relevante vira um ADR em [`docs/adr/`](docs/adr/README.md).

## Commits

- Em **português**, título curto dizendo o que muda para quem usa.
- O corpo explica **por que** a mudança existe (o problema, a escolha), não só
  o que mudou.
- Sem prefixo Conventional Commits e sem trailers de atribuição
  (`Co-Authored-By`, etc.).

## Vulnerabilidades

Não abra issue pública. Siga o [SECURITY.md](SECURITY.md).
