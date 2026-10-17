# 22 — Idiomas e temas (claro/escuro)

Dois recursos que valem para **todas as telas**: o painel em vários idiomas e
o tema claro/escuro, escolhidos por usuário.

## Idiomas

### Quais

| Idioma | Código | Situação |
|---|---|---|
| Português do Brasil | `pt-BR` | Padrão, completo sempre |
| Inglês | `en` | Completo sempre |
| Espanhol | `es` | Completo antes da 1.0 (o Tucano já tem os três) |

Um idioma novo é um arquivo novo de catálogo; nada no código muda.

### Como escolhe

1. Preferência salva na conta (`users.locale`), trocada em "Minha conta".
2. Sem preferência: o cabeçalho `Accept-Language` do navegador.
3. Nada disso: `pt-BR`.

A tela de login, que vem antes de saber quem é o usuário, usa o
`Accept-Language`, com um seletor discreto no rodapé.

### Como funciona no código

- **Catálogos** em `internal/i18n/locales/<idioma>.toml`, embutidos no binário:

  ```toml
  [login]
  title = "Entrar"
  bad_credentials = "E-mail ou senha incorretos, ou conta bloqueada."

  [service.deploys]
  count = { one = "1 deploy", other = "{n} deploys" }
  ```

- As telas chamam `T(ctx, "login.title")`, e o idioma vem do contexto da
  requisição. Plural (`one`/`other`) e variáveis (`{n}`) entram no catálogo.
- **Chave sempre em inglês**, texto no idioma. Isso casa com o padrão inglês
  do código ([12](12-padroes-de-codigo.md)).
- **Erros para o usuário viram chave**: o código devolve um erro com código
  (`project.slug_invalid`) e a tela traduz. Mensagem de log e de auditoria
  continua em inglês e não é traduzida, porque é dado, não interface.
- **Datas e números** formatados pelo idioma (`15/10/2026 14:32` ×
  `10/15/2026 2:32 PM`), sempre no fuso do navegador do usuário.
- **CLI** (`hangard user create` etc.) segue `LANG` do servidor, com o mesmo
  catálogo.
- O **Tucano** recebe o mesmo idioma (`Tucano.setTexts`), para date picker,
  select e afins falarem a mesma língua da tela.

### Garantias (testes no CI)

- Todo idioma tem **todas** as chaves do `pt-BR`; faltou uma, o build falha.
- Nenhuma chave usada no código fica sem tradução; nenhuma chave sobra sem uso.
- Nenhum texto de tela escrito direto no template: um teste procura texto
  solto nos `.templ`.
- Textos traduzidos passam pelo escape do templ como qualquer outro (um
  catálogo não consegue injetar HTML).

## Temas: escuro, claro e sistema

### Como escolhe

| Opção | Comportamento |
|---|---|
| **Sistema** (padrão) | Segue o sistema operacional (`prefers-color-scheme`) e muda junto se ele mudar |
| Escuro | Sempre escuro |
| Claro | Sempre claro |

A preferência fica na conta (`users.theme`) e vale em qualquer computador. O
seletor fica na barra superior (ícone sol/lua) e em "Minha conta".

### Como funciona

- Os tokens do Pista já existem nos dois temas ([18](18-design-system.md)).
  O CSS define as cores para `[data-theme="dark"]` e
  `[data-theme="light"]`, e para "sistema" usa `@media (prefers-color-scheme)`.
- **O servidor já entrega o HTML com o tema certo** (`<html
  data-theme="dark">`). Não há "piscada" de tema errado ao carregar, e não
  precisa de script inline (que a CSP proíbe).
- O **canvas**, os **gráficos** (uPlot), o **terminal** (xterm) e os
  componentes do **Tucano** leem os mesmos tokens, então trocar o tema troca
  tudo junto.
- A **página pública de status** ([15](15-painel-publico-de-status.md))
  segue o tema do sistema do visitante, e o modo TV é sempre escuro.

### Garantias

- Contraste AA conferido nos dois temas (teste automático sobre os tokens).
- Nenhuma cor fixa no CSS fora dos tokens: um teste procura `#hex` fora do
  bloco de tokens.

## Situação (Etapa 3b, concluída)

- `pt-BR` e `en` completos: telas, mensagens de erro, linha de comando.
  Espanhol entra antes da 1.0 (basta o arquivo `locales/es.toml`).
- Tema escuro, claro e sistema, por usuário, em "Minha conta".
- Testes no CI: chaves iguais em todos os idiomas, nenhuma chave usada sem
  tradução nem tradução sem uso, nenhum texto solto nos templates, contraste
  AA nos dois temas e nenhuma cor fora dos tokens.
- Erro dentro de erro sai no mesmo idioma (ex.: o motivo de um `panel.listen`
  inválido).
- **Pendente:** o `install.sh` ainda fala só português (é script de shell,
  fora do catálogo); o Tucano já está nas telas (v0.5.1): vai embutido no binário (`assets/vendor/tucano`, versão e hash travados por teste), seus tokens `--tuc-*` apontam para os do Pista e os textos que ele escreve sozinho vêm do catálogo do painel.

## Modelo de dados

```sql
ALTER TABLE users ADD COLUMN locale TEXT;                       -- NULL = Accept-Language
ALTER TABLE users ADD COLUMN theme  TEXT NOT NULL DEFAULT 'system'
    CHECK (theme IN ('system', 'dark', 'light'));
```
