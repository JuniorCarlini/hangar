# Segurança

## Reportar uma vulnerabilidade

**Não abra issue pública** nem PR com o detalhe da falha.

- Fale em privado com o mantenedor, [@JuniorCarlini](https://github.com/JuniorCarlini)
  no GitHub. Quando o repositório for público, use **Security → Report a
  vulnerability** (aviso privado do GitHub).
- Conte o que encontrou, a versão (`hangard version`), como reproduzir e o
  impacto que você vê. Prova de conceito é bem-vinda; não teste contra
  servidores de terceiros nem contra dados de clientes.
- Nunca mande segredos reais (chave mestra, kit de recuperação, tokens): se um
  vazou, troque-o primeiro ([docs/24 § 6](docs/24-operacao.md#6-trocar-chaves-senhas-e-tokens)).

A resposta vem assim que possível; a correção sai numa release assinada,
descrita no [CHANGELOG](CHANGELOG.md).

## Versões com correção

Correções saem numa release nova; não há versões antigas mantidas em
paralelo. Mantenha o painel na mais recente pelo botão **Atualizar Hangar** ou
com `sudo -u hangar hangard self-update stage`.

## Onde ler mais

- [docs/04 — Segurança](docs/04-seguranca.md): modelo de ameaça e controles.
- [docs/17 — Telas, fluxos e segurança](docs/17-telas-fluxos-e-seguranca.md): as 34 brechas e mitigações.
- [docs/24 — Operação](docs/24-operacao.md): trancar o painel e o que fazer numa suspeita de invasão.
