# 21 — Atualização com um clique

Dois tipos de atualização, ambos com um clique e sem reinstalar nada:

1. **Do próprio Hangar**: saiu versão nova no GitHub → botão "Atualizar" no
   painel.
2. **Das suas aplicações** (ex.: um SaaS multi-loja): você fez push no GitHub → botão
   "Fazer deploy" (ou automático pelo webhook). Isso já é o pipeline de deploy
   de [07](07-deploy-e-builds.md): build, `migrate` uma vez no pré-deploy,
   troca sem downtime e volta automática se o healthcheck falhar.

Este documento trata do primeiro.

## Como fica para você

```
┌ Atualização disponível ─────────────────────────────────────────────────┐
│ Hangar v1.3.0 (você está na v1.2.4)            [Ver novidades] [Atualizar 🔒] │
└──────────────────────────────────────────────────────────────────────────┘
```

Clicou → confirma o 2FA → barra de progresso → o painel recarrega já na
versão nova. **As lojas não caem**: o que reinicia é só o painel. Caddy e
containers continuam rodando (o Docker está com `live-restore`).

Opcional, nas configurações: "instalar correções (patch) automaticamente de
madrugada". Vem desligado.

## O que acontece por trás

```
 hangard (usuário hangar, sem privilégio)          hangar-updater (root, só isto)
 ─────────────────────────────────────────          ─────────────────────────────
 1. a cada ~10 min vê a última release (um redirect
    sem corpo, fora da API) e confere a assinatura
    do release.json de cada versão nova uma vez
 2. clique + sudo → baixa binário + release.json + release.json.sig
    + assinatura para /var/lib/hangar/update/
 3. confere assinatura e checksum
 4. grava o pedido (request.json) ──────────────►  5. systemd percebe o pedido (path unit)
                                                   6. CONFERE TUDO DE NOVO (não confia no
                                                      processo sem privilégio)
                                                   7. cópia do banco (VACUUM INTO) +
                                                      guarda o binário atual em releases/
                                                   8. troca o binário (rename atômico)
                                                   9. systemctl restart hangard
                                                      → as migrações rodam sozinhas no boot,
                                                        com cópia prévia (já implementado)
                                                  10. espera o painel gravar run/ready com a
                                                      versão nova (até 90 s; se o systemd
                                                      reiniciar 3 vezes seguidas, desiste
                                                      em ~10 s)
                                                  11a. ok → registra na auditoria, limpa
                                                  11b. falhou → volta o binário antigo,
                                                       restaura a cópia do banco, reinicia
                                                       e manda alerta
```

### Por que dois processos

O `hangard` roda como usuário sem privilégio e com o sistema de arquivos
somente leitura (`ProtectSystem=strict`). Ele **não consegue** trocar o
próprio binário, e é bom que não consiga: se alguém tomasse o painel, não
conseguiria instalar um binário dele. Quem troca é o `hangar-updater`, um
serviço `oneshot` do systemd que só faz isso e **só aceita binário assinado
pela chave de release do projeto**.

### Assinatura das releases

- O CI do GitHub gera os binários (Linux amd64 e arm64), o `release.json` (com o SHA-256 de cada binário) e
  uma assinatura **Ed25519** desse arquivo (`release.json.sig`), com a chave privada guardada
  como segredo do repositório.
- A **chave pública vai embutida no binário**. A verificação usa só a
  biblioteca padrão do Go, sem ferramenta externa.
- Binário sem assinatura válida, versão menor que a atual (downgrade) ou
  arquitetura diferente: recusado e auditado.

### Migrações compatíveis com a volta

Para a volta automática (11b) ser segura, as migrações seguem a regra
**expandir → migrar → contrair**: uma versão só adiciona coluna ou tabela;
remover o que ficou sem uso acontece numa versão seguinte. Assim a versão
anterior ainda consegue rodar sobre o banco novo, e a cópia de antes da
atualização é restaurada só se a versão nova nem chegou a subir.

## Linha de comando (alternativa)

```
sudo -u hangar hangard self-update check -config /etc/hangar/hangar.toml   # só diz se há versão nova
sudo -u hangar hangard self-update stage -config /etc/hangar/hangar.toml   # o mesmo que o botão
```

`self-update apply` é chamado pelo systemd (`hangar-updater.path` →
`hangar-updater.service`), como root.

## Repositório privado

Enquanto o repositório for privado, o servidor precisa de um token do GitHub
**só de leitura** (fine-grained, permissão "Contents: read" só neste
repositório), passado ao instalador com `--token-file` e guardado em
`/etc/hangar/github-token` (0400). Se o repositório virar público, o token
deixa de ser necessário.

## Validado na VM (Debian 13)

- Instalador recusa binário adulterado e manifesto adulterado sem instalar
  nada.
- v0.0.1 → v0.0.2 pelo botão (com sudo): aplicada, sessão do usuário
  continua válida.
- Versão que não sobe: desfeita sozinha em ~10 s, painel de volta na versão
  anterior, banco restaurado, tudo na auditoria.

## Testes desta parte

- Release com assinatura errada → recusada.
- Binário que não sobe (simulado) → volta automática para a versão anterior,
  banco restaurado, alerta enviado.
- Atualizar com o projeto `minhaloja` sob carga → zero erros nas lojas.
- Downgrade → recusado.
