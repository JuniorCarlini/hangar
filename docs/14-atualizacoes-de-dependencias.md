# 14 — Monitor de atualizações e vulnerabilidades

Objetivo: você **não** precisar ficar vigiando versões. O Hangar vigia e avisa
pelo Telegram ou e-mail quando algo está desatualizado ou, mais importante,
vulnerável.

## O que é vigiado

| Camada | Exemplo | Fonte da versão atual | Fonte da versão nova / vulnerabilidade |
|---|---|---|---|
| **Bibliotecas das suas aplicações** | `django`, `celery`, `requests` no `requirements.txt`/`pyproject.toml`/`uv.lock`/`poetry.lock`; `package.json`/lockfiles; `go.mod`; `composer.lock` | Arquivos do repositório no commit em produção | PyPI, npm, proxy do Go, Packagist + **OSV.dev** (base aberta de CVEs) |
| **Imagem base** do Dockerfile | `python:3.13-slim` | `FROM` do Dockerfile | Registry (tags novas) |
| **Pacotes dentro da imagem** (SO) | `openssl`, `libc` | SBOM gerado da imagem (Syft/Trivy) | OSV.dev / bases de CVE da distro |
| **Serviços (templates)** | `postgres:18.0` → `18.1`; Redis 8 → 9 | Digest/tag do container rodando | Registry |
| **Infra do servidor** | Docker Engine, Caddy, kernel, pacotes do SO | Versão instalada | Releases oficiais + avisos de segurança |
| **O próprio Hangar** | `hangard` 1.2.0 → 1.3.0 | Binário | Releases do repositório (com assinatura) |

## Classificação dos avisos

| Nível | Quando | Como avisa |
|---|---|---|
| 🔴 **Crítico** | CVE crítica/alta numa versão que você **usa**, com correção disponível | Na hora, Telegram + e-mail |
| 🟠 **Segurança** | CVE média/baixa, ou patch de segurança do Docker/Caddy/SO | Resumo diário |
| 🟡 **Patch/minor** | `4.2.1` → `4.2.3`, `4.2` → `4.3` | Resumo semanal |
| ⚪ **Major** | `4.x` → `5.0` (pode quebrar) | Resumo semanal, separado, com link do changelog |

Cada aviso diz: o que é, versão atual → nova, em qual serviço/projeto, link
para o changelog/CVE e **o comando ou a linha a mudar** (ex.: `Django==5.2.7`
no `requirements.txt`).

Exemplo de mensagem no Telegram:

```
🔴 Hangar — vulnerabilidade crítica
Projeto minhaloja · serviço django
Django 5.2.3 → corrigido em 5.2.7
CVE-2026-XXXXX (SQL injection em QuerySet.filter com JSONField)
Ação: atualizar requirements.txt e fazer deploy
Detalhes: https://painel.../updates/abc123
```

## Como funciona

1. **No build** (apps com fonte Git) e **todo dia às 06:00**, o Hangar lê os
   manifestos/lockfiles do commit que está em produção. Lockfile é preferido:
   ele tem a versão exata instalada.
2. Para imagens, gera um SBOM (lista de tudo que está dentro da imagem) com
   Syft. O SBOM fica guardado por deployment, e a checagem diária só consulta
   CVEs novas contra ele, sem reprocessar a imagem.
3. Consulta OSV.dev em lote (`/v1/querybatch`) e os registries de pacotes,
   com cache de 6 h.
4. Compara com o último resultado e **só avisa o que é novo**. Nada de repetir
   a mesma lista todo dia. Cada item pode ser marcado como "ignorar até a
   versão X" ou "ignorar por 30 dias", com motivo (fica no audit log).
5. Tela "Atualizações" no painel: tudo que está pendente, por projeto,
   ordenado por gravidade.

## O que ele **não** faz sozinho

- Não atualiza nada automaticamente em produção. Atualizar biblioteca pode
  quebrar a aplicação; a decisão é sua.
- Pós-MVP (opcional): abrir um **Pull Request** no GitHub com a atualização
  (estilo Renovate/Dependabot). O CI do projeto roda os testes e você só aprova.
- Para os **templates** (Postgres, Redis): botão "atualizar" para patch
  (`18.0` → `18.1`) com backup automático antes. Versão major nunca é
  atualizada com um clique: o painel mostra o guia de migração.

## Segurança desta parte

- Token do Git **só leitura**, cifrado (ver [04](04-seguranca.md)).
- As consultas a OSV/PyPI/npm enviam **nomes e versões de pacotes**, nunca
  código, segredos ou nomes de clientes.
- Respostas externas são tratadas como dado não confiável (validadas, sem
  renderizar HTML vindo de fora).

## Canais de aviso (compartilhados com os alertas — ver [06](06-monitoramento-e-logs.md))

| Canal | Configuração |
|---|---|
| **Telegram** | Token do bot (cifrado) + chat ID. Botão "enviar teste". Mensagens sem dados sensíveis (sem IP, sem segredos). |
| **E-mail** | SMTP com TLS obrigatório (ou API do Resend/SES/Postmark). |
| **Webhook** | URL + assinatura HMAC, para Discord/Slack/n8n/o que quiser. |

Cada canal escolhe quais níveis recebe (ex.: Telegram só 🔴 e alertas de
servidor; e-mail recebe o resumo semanal completo).


## Como ficou na Etapa 11

O que já funciona (pacote `internal/deps`, tela `/updates`):

- **Inventário pela imagem em produção**, não pelo repositório: o Hangar
  exporta do Docker a imagem que o container está rodando (pelo ID, não pela
  tag), lê com o [OSV-SCALIBR](https://github.com/google/osv-scalibr) e
  apaga o arquivo. Entram os pacotes do SO (dpkg, apk, rpm, chisel), o que
  está instalado em cada linguagem (`*.dist-info` do Python, `node_modules`,
  gems, jars Maven, `*.deps.json` do .NET), os lockfiles de Composer,
  Bundler, Cargo, Pub e Mix, e os módulos compilados dentro de binários Go e
  Rust. Só extratores de pacotes: nenhum detector de segredo, nada com rede,
  nada executado da imagem. A imagem do Caddy também é lida.
  - Limites (o painel roda com 384 MB de memória): uma imagem por vez, até
    3 GB, 10 min por imagem, e só com o dobro do tamanho livre em disco.
    Os arquivos temporários ficam em `<data_dir>/tmp` (o `/tmp` do serviço é
    privado e pequeno). Imagem pulada ou que falha cai no método antigo, com
    o motivo no log.
  - Método antigo (reserva): comandos fixos de leitura (`cat`, `find`)
    dentro do container, para o banco de pacotes do SO, `*.dist-info` e
    `package-lock.json`/`composer.lock`. Imagem sem `find`/`cat`
    (distroless) aparece em "Não foi possível ler tudo".
- **OSV.dev em lote** (`/v1/querybatch` + `/v1/vulns/{id}`), cache de 6 h.
  Só nome, ecossistema e versão saem do servidor (há teste conferindo).
- **Tags de imagem** pelo registry (Docker Hub e qualquer registry com a API
  v2, token anônimo): o mais novo do mesmo major (🟡) e o major novo (⚪),
  só entre tags com o mesmo sufixo e a mesma precisão (`18.0` → `18.2`,
  `1.29-alpine` → `1.30-alpine`). A imagem do Caddy entra como "servidor".
- **Níveis** como na tabela acima. Aviso sem correção e com gravidade
  baixa/média/não informada é descartado: as distros têm centenas desses e
  não há o que fazer.
- **Varredura** todo dia às 06:00 (`[scan] hour`) e no botão "Verificar
  agora" (Operador+). Achado que some numa varredura fica resolvido; se
  voltar, é avisado de novo.
- **Ignorar** (Operador+, motivo obrigatório, vai para a auditoria): por 30
  dias ou "até sair versão mais nova que X".
- **Avisos:** críticos na hora, segurança no resumo diário, patch/minor/major
  no semanal, cada item uma vez só. Enquanto os canais da Etapa 8 não estão
  ligados, os resumos vão para o log (`dependency notice`); a Etapa 8 só
  precisa implementar `deps.Notifier` e chamar `Monitor.SetNotifier`.

Ainda não: SBOM guardado por deploy (a checagem lê a imagem a cada
varredura), varredura no build (não há build de Git ainda), infra do servidor (Docker Engine, kernel), botão "atualizar"
dos templates e o Pull Request automático.
