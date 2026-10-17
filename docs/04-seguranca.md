# 04 — Segurança

## Modelo de ameaça

| Ameaça | Exemplo | Controles |
|---|---|---|
| Invasão do painel | Força bruta, senha vazada, sessão roubada | 2FA (obrigatório em produção com `require_2fa`), passkeys, rate limit, lockout, sessão curta, painel só por HTTPS (ou modo bunker) |
| Abuso de domínio dinâmico | Esgotar rate limit da Let's Encrypt, phishing | `ask` com autorização da app, limites, fail-closed ([03](03-dominios-customizados-tls.md)) |
| Container comprometido escapando | RCE na aplicação → host | Hardening de container, sem docker.sock, redes isoladas ([05](05-isolamento-e-recursos.md)) |
| Movimento lateral entre projetos | App A acessa Postgres do projeto B | Rede por projeto; conexão entre projetos só quando você liga; senhas fortes geradas |
| Vazamento de segredos | Dump do SQLite, backup exposto | Segredos cifrados com chave fora do banco; backups cifrados |
| Exposição acidental de porta | Docker ignorando UFW, porta esquecida aberta | Regras na chain `DOCKER-USER`; opção por IP/localhost; tela de portas abertas; aviso ao expor banco |
| Supply chain | Imagem trocada, dependência maliciosa | Imagens fixadas por digest, `govulncheck`, binário assinado |
| Ação maliciosa/indevida de operador | "Quem apagou esse banco?" | Log de auditoria encadeado por hash, reautenticação em ações críticas |

## Acesso ao painel

Dois modos:

1. **Público (padrão da instalação)** — `[panel] public = true`: o Caddy
   publica o painel com HTTPS em `hangar.<ip>.sslip.io` (sem domínio, com
   certificado Let's Encrypt de verdade) ou em `public_host`
   (`painel.seudominio.com`). O instalador liga quando as portas 80/443
   estão livres e descobre o IP público. O painel continua escutando só em
   127.0.0.1 e no gateway da rede `hangar-edge`, onde **só o IP do Caddy**
   é aceito; o IP do visitante vem do `X-Forwarded-For` que o Caddy põe, e
   vale para limites de tentativa, sessões e auditoria. Com o painel
   trancado, quem chega pelo Caddy recebe 403.
2. **Bunker** — sem `public`: o painel **não** tem endereço público. Acesso
   só por WireGuard/Tailscale ou túnel SSH (`ssh -L 7700:127.0.0.1:7700
   vps`). A internet nem sabe que o painel existe.

Nos dois modos, cabeçalhos: HSTS (com preload), CSP estrita
(`default-src 'self'`, sem `unsafe-inline` — por isso HTMX e Tucano são
servidos localmente, e o Editor do Tucano, que grava `style` em atributo, não
é usado), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy` restrita, `Cross-Origin-Opener-Policy: same-origin`.

## Autenticação

- **Senha**: mínimo 14 caracteres, verificada contra lista de senhas vazadas
  (lista local, k-anonymity opcional), hash **argon2id** (m=64 MiB, t=3, p=2,
  ajustável).
- **2FA**: TOTP com códigos de recuperação (10, de uso único). Como no
  Easypanel, cada conta liga ou desliga em "Minha conta"; quem está sem 2FA
  entra só com a senha, vê um aviso fixo no topo de todas as telas, e as
  ações perigosas pedem a senha de novo em vez do código. Com
  `[auth] require_2fa = true` no `hangar.toml` (o instalador escreve
  `false`), o painel recusa login de conta sem 2FA e impede desligar. No servidor,
  `hangard user totp-off -email ...` desliga a 2FA de uma conta (celular
  perdido), encerrando as sessões dela.
- **Passkeys (WebAuthn)**: recomendadas; podem substituir senha+TOTP.
- **Rate limit**: 5 tentativas/15 min por IP e por usuário; depois, atraso
  exponencial. 20 falhas por usuário → conta bloqueada até desbloqueio via CLI
  no servidor (`hangard user unlock`).
- **Sem enumeração de usuário**: mesma resposta e mesmo tempo para usuário
  inexistente.
- **Primeiro acesso**: enquanto não existe usuário, a tela "Criar a conta
  de dono" fica aberta por **30 minutos** depois que o painel liga. Passado
  o prazo, ela fecha e só reabre com `sudo systemctl restart hangard` (quem
  reabre tem shell no servidor): uma instalação esquecida não fica para
  quem achar o endereço. Tentativas contam no mesmo limite do login; o dono
  só é gravado se a tabela de usuários ainda estiver vazia (duas tentativas
  ao mesmo tempo não criam dois donos); depois disso a tela some. A CLI
  (`hangard user create`) segue disponível e também fecha a tela.

## Sessão

- Sessão server-side (tabela `sessions`), ID aleatório de 256 bits; no banco
  guarda-se só o hash.
- Cookie `__Host-hangar_session`: `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`.
- Expiração ociosa 30 min, absoluta 12 h. Rotação do ID após login e após
  reautenticação.
- **Modo sudo**: ações críticas (apagar serviço/volume, ver segredo em claro,
  abrir terminal, alterar usuários, restaurar backup) exigem reautenticação
  (TOTP/passkey) válida por 5 min.
- Lista de sessões ativas com botão "encerrar".
- **Modo trancado** (botão de pânico, [17 § 1.6](17-telas-fluxos-e-seguranca.md)):
  "Trancar painel" no menu do Dono ou `hangard lockdown` no servidor
  encerra todas as sessões e deixa o painel acessível só pelo próprio
  servidor (túnel SSH). Destrancar só com `hangard lockdown off`.

## CSRF e entrada

- Token CSRF por sessão em todo POST/PUT/DELETE + verificação de
  `Origin`/`Sec-Fetch-Site` (a stdlib do Go tem `http.CrossOriginProtection`).
- Validação de toda entrada no servidor (nomes de serviço `^[a-z][a-z0-9-]{1,30}$`,
  domínios, imagens Docker, portas).
- Nada da entrada do usuário vai para shell. Toda interação com Docker é pela
  API (nunca `exec.Command("docker", ...)` com string montada).

## Segredos

- Variáveis de ambiente marcadas como secretas, senhas de banco, tokens de
  Git e credenciais S3 são cifradas com **XChaCha20-Poly1305**.
- Chave mestra de 256 bits em `/etc/hangar/master.key` (0400, dono `hangar`),
  gerada na instalação. Opcional: carregar via `systemd-creds` (cifrada pelo
  TPM quando houver).
- Associated data = `tabela|id|coluna` (impede copiar o valor cifrado de um
  registro para outro).
- Segredos nunca aparecem em log, em mensagem de erro ou na interface (mostra
  `••••` + botão "revelar" em modo sudo, auditado).
- A chave mestra vai **dentro** do backup do painel, que é cifrado com a chave
  pública do operador (age). Só o Kit de recuperação do operador abre esse
  backup ([09](09-backups.md)).

## Auditoria

- Toda ação que muda estado gera um registro em `audit_log`: quem, quando, IP,
  user-agent, ação, alvo, resumo (sem segredos).
- Cada registro guarda `hash = SHA-256(hash_anterior || conteúdo)`; um comando
  `hangard audit verify` detecta adulteração.
- Exportação opcional para syslog/arquivo remoto.

## Host (aplicado pelo instalador, com confirmação)

- SSH: só chave, `PermitRootLogin no`, porta configurável.
- Firewall nftables: entrada permitida só em 22 (ou porta SSH), 80, 443 TCP e
  443 UDP. **Regras também na chain `DOCKER-USER`**, porque portas publicadas
  pelo Docker passam por cima do UFW/regras comuns.
- `unattended-upgrades` (ou equivalente) para patches de segurança.
- Opcional: CrowdSec lendo os logs do Caddy e do SSH.
- Relógio sincronizado (chrony) — TOTP e ACME dependem disso.

## O próprio `hangard`

- Unit systemd com: `User=hangar`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `ReadWritePaths=/var/lib/hangar /run/hangar`, `CapabilityBoundingSet=` (vazio),
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`.
- Observação honesta: acesso ao socket do Docker equivale a root no host. O
  sandbox do systemd reduz o estrago de bugs triviais, mas **a proteção real é
  ninguém não autorizado conseguir mandar comandos ao `hangard`** — por isso o
  foco em autenticação, modo bunker e superfície mínima.
- Binário publicado com checksum SHA-256 e assinatura cosign; o
  `hangard self-update` verifica antes de trocar.
- CI roda `govulncheck` e `golangci-lint` (com `gosec`) em todo PR.

## Checklist de revisão de segurança (todo PR que toca estes pontos)

- [ ] Nova rota: exige autenticação? CSRF? autorização por papel?
- [ ] Nova entrada do usuário: validada no servidor?
- [ ] Algum segredo pode cair em log ou resposta?
- [ ] Algum container novo nasce sem os padrões de hardening?
- [ ] Alguma porta nova publicada no host?
- [ ] Ação crítica nova está em modo sudo e no audit log?
