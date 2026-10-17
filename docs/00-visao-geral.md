# 00 — Visão geral

## O problema

Hoje o sistema (Django, multi-loja, uma instância servindo todas as lojas) roda
no Easypanel, que usa Traefik como proxy. Funciona bem para domínios
conhecidos, cadastrados um a um. Mas o modelo de negócio exige:

- O lojista compra o próprio domínio (`minhaloja.com.br`).
- Aponta o DNS para o nosso servidor.
- A loja dele **passa a abrir com HTTPS válido sozinha**, sem ninguém cadastrar
  nada no painel.

No Easypanel/Traefik isso só sai com gambiarra (editar configuração interna,
regras catch-all, certificados manuais). Cada gambiarra é um ponto de quebra em
atualização e um risco de segurança.

O Hangar não é só para um SaaS multi-loja: ele vai hospedar **todos os projetos do
operador** (lojas, sites, bots, APIs), cada um isolado no seu projeto. Um
SaaS multi-loja é o caso que motivou o desenho, por causa dos domínios de
lojistas, e é o último a migrar, depois de tudo validado num projeto de
laboratório.

## O que o Hangar precisa entregar

### Obrigatório (MVP)

- [ ] Instalação com um comando em uma VPS Linux limpa.
- [ ] Login seguro (senha forte + 2FA obrigatório; passkey opcional).
- [ ] Projetos contendo vários serviços isolados entre si.
- [ ] Serviço "App": imagem Docker ou build a partir de repositório Git.
- [ ] Serviços prontos: PostgreSQL, Redis/Valkey (vários por servidor, cada um isolado).
- [ ] Variáveis de ambiente criptografadas.
- [ ] Domínios fixos por serviço com HTTPS automático.
- [ ] **Domínios dinâmicos** (on-demand TLS) com autorização pela aplicação.
- [ ] Logs ao vivo e histórico curto por container.
- [ ] Monitoramento: CPU, RAM, rede, disco por container e do host.
- [ ] Deploy sem downtime e rollback para a versão anterior.
- [ ] Log de auditoria de tudo que é feito no painel.
- [ ] Portas expostas e projetos conectáveis, como no Easypanel.
- [ ] Aviso de bibliotecas/imagens desatualizadas e vulneráveis (Telegram/e-mail).
- [ ] Link externo de status (opcional, anonimizado) para monitorar de fora.

### Desejável (pós-MVP)

- Backups agendados para storage S3 compatível.
- Alertas de servidor (Telegram, e-mail, webhook).
- PR automático de atualização de dependências.
- Terminal web no container (com reautenticação).
- Webhook de deploy do GitHub/GitLab.
- Mais templates (MySQL, MongoDB, n8n, etc.).
- Vários servidores gerenciados por um painel.

### Fora do escopo

- Kubernetes.
- Multi-tenant do *painel* (vender o painel para terceiros). O Hangar é para
  operar a nossa infraestrutura.
- Substituir o sistema de lojas: o Hangar não sabe o que é uma loja; ele só
  pergunta à aplicação se um domínio é válido (ver [03](03-dominios-customizados-tls.md)).

## Comparação com as ferramentas atuais

| Recurso | Easypanel | Coolify | Dokploy | Hangar |
|---|---|---|---|---|
| Proxy | Traefik | Traefik/Caddy | Traefik | Caddy |
| Domínio arbitrário com TLS automático | Não (gambiarra) | Parcial/manual | Não | **Sim, nativo** |
| Autorização do domínio pela aplicação | Não | Não | Não | **Sim** |
| Runtime do painel | Node | PHP + Laravel + vários containers | Node | **Binário Go único** |
| Código nosso, livre para mudar | Não | Sim (complexo) | Sim | **Sim** |
