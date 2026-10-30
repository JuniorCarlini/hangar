#!/usr/bin/env bash
# Hangar installer (Debian 13 / Ubuntu 26.04).
#
#   curl -fsSLO https://github.com/JuniorCarlini/hangar/releases/latest/download/install.sh
#   sudo bash install.sh [--version vX.Y.Z] [--token-file arquivo] [--from-dir diretorio]
#
# Nothing is installed without checking the release's Ed25519 signature with
# the public key below (the same one embedded in the binary) and the binary's
# SHA-256. Running the installer again is safe: it never deletes data or the
# master key.
set -euo pipefail

REPO="JuniorCarlini/hangar"
RELEASE_PUBKEY_HEX="3c84b55c17438e93d4fd0a11dde9e88de3d00cf2bab5fad52589b841c6d49121"

VERSION="latest"
TOKEN_FILE=""
FROM_DIR=""

die() { echo "erro: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "aviso: $*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --from-dir)   FROM_DIR="$2"; shift 2 ;;
    -h|--help)    sed -n '2,10p' "$0"; exit 0 ;;
    *) die "opção desconhecida: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "rode como root (sudo bash install.sh)"
command -v systemctl >/dev/null || die "systemd é obrigatório"
command -v openssl >/dev/null || die "openssl é obrigatório para conferir a assinatura"
command -v sha256sum >/dev/null || die "sha256sum é obrigatório"

case "$(uname -m)" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) die "arquitetura não suportada: $(uname -m)" ;;
esac
ASSET="hangard-linux-${ARCH}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- download -----------------------------------------------------------
fetch_release() {
  local auth=()
  if [[ -n "$TOKEN_FILE" ]]; then
    auth=(-H "Authorization: Bearer $(tr -d '[:space:]' < "$TOKEN_FILE")")
  fi
  local api="https://api.github.com/repos/${REPO}/releases"
  local url="${api}/latest"
  [[ "$VERSION" != "latest" ]] && url="${api}/tags/${VERSION}"

  curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" "$url" -o "$WORK/release-meta.json" \
    || die "não consegui consultar a release no GitHub (sem internet? fork privado precisa de --token-file)"

  for name in release.json release.json.sig "$ASSET"; do
    # Asset API URL: with Accept octet-stream GitHub serves the file.
    local asset_url
    asset_url="$(tr ',' '\n' < "$WORK/release-meta.json" | tr -d '{}[]' \
      | awk -v n="\"$name\"" '/"url":/ {u=$0} /"name":/ && index($0, n) {print u; exit}' \
      | sed -E 's/.*"url": *"([^"]+)".*/\1/')"
    [[ -n "$asset_url" ]] || die "a release não tem o arquivo $name"
    curl -fsSL "${auth[@]}" -H "Accept: application/octet-stream" "$asset_url" -o "$WORK/$name" \
      || die "falha ao baixar $name"
  done
}

if [[ -n "$FROM_DIR" ]]; then
  info "usando release local em $FROM_DIR"
  for name in release.json release.json.sig "$ASSET"; do
    cp "$FROM_DIR/$name" "$WORK/$name" || die "faltou $name em $FROM_DIR"
  done
else
  info "baixando release $VERSION de $REPO"
  fetch_release
fi

# --- verify -------------------------------------------------------------
info "conferindo assinatura e hash"
# Raw Ed25519 key -> PEM (DER SubjectPublicKeyInfo prefix for Ed25519).
der_hex="302a300506032b6570032100${RELEASE_PUBKEY_HEX}"
printf '%b' "$(echo "$der_hex" | sed 's/../\\x&/g')" > "$WORK/pub.der"
openssl pkey -pubin -inform DER -in "$WORK/pub.der" -out "$WORK/pub.pem" 2>/dev/null \
  || die "chave pública inválida no instalador"
base64 -d < "$WORK/release.json.sig" > "$WORK/release.sig" || die "assinatura em formato inválido"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin \
  -in "$WORK/release.json" -sigfile "$WORK/release.sig" >/dev/null 2>&1 \
  || die "ASSINATURA INVÁLIDA: a release não foi publicada pelo projeto. Nada foi instalado."

want="$(grep -E "\"${ASSET}\"" "$WORK/release.json" | sed -E 's/.*: *"([0-9a-f]{64})".*/\1/')"
got="$(sha256sum "$WORK/$ASSET" | cut -d' ' -f1)"
[[ "$want" =~ ^[0-9a-f]{64}$ && "$want" == "$got" ]] || die "HASH DO BINÁRIO NÃO CONFERE. Nada foi instalado."
REL_VERSION="$(grep -E '"version"' "$WORK/release.json" | sed -E 's/.*: *"([^"]+)".*/\1/')"
info "release $REL_VERSION conferida"

# --- install ------------------------------------------------------------
if ! id hangar >/dev/null 2>&1; then
  info "criando usuário de sistema hangar"
  useradd --system --home-dir /var/lib/hangar --shell /usr/sbin/nologin --user-group hangar
fi

# --- Docker ----------------------------------------------------------------
# Docker's official repository with its signing key (apt refuses packages
# not signed by that key). No "curl | sh".
if ! command -v docker >/dev/null 2>&1; then
  info "instalando Docker Engine (repositório oficial)"
  . /etc/os-release
  case "$ID" in debian|ubuntu) ;; *) die "instalação automática do Docker só em Debian/Ubuntu";; esac
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io >/dev/null
fi

if [[ ! -f /etc/docker/daemon.json ]]; then
  info "configurando o Docker (logs com rotação, live-restore)"
  install -d -m 0755 /etc/docker
  cat > /etc/docker/daemon.json <<'JSON'
{
  "log-driver": "local",
  "log-opts": { "max-size": "50m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false,
  "userland-proxy": false
}
JSON
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null

# Disk size limits (docs/05) format an ext4 image per volume. e2fsprogs is
# only "important" in Debian: minimal and container images leave it out, and
# the limit then fails with "mkfs.ext4 not found".
if ! command -v mkfs.ext4 >/dev/null 2>&1; then
  info "instalando e2fsprogs (limite de tamanho dos discos)"
  apt-get update -qq
  apt-get install -y -qq e2fsprogs >/dev/null
fi

# The docker group is root-equivalent on the server: only the panel user
# joins it (docs/04, "residual risk").
usermod -aG docker hangar

install -d -m 0750 -o root -g hangar /etc/hangar
install -d -m 0700 -o hangar -g hangar /var/lib/hangar
install -d -m 0700 -o hangar -g hangar /var/lib/hangar/backups
install -d -m 0750 -o hangar -g hangar /var/lib/hangar/update

if [[ ! -f /etc/hangar/master.key ]]; then
  info "gerando chave mestra (guarde uma cópia fora do servidor)"
  head -c 32 /dev/urandom > /etc/hangar/master.key
fi
chown hangar:hangar /etc/hangar/master.key
chmod 0400 /etc/hangar/master.key

TOKEN_LINE=""
if [[ -n "$TOKEN_FILE" ]]; then
  install -m 0400 -o hangar -g hangar "$TOKEN_FILE" /etc/hangar/github-token
  TOKEN_LINE='token_file = "/etc/hangar/github-token"'
fi

# A fresh install publishes the panel with HTTPS when it can: Caddy needs
# ports 80 and 443 free, and the server's public IPv4 names the panel
# (hangar.<ip>.sslip.io). Otherwise the panel stays reachable only through
# an SSH tunnel, and the edge can be turned on later in hangar.toml.
public_v4() {
  local a b
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
  (( a == 0 || a == 10 || a == 127 || a >= 224 )) && return 1
  (( a == 172 && b >= 16 && b <= 31 )) && return 1
  (( a == 192 && b == 168 )) && return 1
  (( a == 169 && b == 254 )) && return 1
  (( a == 100 && b >= 64 && b <= 127 )) && return 1
  return 0
}
detect_public_ip() {
  local ip url
  # A public address on an interface (most VPS)...
  for ip in $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
    public_v4 "$ip" && { echo "$ip"; return; }
  done
  # ...or behind the provider's NAT (Oracle, AWS, GCP): ask from outside.
  for url in https://api.ipify.org https://ifconfig.me/ip; do
    ip="$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')" || continue
    public_v4 "$ip" && { echo "$ip"; return; }
  done
}

EDGE_BLOCK='# [edge]
# enabled = true
# public_ips = ["203.0.113.10"]'
PANEL_PUBLIC='# public = true   # painel na internet com HTTPS (exige [edge])'
if [[ ! -f /etc/hangar/hangar.toml ]]; then
  PUBLIC_IP="$(detect_public_ip || true)"
  if [[ -z "$PUBLIC_IP" ]]; then
    warn "não descobri o IP público: o painel fica só pelo túnel SSH (ligue [edge] e [panel] public depois)"
  elif ss -Hltn '( sport = :80 or sport = :443 )' 2>/dev/null | grep -q .; then
    warn "as portas 80/443 já estão em uso: o painel fica só pelo túnel SSH (ligue [edge] e [panel] public depois)"
  else
    info "painel público com HTTPS em hangar.${PUBLIC_IP//./-}.sslip.io"
    EDGE_BLOCK="[edge]
enabled = true
public_ips = [\"${PUBLIC_IP}\"]"
    PANEL_PUBLIC='public = true'
  fi
fi

if [[ ! -f /etc/hangar/hangar.toml ]]; then
  info "criando /etc/hangar/hangar.toml"
  cat > /etc/hangar/hangar.toml <<CFG
# Configuração do Hangar. Detalhes em docs/ do repositório.
data_dir = "/var/lib/hangar"
master_key_file = "/etc/hangar/master.key"

[panel]
# O painel escuta localmente; com public = true o Caddy também o publica na
# internet com HTTPS, em hangar.<ip>.sslip.io (ou em public_host). Sem ele,
# acesse por túnel SSH:
#   ssh -L 7700:127.0.0.1:7700 usuario@servidor  ->  http://localhost:7700
listen = ["127.0.0.1:7700"]
hosts  = ["127.0.0.1:7700", "localhost:7700"]
${PANEL_PUBLIC}
# public_host = "painel.exemplo.com"   # endereço próprio, com DNS apontando para cá

[update]
repo = "${REPO}"
${TOKEN_LINE}

[auth]
# A 2FA é obrigatória para donos e admins, sempre. "Exigir 2FA de todos"
# (operadores e leitores também) é uma opção do painel, em Equipe →
# Segurança, ligada num painel novo. Esta linha só vale como valor inicial
# para um painel que já tinha contas antes de a opção existir; depois, manda
# a opção do painel.
require_2fa = true

# Proxy de borda (Caddy) nas portas 80 e 443: HTTPS automático no painel,
# nos serviços e nos domínios dos clientes (docs/03). O instalador liga
# quando as portas estão livres e descobre o IP público.
${EDGE_BLOCK}
# acme_email = "voce@exemplo.com"   # avisos de expiração do certificado
# Deploy automático por push (webhook do GitHub): um domínio que aponte
# para este servidor. O Caddy publica só /hooks/git/* nele; o painel
# continua fechado.
# hooks_hostname = "hooks.exemplo.com"

# Monitor de atualizações e vulnerabilidades (docs/14): todo dia nesta hora
# o Hangar lê os pacotes dos containers e consulta o OSV.dev (só nomes e
# versões de pacotes saem do servidor).
# [scan]
# enabled = true
# hour = 6

# Catálogo de templates (docs/08): uma vez por dia o painel baixa o
# catálogo da comunidade, assinado, e confere cada template com as mesmas
# regras dos que vêm no binário. Desligado, só os embutidos aparecem.
# [templates]
# sync = true

# Links públicos de status (docs/15) num domínio separado do painel. Esse
# domínio só alcança as páginas /s/..., nunca o painel.
# [status]
# hosts = ["status.exemplo.com"]
CFG
  chown root:hangar /etc/hangar/hangar.toml
  chmod 0640 /etc/hangar/hangar.toml
fi

info "instalando binário"
install -m 0755 -o root -g root "$WORK/$ASSET" /usr/local/bin/hangard.new
mv -f /usr/local/bin/hangard.new /usr/local/bin/hangard

/usr/local/bin/hangard system install-units
systemctl enable --now hangar-updater.path >/dev/null
systemctl enable hangard >/dev/null
STARTED="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart hangard

# The first start with the edge on also pulls the Caddy image: give it time.
for _ in $(seq 1 180); do
  [[ "$(cat /var/lib/hangar/run/ready 2>/dev/null || true)" == "$REL_VERSION" ]] && break
  sleep 1
done
[[ "$(cat /var/lib/hangar/run/ready 2>/dev/null || true)" == "$REL_VERSION" ]] \
  || die "o painel não subiu; veja: journalctl -u hangard -n 50"

# What the panel said on this start: its public address, and whether the
# owner still has to be created (the first-run window).
LOG="$(journalctl -u hangard --since "$STARTED" -o cat --no-pager 2>/dev/null || true)"
PANEL_URL="$(grep '"msg":"panel public"' <<<"$LOG" | tail -n1 | sed -E 's/.*"url":"([^"]+)".*/\1/' || true)"
NEEDS_OWNER=0
grep -q '"msg":"no user yet' <<<"$LOG" && NEEDS_OWNER=1

echo
echo "Hangar $REL_VERSION instalado e rodando."
echo
if [[ -n "$PANEL_URL" ]]; then
  echo "Painel: $PANEL_URL"
  echo "  (o certificado HTTPS sai no primeiro minuto; as portas 80 e 443 precisam"
  echo "   estar liberadas também no firewall do provedor, se ele tiver um)"
else
  echo "Painel (só pelo túnel SSH), do seu computador:"
  echo "  ssh -L 7700:127.0.0.1:7700 usuario@este-servidor"
  echo "  e abra http://localhost:7700"
fi
echo
if [[ "$NEEDS_OWNER" == 1 ]]; then
  echo "Crie a conta de dono no painel nos próximos 30 minutos. Passou do prazo?"
  echo "  sudo systemctl restart hangard   (abre mais 30 minutos)"
  echo
fi
echo "Depois, no painel: Backups -> Kit de recuperação. O kit guarda tudo,"
echo "inclusive a chave mestra do servidor: não precisa copiar nada pelo SSH."
echo "Atualizações: botão \"Atualização\" no painel, ou: sudo -u hangar hangard self-update stage -config /etc/hangar/hangar.toml"
