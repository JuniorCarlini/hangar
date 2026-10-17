#!/usr/bin/env bash
# Starts a throwaway hangard for the security scan and the load test:
# its own temporary directory (database, master key, config),
# a free port on 127.0.0.1, an owner created through the CLI without 2FA,
# no contact with GitHub, OSV.dev or Telegram. Never the real panel.
#
#   tools/lab-panel.sh start   prints DIR, PORT, PID, EMAIL and PASSWORD
#   tools/lab-panel.sh stop DIR
#
# Docker is optional: without it the panel runs read-only for projects.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
email="lab@hangar.test"
password="pista-lab-Runway-2026!"

case "${1:-}" in
start)
  dir="$(mktemp -d "${TMPDIR:-/tmp}/hangar-lab-XXXXXX")"
  port="${HANGAR_LAB_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')}"
  (cd "$root" && go build -o "$dir/hangard" ./cmd/hangard)
  cat >"$dir/hangar.toml" <<EOF
data_dir = "data"
master_key_file = "master.key"

[panel]
listen = ["127.0.0.1:${port}"]
hosts = ["127.0.0.1:${port}", "localhost:${port}", "host.docker.internal:${port}"]

[update]
api_base = "http://127.0.0.1:9"

[scan]
enabled = false
osv_api = "http://127.0.0.1:9"

[alerts]
telegram_api = "http://127.0.0.1:9"
EOF
  printf '%s\n%s\n' "$password" "$password" |
    "$dir/hangard" user create -config "$dir/hangar.toml" -email "$email" -role owner -no-2fa >/dev/null
  "$dir/hangard" serve -config "$dir/hangar.toml" >"$dir/hangard.log" 2>&1 &
  pid=$!
  echo "$pid" >"$dir/hangard.pid"
  for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && break
    sleep 0.2
  done
  echo "DIR=$dir"
  echo "PORT=$port"
  echo "PID=$pid"
  echo "EMAIL=$email"
  echo "PASSWORD=$password"
  ;;
start-linux)
  # The same panel as a Linux process (memory numbers like the VPS's),
  # in a throwaway container e2e-cx-lab-* with the systemd unit's
  # GOMEMLIMIT. Without the Docker socket: projects are read-only.
  dir="$(mktemp -d "${TMPDIR:-/tmp}/hangar-lab-XXXXXX")"
  port="${HANGAR_LAB_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')}"
  name="e2e-cx-lab-$(basename "$dir" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')"
  (cd "$root" && GOOS=linux CGO_ENABLED=0 go build -trimpath -o "$dir/hangard" ./cmd/hangard)
  docker network inspect e2e-cx-labnet >/dev/null 2>&1 ||
    docker network create --subnet 172.31.250.0/24 e2e-cx-labnet >/dev/null
  ip="172.31.250.$((RANDOM % 200 + 20))"
  cat >"$dir/hangar.toml" <<EOF
data_dir = "/lab/data"
master_key_file = "/lab/master.key"

[panel]
listen = ["${ip}:7700"]
hosts = ["127.0.0.1:${port}", "localhost:${port}"]

[update]
api_base = "http://127.0.0.1:9"

[scan]
enabled = false
osv_api = "http://127.0.0.1:9"

[alerts]
telegram_api = "http://127.0.0.1:9"
EOF
  docker run --rm -i -v "$dir:/lab" alpine:3.24.1 /lab/hangard user create -config /lab/hangar.toml \
    -email "$email" -role owner -no-2fa <<<"$(printf '%s\n%s' "$password" "$password")" >/dev/null 2>&1
  docker run -d --name "$name" --network e2e-cx-labnet --ip "$ip" -p "127.0.0.1:${port}:7700" \
    -e GOMEMLIMIT=192MiB -v "$dir:/lab" alpine:3.24.1 /lab/hangard serve -config /lab/hangar.toml >/dev/null
  echo "$name" >"$dir/container"
  for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && break
    sleep 0.2
  done
  echo "DIR=$dir"
  echo "PORT=$port"
  echo "CONTAINER=$name"
  echo "EMAIL=$email"
  echo "PASSWORD=$password"
  ;;
stop)
  dir="${2:?usage: $0 stop DIR}"
  [[ "$dir" == */hangar-lab-* ]] || { echo "not a lab directory: $dir" >&2; exit 1; }
  if [[ -f "$dir/hangard.pid" ]]; then
    kill "$(cat "$dir/hangard.pid")" 2>/dev/null || true
    sleep 1
  fi
  if [[ -f "$dir/container" ]]; then
    docker rm -f "$(cat "$dir/container")" >/dev/null 2>&1 || true
    # The container wrote as root: remove its files from inside.
    docker run --rm -v "$dir:/lab" alpine:3.24.1 rm -rf /lab/data /lab/master.key >/dev/null 2>&1 || true
  fi
  rm -rf "$dir"
  ;;
*)
  echo "usage: $0 start | start-linux | stop DIR" >&2
  exit 2
  ;;
esac
