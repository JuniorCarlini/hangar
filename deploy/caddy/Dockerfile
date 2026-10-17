# Caddy for the Hangar edge, built with the DNS provider modules needed for
# DNS-01 wildcard certificates (docs/28). The stock caddy image cannot do
# DNS-01, so Level 2 (base_domain + dns_token) needs this image.
#
# Build and point the edge at it:
#   docker build -t hangar-caddy:2.11 deploy/caddy
#   # hangar.toml: [edge] image = "hangar-caddy:2.11"
#
# Versions are pinned on purpose (no @latest): keep them on the newest stable
# patch and bump deliberately. To add a provider, add another --with line
# with its pinned caddy-dns module.
FROM caddy:2.11-builder-alpine AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@v0.2.1

FROM caddy:2.11-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
