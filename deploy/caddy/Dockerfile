# Caddy for the Hangar edge, built with the DNS provider modules needed for
# DNS-01 wildcard certificates (docs/28). The stock caddy image cannot do
# DNS-01, so Level 2 (base_domain + dns_token) needs this image. The release
# builds and publishes it (ghcr.io/juniorcarlini/hangar-caddy) and bakes its
# digest into the binary, which pulls it by digest.
#
# Build locally and point the edge at it:
#   docker build -t hangar-caddy:2.11 deploy/caddy
#   # hangar.toml: [edge] image = "hangar-caddy:2.11"
#
# Everything is pinned on purpose. The base images are pinned by digest so the
# built image's own digest stays stable across releases — the edge container is
# recreated only when this file actually changes, not on every update. To bump
# Caddy, update both digests to the new tag's digest and the module versions
# below; to add a DNS provider, add a --with line with its pinned caddy-dns
# module and list the provider in edge.DNSProviders.
FROM caddy:2.11-builder-alpine@sha256:d6161a2c82fd58b3205048958fb6246d0c5d892beee8a47e90944610c4efd100 AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@v0.2.1

FROM caddy:2.11-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
