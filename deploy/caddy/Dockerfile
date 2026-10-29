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
FROM caddy:2.11-builder-alpine@sha256:ef9b65adf9a224770c6d5f6d1ae1bf99bc3caaa78d8c4bae3ea949ee6984f301 AS builder
# The Caddy release and the Go modules with fixes newer than that release
# are named here, so the edge does not wait for the next official image.
RUN xcaddy build v2.11.7 \
    --with github.com/caddy-dns/cloudflare@v0.2.4 \
    --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
    --replace github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.6 \
    --replace github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@v5.4.0

FROM caddy:2.11-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
# The official image is rebuilt rarely: take the Alpine fixes published
# since (this runs only when this file changes; the release reuses the
# image otherwise).
RUN apk upgrade --no-cache
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
