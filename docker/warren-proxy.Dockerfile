# syntax=docker/dockerfile:1
# Minimal warren-proxy image: one static musl binary on Alpine, no root, no
# NET_ADMIN, no TUN. The unprivileged sibling of ghcr.io/warrenbrowse/warren-vpn
# (which owns a netns with a kill switch); this one is a plain proxy endpoint
# other containers point at. Built by .github/workflows/release-proxy.yml,
# which drops the per-arch static binaries under dist/<arch>/ first.

FROM alpine:3.22
# curl, because the documented port-forward hook shape is a curl into an
# application API (BusyBox wget cannot express it).
RUN apk add --no-cache ca-certificates curl && adduser -D -H warren
ARG TARGETARCH
COPY dist/${TARGETARCH}/warren-proxy /usr/local/bin/warren-proxy

# Links the GHCR package back to this repository, which is the only way to
# reach the source from a private package page.
LABEL org.opencontainers.image.source="https://github.com/WarrenBrowse/warren-sdk-rs" \
      org.opencontainers.image.description="Headless Warren proxy daemon (SOCKS5 / HTTP CONNECT), unprivileged" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Container defaults: listeners on the container interface (reachable by
# compose neighbours; the image is expected to run on an internal network),
# health endpoint loopback for the HEALTHCHECK.
ENV WARREN_SOCKS_LISTEN=0.0.0.0:1080 \
    WARREN_HTTP_LISTEN=0.0.0.0:8888 \
    WARREN_HEALTH_LISTEN=127.0.0.1:9999

EXPOSE 1080 8888
USER warren
HEALTHCHECK --interval=60s --timeout=15s --start-period=120s --retries=2 \
  CMD ["/usr/local/bin/warren-proxy", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/warren-proxy"]
