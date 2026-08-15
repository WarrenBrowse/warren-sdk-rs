# syntax=docker/dockerfile:1
# Minimal warren-proxy image: one static musl binary on Alpine, no root, no
# NET_ADMIN, no TUN. The unprivileged sibling of ghcr.io/warrenbrowse/warren-vpn
# (which owns a netns with a kill switch); this one is a plain proxy endpoint
# other containers point at. Built by .github/workflows/release-proxy.yml,
# which drops the per-arch static binaries under dist/<arch>/ first.

# Pinned by digest, not by tag alone: the same tag is rebuilt under a new
# digest, so a tag-only base makes two builds of one release differ.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
# curl, because the documented port-forward hook shape is a curl into an
# application API (BusyBox wget cannot express it). /run/warren is a writable
# home for WARREN_PORT_FORWARD_STATUS_FILE, whose documented seam is a sibling
# container reading that file: every other path in the image belongs to root.
RUN apk add --no-cache ca-certificates curl \
    && adduser -D -H warren \
    && mkdir -p /run/warren \
    && chown warren:warren /run/warren
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
