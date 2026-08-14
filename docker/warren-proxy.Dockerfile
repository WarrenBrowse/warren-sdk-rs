# syntax=docker/dockerfile:1
# Minimal warren-proxy image: one static musl binary on Alpine, no root, no
# NET_ADMIN, no TUN. The unprivileged sibling of ghcr.io/warrenbrowse/warren-vpn
# (which owns a netns with a kill switch); this one is a plain proxy endpoint
# other containers point at. Built by .github/workflows/release-proxy.yml,
# which drops the per-arch static binaries under dist/<arch>/ first.

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H warren
ARG TARGETARCH
COPY dist/${TARGETARCH}/warren-proxy /usr/local/bin/warren-proxy

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
