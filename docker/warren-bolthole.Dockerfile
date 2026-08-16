# syntax=docker/dockerfile:1
# Minimal warren-bolthole image: one static musl binary on Alpine, no root, no
# NET_ADMIN, no TUN, no capability of any kind. The gateway terminates stock
# WireGuard-protocol peers on a UDP socket and carries their packets through a
# Warren exit in userland, so it needs nothing the kernel would have to grant:
# a compose file that adds `cap_add` or maps /dev/net/tun for THIS container is
# adding privilege the gateway never asks for. Built by
# .github/workflows/release-bolthole.yml, which drops the per-arch static
# binaries under dist/<arch>/ first.

# Pinned by digest, not by tag alone: the same tag is rebuilt under a new
# digest, so a tag-only base makes two builds of one release differ.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
# curl, because the documented port-forward hook shape is a curl into an
# application API (BusyBox wget cannot express it). The state directory holds
# the gateway key, the peer configurations and the admin token, all 0600 under
# a 0700 directory, so it belongs to the unprivileged user and to nothing else
# in the image.
RUN apk add --no-cache ca-certificates curl \
    && adduser -D -H warren \
    && mkdir -p /var/lib/warren-bolthole \
    && chown warren:warren /var/lib/warren-bolthole \
    && chmod 700 /var/lib/warren-bolthole
ARG TARGETARCH
COPY dist/${TARGETARCH}/warren-bolthole /usr/local/bin/warren-bolthole

# Links the GHCR package back to this repository, which is the only way to
# reach the source from a private package page.
LABEL org.opencontainers.image.source="https://github.com/WarrenBrowse/warren-sdk-rs" \
      org.opencontainers.image.description="Local gateway carrying stock WireGuard-protocol clients through a Warren exit, unprivileged" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Container defaults. WARREN_BOLTHOLE_LAN is deliberately NOT set here: binding
# anything but loopback exposes the one hop of the path that is ordinary
# WireGuard rather than Warren's QUIC transport, so it stays an explicit
# decision the operator makes per deployment (`-e WARREN_BOLTHOLE_LAN=1`), and
# until they do the daemon refuses this listen address and says why. The health
# endpoint stays on loopback for the HEALTHCHECK below; the state directory is
# named explicitly because the /var/lib default only applies to a root process.
ENV WARREN_BOLTHOLE_LISTEN=0.0.0.0:51820 \
    WARREN_HEALTH_LISTEN=127.0.0.1:9998 \
    WARREN_BOLTHOLE_STATE_DIR=/var/lib/warren-bolthole

# The peers' private keys and preshared keys live here and are kept nowhere
# else: a container recreated without a named volume mounted on this path
# generates a new gateway key and invalidates every client configuration
# already imported on a TV, a router or a phone.
VOLUME ["/var/lib/warren-bolthole"]

EXPOSE 51820/udp
USER warren
# The gate opens only once an epoch has proven egress, and the first connect is
# allowed WARREN_CONNECT_TIMEOUT (90 s by default) before it is called a
# failure, so a shorter start period would report unhealthy on a gateway that
# is merely still dialling. Docker marks an unhealthy container and does not
# restart it: pair `restart: unless-stopped` with the daemon's own exit codes
# (1 restart, 2 stop), or watch it from outside.
#
# Setting WARREN_HEALTH_LISTEN to `off`, `none` or empty leaves this probe with
# nothing to reach, and it then exits 0 without a daemon running at all: the
# container reports healthy for as long as it exists, and a dependent gated on
# `condition: service_healthy` starts against a gateway that may be dead.
# Disabling the endpoint disables the container health gate with it.
HEALTHCHECK --interval=60s --timeout=15s --start-period=120s --retries=2 \
  CMD ["/usr/local/bin/warren-bolthole", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/warren-bolthole"]
