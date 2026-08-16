#!/usr/bin/env sh
#
# Structural tests for the compose examples in docs/burrow/.
#
#   sh docs/burrow/test-examples.sh
#
# These files are copy-paste templates: whatever they get wrong, users deploy.
# Every property pinned here is one whose absence either exposes the one hop of
# the path that is not Warren, strands a stack that cannot start, or writes a
# credential where it does not belong, and none of them is something a build
# step would ever catch.
#
# Each rule is a function of one file, and each is then run against a mutated
# copy of that same file: a check that cannot fail is not a check, and a
# template nobody deploys broken is exactly where that rots unnoticed.
#
# POSIX shell and awk only, no YAML library: the self-hosted runner that gates
# this repo is not guaranteed to carry ruby or python, and a test that skips
# itself on the machine that runs it is not a gate.

set -eu

DOCS_DIR="$(cd "$(dirname "$0")" && pwd)"
GLUETUN="$DOCS_DIR/docker-compose.gluetun.yml"
PEER="$DOCS_DIR/docker-compose.peer.yml"

checks=0
failures=0
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# The lines of one service's block, so a rule about the gateway cannot be
# satisfied by a line that belongs to gluetun.
svc_block() { # svc_block <file> <service>
	awk -v svc="$2" '
		$0 ~ "^  " svc ":[[:space:]]*$" { inblk = 1; next }
		inblk && /^  [^[:space:]#]/ { inblk = 0 }
		inblk { print }
	' "$1"
}

# The services of a compose file: the two-space keys under `services:`, and not
# the two-space keys of the top-level volumes, networks and secrets blocks.
svc_names() { # svc_names <file>
	awk '
		/^services:[[:space:]]*$/ { insvc = 1; next }
		/^[^[:space:]#]/ { insvc = 0 }
		insvc && /^  [a-z][a-z0-9_-]*:[[:space:]]*$/ {
			sub(/:[[:space:]]*$/, ""); sub(/^  /, ""); print
		}
	' "$1"
}

# The value of `key: value` inside a service block, quotes stripped.
svc_value() { # svc_value <file> <service> <key>
	svc_block "$1" "$2" | awk -v key="$3" '
		$0 ~ "^[[:space:]]+" key ":" {
			sub("^[[:space:]]*" key ":[[:space:]]*", "")
			gsub(/["\047]/, "")
			print
			exit
		}
	'
}

check() { # check <description> <rule> [args...]
	description="$1"
	shift
	checks=$((checks + 1))
	if "$@"; then
		printf '  ok   %s\n' "$description"
	else
		printf '  FAIL %s\n' "$description"
		failures=$((failures + 1))
	fi
}

# Applies a mutation to a copy of the file and asserts the rule refuses it.
# A mutation that changed nothing fails here too, so a rule can never be
# retired by quietly breaking the sed that was supposed to exercise it.
check_refuses() { # check_refuses <description> <sed-expression> <file> <rule>
	description="$1"
	mutation="$2"
	file="$3"
	rule="$4"
	checks=$((checks + 1))
	mutant="$tmpdir/mutant-$checks.yml"
	sed "$mutation" "$file" > "$mutant"
	if cmp -s "$file" "$mutant"; then
		printf '  FAIL %s (the mutation changed nothing)\n' "$description"
		failures=$((failures + 1))
	elif "$rule" "$mutant"; then
		printf '  FAIL %s (the rule accepted the broken file)\n' "$description"
		failures=$((failures + 1))
	else
		printf '  ok   %s\n' "$description"
	fi
}

# --- rules ---------------------------------------------------------------

# The gateway needs no capability and no device: it terminates its peers on a
# UDP socket and reaches the exit in userland. An example that grants either
# teaches an operator to hand privilege to the one container that never asks
# for it.
rule_gateway_unprivileged() {
	! svc_block "$1" warren-burrow | grep -qE '^[[:space:]]+(cap_add|devices|privileged):'
}

# Binding anything but loopback is the decision that exposes the ordinary
# WireGuard hop, so it is made once, visibly, in the file the operator edits.
rule_lan_is_opt_in() {
	svc_block "$1" warren-burrow | grep -qE '^[[:space:]]+WARREN_BURROW_LAN:[[:space:]]*"1"'
}

# The recovery phrase reaches the daemon as a path to a file, never as a value
# a compose file, a shell history or a `docker inspect` can hand out.
rule_mnemonic_by_file() {
	! grep -qE '^[[:space:]]+WARREN_MNEMONIC:' "$1" \
		&& grep -qE '^[[:space:]]+WARREN_MNEMONIC_FILE:[[:space:]]*/' "$1"
}

# A secret compose does not mount into a service is a path that does not exist
# inside it, and the service names that path in its own environment: the daemon
# then fails at startup on a file it was told to read. Compose mounts a secret
# only into the services that list it, and nothing warns when a `secrets:` block
# is edited away from an environment that still points into /run/secrets.
rule_secret_paths_are_mounted() {
	for svc in $(svc_names "$1"); do
		block="$(svc_block "$1" "$svc")"
		referenced="$(printf '%s\n' "$block" | awk '
			{
				line = $0
				while (match(line, /\/run\/secrets\/[A-Za-z0-9_.-]+/)) {
					print substr(line, RSTART + 13, RLENGTH - 13)
					line = substr(line, RSTART + RLENGTH)
				}
			}
		' | sort -u)"
		[ -n "$referenced" ] || continue
		mounted="$(printf '%s\n' "$block" | awk '
			/^[[:space:]]+secrets:[[:space:]]*$/ { inlist = 1; next }
			inlist && /^[[:space:]]+[a-z_]+:/ { inlist = 0 }
			inlist && /^[[:space:]]+- / { sub(/^[[:space:]]+-[[:space:]]*/, ""); print }
		' | sort -u)"
		# Not `name`: a shell function shares the caller's scope, and `name`
		# is the file the check loop below is reporting on.
		for secret in $referenced; do
			printf '%s\n' "$mounted" | grep -qx "$secret" || return 1
		done
	done
}

# The gateway's peers are containers on the docker network or devices on the
# LAN, never anything inside its own network namespace, so a loopback listen
# address answers nobody. Nothing downstream catches it: the daemon starts, the
# gate opens on its egress proof, the container reports healthy, and every peer
# handshakes with silence until somebody reads a packet counter.
rule_listen_is_not_loopback() {
	svc_value "$1" warren-burrow WARREN_BURROW_LISTEN \
		| grep -qvE '^(127\.|\[?::1\]?:|localhost:)'
}

# Publishing the gateway's UDP port puts the one hop that is plain WireGuard on
# every network the host sits on, which is what the obfuscation boundary is
# about, so no example does it and every example says why.
rule_udp_port_not_published() {
	! awk '
		/^[[:space:]]+ports:/ { inports = 1; if ($0 ~ /51820/) found = 1; next }
		inports && /^[[:space:]]+[a-z_]+:/ { inports = 0 }
		inports && /51820/ { found = 1 }
		END { exit(found ? 0 : 1) }
	' "$1" && grep -qE '^[[:space:]]*#.*51820' "$1" && grep -qE '^[[:space:]]*#.*publish' "$1"
}

# The peers' private keys and preshared keys live in the state directory and
# nowhere else. A container recreated without this volume generates a new
# gateway key and invalidates every configuration already imported on a device
# somebody has to walk to.
rule_named_state_volume() {
	svc_block "$1" warren-burrow \
		| grep -qE '^[[:space:]]+- [a-z][a-z0-9_-]*:/var/lib/warren-burrow'
}

# The health gate opens only once an epoch has proven egress, and the first
# connect is allowed WARREN_CONNECT_TIMEOUT before it is called a failure. A
# shorter start period reports unhealthy on a gateway that is merely still
# dialling, and everything that waits for it gives up.
rule_start_period_covers_connect_timeout() {
	start="$(svc_block "$1" warren-burrow | awk '
		/^[[:space:]]+start_period:/ {
			sub(/^[[:space:]]*start_period:[[:space:]]*/, "")
			gsub(/[^0-9]/, "")
			print
			exit
		}
	')"
	connect="$(svc_value "$1" warren-burrow WARREN_CONNECT_TIMEOUT)"
	[ -n "$start" ] && [ -n "$connect" ] && [ "$start" -ge "$connect" ]
}

# gluetun's own startup check dials a public host seconds after it comes up and
# restarts its VPN when that fails, so a client that starts before the gate is
# open spends its first minute restart-looping.
rule_dependents_wait_for_healthy() {
	awk '
		/^  [^[:space:]#]/ { indeps = 0 }
		indeps && /^    [a-z_]+:/ { indeps = 0 }
		/^[[:space:]]+depends_on:/ { indeps = 1; next }
		indeps && /warren-burrow:/ { seen = 1; next }
		indeps && seen && /condition:[[:space:]]*service_healthy/ { healthy++; seen = 0 }
		indeps && seen && /^[[:space:]]+[a-z_-]+:/ { seen = 0 }
		END { exit(healthy > 0 ? 0 : 1) }
	' "$1"
}

# gluetun refuses a hostname for WIREGUARD_ENDPOINT_IP, and a compose service
# name is a hostname. The literal has to be the address the gateway holds on
# this network, which is why that address is fixed rather than assigned by
# docker in whatever order the containers happened to start.
rule_literal_endpoint_matches_gateway() {
	endpoint="$(svc_value "$1" gluetun WIREGUARD_ENDPOINT_IP)"
	gateway="$(svc_block "$1" warren-burrow | awk '
		/^[[:space:]]+ipv4_address:/ {
			sub(/^[[:space:]]*ipv4_address:[[:space:]]*/, "")
			gsub(/[^0-9.]/, "")
			print
			exit
		}
	')"
	echo "$endpoint" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
		&& [ "$endpoint" = "$gateway" ]
}

# A fixed subnet is what makes that literal address reservable at all.
rule_fixed_subnet() {
	grep -qE '^[[:space:]]+- subnet: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$1"
}

# gluetun falls back to wireguard-go on a kernel without the module, and
# wireguard-go needs the TUN device. This is the container that gets the
# privilege, not the gateway.
rule_client_has_tun_device() {
	svc_block "$1" gluetun | grep -q '/dev/net/tun'
}

# Compose mounts a file secret with the ownership it has on the host and ignores
# the uid/gid/mode keys outside swarm, so a recovery phrase written by root and
# left 0600 is one the gateway (uid 1000) cannot read. The daemon says so at
# startup, and the file that hands out the recipe has to hand out that line too.
rule_secret_ownership_documented() {
	grep -qE '^[[:space:]]*#.*chown 1000:1000' "$1"
}

# The gateway of a LAN device is reachable at a LAN address, and a compose file
# that defaults an unset one to the empty string starts a daemon bound to
# nothing anybody can reach.
rule_lan_address_is_required() {
	grep -qE '\$\{WARREN_LAN_IP:\?' "$1"
}

# --- the examples ---------------------------------------------------------

for file in "$GLUETUN" "$PEER"; do
	if [ ! -f "$file" ]; then
		printf '  FAIL missing example: %s\n' "$file"
		checks=$((checks + 1))
		failures=$((failures + 1))
	fi
done
[ "$failures" -eq 0 ] || {
	printf '\n%d checks, %d failure(s)\n' "$checks" "$failures"
	exit 1
}

echo "every example"
for file in "$GLUETUN" "$PEER"; do
	name="$(basename "$file")"
	check "$name: the gateway gets no capability and no device" rule_gateway_unprivileged "$file"
	check "$name: LAN exposure is an explicit opt-in" rule_lan_is_opt_in "$file"
	check "$name: the recovery phrase is a file path, never a literal" rule_mnemonic_by_file "$file"
	check "$name: every secret an environment points at is mounted into that service" rule_secret_paths_are_mounted "$file"
	check "$name: the gateway does not listen on loopback" rule_listen_is_not_loopback "$file"
	check "$name: the gateway's UDP port is not published, and the file says why" rule_udp_port_not_published "$file"
	check "$name: the state directory is a named volume" rule_named_state_volume "$file"
	check "$name: the health start period covers the connect timeout" rule_start_period_covers_connect_timeout "$file"
	check "$name: the secret's ownership requirement is written down" rule_secret_ownership_documented "$file"
done

echo "the gluetun stack"
check "a client waits for a healthy gateway" rule_dependents_wait_for_healthy "$GLUETUN"
check "the endpoint is a literal address, and it is the gateway's" rule_literal_endpoint_matches_gateway "$GLUETUN"
check "the network has a fixed subnet" rule_fixed_subnet "$GLUETUN"
check "the client, not the gateway, holds the TUN device" rule_client_has_tun_device "$GLUETUN"

echo "the plain-peer gateway"
check "the LAN address has no empty default" rule_lan_address_is_required "$PEER"

echo "each rule, against a file that breaks it"
check_refuses "a gateway granted NET_ADMIN" \
	's|^    restart: unless-stopped$|    cap_add: [NET_ADMIN]|' "$GLUETUN" rule_gateway_unprivileged
check_refuses "LAN exposure left at the default" \
	's|WARREN_BURROW_LAN: "1"|WARREN_BURROW_LAN: "0"|' "$GLUETUN" rule_lan_is_opt_in
check_refuses "the recovery phrase written into the file" \
	's|WARREN_MNEMONIC_FILE: /run/secrets/warren_mnemonic|WARREN_MNEMONIC: twelve words go here|' \
	"$GLUETUN" rule_mnemonic_by_file
check_refuses "a secret the service no longer mounts" \
	's|^      - warren_mnemonic$|      - some_other_secret|' "$GLUETUN" rule_secret_paths_are_mounted
check_refuses "a gateway bound to loopback with LAN exposure still on" \
	's|WARREN_BURROW_LISTEN: 0.0.0.0:51820|WARREN_BURROW_LISTEN: 127.0.0.1:51820|' \
	"$GLUETUN" rule_listen_is_not_loopback
check_refuses "the UDP port published to the host" \
	's|^    healthcheck:$|    ports: ["51820:51820/udp"]|' "$GLUETUN" rule_udp_port_not_published
check_refuses "an anonymous state volume" \
	's|- warren-burrow-state:/var/lib/warren-burrow|- /var/lib/warren-burrow|' \
	"$GLUETUN" rule_named_state_volume
check_refuses "a start period shorter than the connect timeout" \
	's|start_period: 120s|start_period: 30s|' "$GLUETUN" rule_start_period_covers_connect_timeout
check_refuses "the ownership recipe dropped from the secret" \
	's|chown 1000:1000|chmod 600|' "$PEER" rule_secret_ownership_documented
check_refuses "a client that starts as soon as the gateway exists" \
	's|condition: service_healthy|condition: service_started|' "$GLUETUN" rule_dependents_wait_for_healthy
check_refuses "an endpoint given as a service name" \
	's|WIREGUARD_ENDPOINT_IP: "172.30.0.10"|WIREGUARD_ENDPOINT_IP: "warren-burrow"|' \
	"$GLUETUN" rule_literal_endpoint_matches_gateway
check_refuses "an endpoint that is not the gateway's address" \
	's|WIREGUARD_ENDPOINT_IP: "172.30.0.10"|WIREGUARD_ENDPOINT_IP: "172.30.0.11"|' \
	"$GLUETUN" rule_literal_endpoint_matches_gateway
check_refuses "a network docker addresses as it pleases" \
	's|^        - subnet: |        # - subnet: |' "$GLUETUN" rule_fixed_subnet
check_refuses "a client without the TUN device" \
	's|^      - /dev/net/tun:/dev/net/tun$|      []|' "$GLUETUN" rule_client_has_tun_device
check_refuses "a LAN address defaulting to nothing" \
	's|\${WARREN_LAN_IP:?[^}]*}|${WARREN_LAN_IP}|' "$PEER" rule_lan_address_is_required

printf '\n%d checks, %d failure(s)\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
