wasm := "target/wasm32-wasip2/release/component_vnc_desktop.wasm"
# OCI reference to publish to (registry/namespace/name, no tag). Override with OCI_REF.
component_ref := env("OCI_REF", "actpkg.dev/library/vnc-desktop")

act := env("ACT", "npx @actcore/act")
actbuild := env("ACT_BUILD", "npx @actcore/act-build")
hurl := env("HURL", "hurl")
# Random port for the e2e server, in a safe range: above the well-known/common
# dev ports and below the Linux outbound ephemeral range (32768+).
port := `shuf -i 10000-29999 -n 1`
addr := "[::1]:" + port
baseurl := "http://" + addr

# Fetch WIT deps from the registry (ghcr.io/actcore) into wit/deps/.
# wkg-registry.toml maps the act namespace -> actcore.dev (well-known -> ghcr.io/actcore).
init:
    WKG_CONFIG_FILE=wkg-registry.toml wkg wit fetch --type wit

setup: init
    prek install

build:
    cargo build --release

# Embed act:component metadata and act:skill into the wasm.
pack: build
    {{actbuild}} pack {{wasm}}

test: pack
    #!/usr/bin/env bash
    set -euo pipefail
    # CI sets VNC_HOST + VNC_PORT after launching Xvfb + x11vnc
    VNC_HOST="${VNC_HOST:-127.0.0.1}"
    VNC_PORT="${VNC_PORT:-5900}"
    GRANT="{\"wasi:sockets\":{\"mode\":\"allowlist\",\"allow\":[{\"host\":\"$VNC_HOST\",\"ports\":[$VNC_PORT],\"protocols\":[\"tcp\"]}]}}"
    {{act}} run --http --listen "{{addr}}" --grant "$GRANT" {{wasm}} &
    trap "kill $!" EXIT
    curl --retry 60 --retry-connrefused --retry-delay 1 -fsS -o /dev/null {{baseurl}}/info
    {{hurl}} --test \
      --variable "baseurl={{baseurl}}" \
      --variable "vnc_host=$VNC_HOST" \
      --variable "vnc_port=$VNC_PORT" \
      e2e/*.hurl

publish: pack
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} inspect component-manifest {{wasm}})
    VERSION=$(echo "$INFO" | jq -r .std.version)
    OUTPUT=$({{actbuild}} push {{wasm}} "{{component_ref}}:$VERSION" \
      --skip-if-exists \
      --also-tag latest 2>&1) || { echo "$OUTPUT" >&2; exit 1; }
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}' || true)
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{component_ref}}" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi

