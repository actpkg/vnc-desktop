wasm := "target/wasm32-wasip2/release/component_vnc_desktop.wasm"
# OCI reference to publish to (registry/namespace/name, no tag). Override with OCI_REF.
component_ref := env("OCI_REF", "actpkg.dev/library/vnc-desktop")

act := env("ACT", "npx @actcore/act")
actbuild := env("ACT_BUILD", "npx @actcore/act-build")
hurl := env("HURL", "npx @orangeopensource/hurl")
# Random port for the e2e server, in a safe range: above the well-known/common
# dev ports and below the Linux outbound ephemeral range (32768+).
port := `shuf -i 10000-29999 -n 1`
addr := "[::1]:" + port
baseurl := "http://" + addr

init:
    wit-deps

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
    {{act}} run --http --listen "{{addr}}" --sockets-allow "$VNC_HOST:$VNC_PORT" {{wasm}} &
    trap "kill $!" EXIT
    npx wait-on -t 180s {{baseurl}}/info
    {{hurl}} --test \
      --variable "baseurl={{baseurl}}" \
      --variable "vnc_host=$VNC_HOST" \
      --variable "vnc_port=$VNC_PORT" \
      e2e/*.hurl

publish: pack
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} info {{wasm}} --format json)
    VERSION=$(echo "$INFO" | jq -r .version)
    SOURCE=$(git remote get-url origin 2>/dev/null | sed 's/\.git$//' | sed 's|git@github.com:|https://github.com/|' || echo "")
    OUTPUT=$({{actbuild}} push {{wasm}} "{{component_ref}}:$VERSION" \
      --skip-if-exists \
      --also-tag latest \
      --source "$SOURCE" 2>&1) || { echo "$OUTPUT" >&2; exit 1; }
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}' || true)
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{component_ref}}" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi

