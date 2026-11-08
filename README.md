# vnc-desktop

Sandboxed desktop control over the [VNC / RFB](https://datatracker.ietf.org/doc/html/rfc6143) protocol — an ACT component.

This component implements the "computer use" tool surface (screenshots, mouse, keyboard, clipboard) but talks to a *remote* desktop via VNC instead of an OS-level mouse/keyboard injector on the host. The host capabilities it declares are `wasi:sockets` (TCP egress, ports 5900-5909) and `act:credentials` (read one password out of the host's credential store) — auditors can see exactly which `host:port` the agent can reach and which credential it can ask for.

## Tools

| Group | Tool | Notes |
|---|---|---|
| Mouse | `click`, `move_pointer`, `drag`, `scroll` | x/y are absolute screen pixels |
| Keyboard | `type_text`, `key`, `key_down`, `key_up` | `key` accepts combos like `ctrl+shift+a` |
| Screen | `screenshot`, `display_info` | Screenshot returns `image/png` content-part |
| Clipboard | `copy`, `paste` | VNC `ClientCutText` / `ServerCutText` |

All tools require `std:session-id` metadata that identifies the open VNC session.

## Session

The component exports `act:sessions/session-provider@0.2.0`. Open a session with:

```json
{
  "host": "vnc.example.com",
  "port": 5900,
  "credential_key": "default",
  "shared": true
}
```

`port` defaults to 5900; `credential_key` defaults to `"default"`; `shared` defaults to true.

**There is no `password` argument, and there must never be one.** Everything sent to `open-session` is agent-visible plaintext that lands in the transcript and in the host's record of the session. The VNC password lives in the host credential store instead, and the component reads it through `act:credentials/store` — so it never crosses into the agent's context at all.

## The password

One credential, one field, declared in `act.toml`, so `act login` prompts for it with no arguments:

```bash
act login ./component_vnc_desktop.wasm
```

Or set it directly:

```bash
echo '{"vnc:password":"..."}' | act secret set ./component_vnc_desktop.wasm \
    --key default --field vnc:password --fields-stdin
```

`vnc:password` is in this component's own namespace, not `std:`: [`ACT-CONSTANTS.md`](../../act-spec/spec/ACT-CONSTANTS.md) §8 registers field *types*, not field *names*, and `act-build pack` refuses a `std:`-prefixed field key outright.

### When a credential is needed — and when it is not

The store is consulted **only when the server offers the RFB password challenge** (security type 2). A server that offers `None` — `x11vnc -nopw`, a TigerVNC instance behind an SSH tunnel — is driven with no stored credential at all, and no `get-secret`, so no consent prompt appears for a password nobody needs.

| Server offers | Credential stored | What happens |
|---|---|---|
| `None` | either | Connects unauthenticated. The store is never asked. |
| `None` + `VncAuth` | yes | Authenticates. A provisioned credential is used in preference to an anonymous connection. |
| `None` + `VncAuth` | no | Connects unauthenticated — the server itself said that is acceptable. |
| `VncAuth` only | yes | Authenticates. |
| `VncAuth` only | no | `std:credential-required`, naming the `act secret set` command that fixes it. |

A credential that exists but carries no non-empty `vnc:password` is an error even against a server that would have accepted an anonymous connection: somebody provisioned that entry meaning to authenticate with it, and degrading quietly would hide the typo.

### Failures moved to the first tool call

`get-secret` needs a session the host has already marked live, and the host does that only *after* `open-session` returns ([ACT-AUTH](../../act-spec/spec/ACT-AUTH.md) §1.1.4). The RFB handshake picks its security type from what the client can answer with and is not resumable once started, so it cannot be split across the two calls either.

The whole connect — TCP, RFB handshake, authentication — therefore happens on the **first tool call**, and the live connection is cached in the session. An unreachable server, a host the policy refuses, and a rejected password all surface there rather than at `open-session`, and every message on those paths says so. A rejected password also poisons the session: the next call answers from that flag instead of re-fetching the credential, so an `ask` policy does not prompt a human on every call.

## Build

```bash
just init        # fetch WIT deps with wkg (wit/deps/ is gitignored)
just build       # cargo build --release for wasm32-wasip3, then pack
just pack        # re-embed metadata + skill without rebuilding
just test        # e2e: provisions Xvfb + x11vnc and drives `act run --mcp`
```

## Run

```bash
act run component_vnc_desktop.wasm --mcp \
    --grant '{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"vnc.example.com","ports":[5900],"protocols":["tcp"]}]}}' \
    --allow act:credentials
```

`--allow act:credentials` opens a class whose declared ceiling is a bare table, so it grants exactly "may ask this component's own credential profile" and nothing wider. Without it the store is denied outright and a password-protected server is unreachable — an undeclared or ungranted class cannot be widened by anything.

## Why over OS-level computer use

| | OS-level injector | vnc-desktop |
|---|---|---|
| Sandbox | Host process | wasm component |
| Network surface | Anything the agent can dial | Declared `wasi:sockets` only |
| Credentials in the agent's context | Often | Never — fetched host-side via `act:credentials` |
| Remote desktop | Hack | First-class |

This is the *Hardened AI toolchain* positioning made concrete for desktop control.
