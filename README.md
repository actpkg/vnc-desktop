# vnc-desktop

Sandboxed desktop control over the [VNC / RFB](https://datatracker.ietf.org/doc/html/rfc6143) protocol — an ACT component.

This component implements the "computer use" tool surface (screenshots, mouse, keyboard, clipboard) but talks to a *remote* desktop via VNC instead of an OS-level mouse/keyboard injector on the host. The only host capability declared is `wasi:sockets` (TCP egress) — auditors can see exactly which host:port the agent can reach.

## Tools

| Group | Tool | Notes |
|---|---|---|
| Mouse | `click`, `move`, `drag`, `scroll` | x/y are absolute screen pixels |
| Keyboard | `type`, `key`, `key_down`, `key_up` | `key` accepts combos like `ctrl+shift+a` |
| Screen | `screenshot`, `display_info` | Screenshot returns `image/png` content-part |
| Clipboard | `copy`, `paste` | VNC `ClientCutText` / `ServerCutText` |

All tools require `std:session-id` metadata that identifies the open VNC session.

## Session

The component exports `act:sessions/session-provider@0.1.0`. Open a session with:

```json
{
  "host": "vnc.example.com",
  "port": 5900,
  "password": "secret",
  "shared": true
}
```

`port` defaults to 5900; `password` is optional (None auth is used when absent); `shared` defaults to true.

## Build

```bash
just init        # wit-deps fetch
just build       # cargo build --release for wasm32-wasip2
just pack        # embed metadata + skill into act:component custom section
```

## Run

```bash
act run components/vnc-desktop/component.wasm --mcp \
    --sockets-allow vnc.example.com:5900
```

## Why over OS-level computer use

| | OS-level injector | vnc-desktop |
|---|---|---|
| Sandbox | Host process | wasm component |
| Network surface | Anything the agent can dial | Declared `wasi:sockets` only |
| Credentials in logs | Often | Never (VNC password lives in session args) |
| Remote desktop | Hack | First-class |

This is the *Hardened AI toolchain* positioning made concrete for desktop control.
