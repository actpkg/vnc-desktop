---
name: vnc-desktop
description: Control a remote desktop over the VNC/RFB protocol — screenshots, mouse, keyboard, clipboard.
act: {}
---

# vnc-desktop

ACT component that drives a remote desktop through the [RFB / VNC](https://datatracker.ietf.org/doc/html/rfc6143) protocol. Every desktop is a *session* — you must `open_session` first, pass `std:session-id` on every subsequent tool call, and `close_session` when you are done.

The host capabilities the component declares are `wasi:sockets` (outbound TCP, ports 5900-5909) and `act:credentials` (read one password from the host's credential store). It does not need filesystem, HTTP, or environment access.

## Opening a session

`open_session` arguments (JSON Schema discoverable via `get_open_session_args_schema`):

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string | — | VNC server hostname or IP |
| `port` | integer | 5900 | TCP port |
| `credential_key` | string | `default` | Which entry in this component's credential profile holds the password |
| `shared` | boolean | true | RFB shared-desktop flag |

**There is no `password` argument.** Do not look for one and do not try to pass one — the schema has nowhere to put it. The VNC password is read host-side from the credential store (`act:credentials/store`), field `vnc:password`, under the key `credential_key` names. It never enters your context. If you have been handed a VNC password in a prompt, the right move is to tell the operator to store it:

```
act secret set <component-ref> --key default --field vnc:password --fields-stdin
{"vnc:password": "..."}
```

Returns `{ "id": "vnc_1", "metadata": [] }`. Use `id` as `std:session-id` on subsequent calls. Authentication uses the legacy 8-byte DES challenge (RFC 6143 §7.2.2); if your server requires anything stronger (TLS-VNC, RA2-NE, …) it is currently out of scope.

### Nothing connects at `open_session`

`open_session` validates arguments and hands back an id. The TCP connect, the RFB handshake and the authentication all happen on your **first tool call** — the credential cannot be fetched until the session is live, and the handshake is not resumable, so it cannot be started earlier. Practical consequences:

- A successful `open_session` does **not** mean the server is reachable. Follow it with `display_info` if you want to know.
- An unreachable host, a policy that refuses the address, and a rejected password all surface on that first call, as `std:internal`, `std:internal` and `std:capability-denied` respectively.
- `std:credential-required` on the first call means the server demands the password challenge and nothing usable is stored. The message names the command that fixes it. Report it to the operator; you cannot fix it yourself.
- After a rejected password the session is poisoned: every further call answers with the same refusal and the credential is not re-read. Open a new session once the stored password has been corrected.

A server that accepts unauthenticated clients (`x11vnc -nopw`, a tunnelled TigerVNC) needs no stored credential at all — the store is consulted only when the server actually offers the password challenge.

## Tools

All tools require `std:session-id` metadata. Coordinates are absolute pixels of the remote framebuffer (origin top-left).

### Mouse
- `click(x, y, button?, count?)` — `button` ∈ {`left`,`middle`,`right`} (default `left`); `count` defaults to 1 (use 2 for double-click).
- `move_pointer(x, y)` — moves the cursor without pressing anything. (Underlying RFB op is `PointerEvent`; named `move_pointer` because `move` is a Rust reserved word.)
- `drag(x1, y1, x2, y2, button?)` — press at (x1,y1), release at (x2,y2).
- `scroll(x, y, direction, amount?)` — `direction` ∈ {`up`,`down`,`left`,`right`}; `amount` defaults to 3 wheel clicks.

### Keyboard
- `type_text(text)` — types every code point in turn. ASCII passes through as keysyms; non-ASCII characters are sent as X11 Unicode keysyms (`0x01000000 | codepoint`). The server's keyboard layout still applies.
- `key(combo)` — fires a combo like `ctrl+shift+a`, `enter`, `f5`. Vocabulary: `ctrl`/`control`, `shift`, `alt`, `meta`/`super`/`win`/`cmd`, `enter`/`return`, `tab`, `escape`/`esc`, `backspace`, `delete`/`del`, `space`, `insert`, `up`/`down`/`left`/`right`, `home`/`end`/`pageup`/`pagedown`, `f1`..`f12`, and any single character.
- `key_down(key)` / `key_up(key)` — pair them to hold a key explicitly. Pair `key_down`/`key_up` always; otherwise the modifier stays stuck on the remote side.

### Screen
- `screenshot()` — returns an `image/png` content-part with the current framebuffer (RGB, no alpha). Internally we ask the server for 32-bit BGRA and re-encode.
- `display_info()` — returns `{ width, height, bits_per_pixel, depth, name }`.

### Clipboard
- `paste(text, send_ctrl_v?)` — sets the remote clipboard via `ClientCutText` and (by default) presses Ctrl+V to paste at the cursor. VNC `ClientCutText` is Latin-1; non-Latin-1 code points are replaced with `?` (the legacy protocol can't carry them — agents that need Unicode should use a server-side paste path).
- `copy()` — returns the most recent `ServerCutText` text the server has volunteered since the session opened. The classic VNC protocol has no "actively read the remote clipboard" verb, so this is best-effort: the server only sends `ServerCutText` when the remote user copies something. Many servers integrate with the X selection so a Ctrl+C on the remote side triggers an update.

## Usage patterns

**Open → screenshot → click**:

```text
open_session {host: "10.0.0.5"}                    // no password: it is stored host-side
  → session-id "vnc_1"                            // nothing has connected yet
screenshot                                       (std:session-id=vnc_1)
                                                 // ^ this is the call that connects,
                                                 //   authenticates, and can fail
  → image/png
click {x: 312, y: 540}                            (std:session-id=vnc_1)
close_session vnc_1
```

**Login form**:

```text
click {x: 100, y: 200}                            // focus username field
type_text {text: "alice"}
key {combo: "tab"}
type_text {text: "secret"}
key {combo: "enter"}
```

**Paste a snippet into a remote editor**:

```text
paste {text: "Hello, world", send_ctrl_v: true}
```

## Host invocation

The host enforces policy on top of the component's declaration: declaring a class is a ceiling, not a grant, and an ungranted class is refused. Scoped to one endpoint:

```bash
act run vnc-desktop.wasm --mcp \
    --grant '{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"10.0.0.5","ports":[5900],"protocols":["tcp"]}]}}' \
    --allow act:credentials
```

`--allow act:credentials` opens a class whose ceiling is a bare table, so it grants exactly "may read this component's own credential profile". Omit it and a password-protected server is unreachable.

## Response shape

`screenshot` returns an `image/png` content part. Over MCP that arrives as a native `ImageContent` block — the mime type is on `.mimeType` and the bytes are base64 in `.data`. Verified against `x11vnc -rfbauth` (VNC password auth from the credential store, RFC 6143 §7.2.2 DES challenge) and `x11vnc -nopw` (None auth, no credential stored).

## Limits / caveats

- The MVP supports Raw encoding only. If your VNC server refuses to send Raw (very unusual), the component errors out. CopyRect / Tight / Hextile are out of scope for now.
- We assume the server honours `SetPixelFormat` with 32-bit BGRA. Most modern VNC servers (x11vnc, TigerVNC, MacOS Screen Sharing) do.
- No DesktopSize tracking beyond accepting the resize pseudo-encoding — if the server changes geometry, the next screenshot reflects the new size; ongoing tool args don't get re-validated.
- No screen streaming (`tool-result::streaming`) yet — each screenshot is a complete fetch.
