---
name: vnc-desktop
description: Control a remote desktop over the VNC/RFB protocol — screenshots, mouse, keyboard, clipboard.
act: {}
---

# vnc-desktop

ACT component that drives a remote desktop through the [RFB / VNC](https://datatracker.ietf.org/doc/html/rfc6143) protocol. Every desktop is a *session* — you must `open_session` first, pass `std:session-id` on every subsequent tool call, and `close_session` when you are done.

The only host capability the component declares is `wasi:sockets` (outbound TCP). It does not need filesystem, HTTP, or environment access.

## Opening a session

`open_session` arguments (JSON Schema discoverable via `get_open_session_args_schema`):

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string | — | VNC server hostname or IP |
| `port` | integer | 5900 | TCP port |
| `password` | string | — | VNC auth password; omit for `None` auth |
| `shared` | boolean | true | RFB shared-desktop flag |

Returns `{ "id": "vnc_1", "metadata": [] }`. Use `id` as `std:session-id` on subsequent calls. Authentication uses the legacy 8-byte DES challenge (RFC 6143 §7.2.2); if your server requires anything stronger (TLS-VNC, RA2-NE, …) it is currently out of scope.

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
open_session {host: "10.0.0.5", password: "..."}
  → session-id "vnc_1"
screenshot                                       (std:session-id=vnc_1)
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

The host enforces socket policy on top of the component's declaration. Even with the component declaring `wasi:sockets`, the user has to explicitly grant access — declared rules alone don't open the network. Easiest one-shot for a trusted run:

```bash
act run vnc-desktop.wasm --http --listen 127.0.0.1:3000 --sockets-policy open
```

Or tighten to a single endpoint:

```bash
act run vnc-desktop.wasm --http --listen 127.0.0.1:3000 \
    --allow-socket 10.0.0.5:5900
```

## Response shape

`screenshot` returns a PNG inside the standard ACT-HTTP envelope, not as raw bytes. The HTTP response is `application/json` with body:

```json
{
  "content": [
    { "data": "<base64-PNG>", "mime_type": "image/png" }
  ]
}
```

Decode `content[0].data` from base64 to get the PNG. Verified against krfb (VNC password auth, RFC 6143 §7.2.2 DES challenge) and `x11vnc -nopw` (None auth).

## Limits / caveats

- The MVP supports Raw encoding only. If your VNC server refuses to send Raw (very unusual), the component errors out. CopyRect / Tight / Hextile are out of scope for now.
- We assume the server honours `SetPixelFormat` with 32-bit BGRA. Most modern VNC servers (x11vnc, TigerVNC, MacOS Screen Sharing) do.
- No DesktopSize tracking beyond accepting the resize pseudo-encoding — if the server changes geometry, the next screenshot reflects the new size; ongoing tool args don't get re-validated.
- No screen streaming (`tool-result::streaming`) yet — each screenshot is a complete fetch.
