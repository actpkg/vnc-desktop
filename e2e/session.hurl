# End-to-end smoke test against a real VNC server.
#
# Justfile / CI sets VNC_HOST + VNC_PORT and starts `act run --http
# --sockets-policy open` against the packed component first. The server
# must accept None or VNC password auth; CI uses `x11vnc -nopw`, local
# runs may use krfb with a password (pass `--variable vnc_password=...`).

# 1. /info — confirm the wasm reports vnc-desktop with sockets-only.
GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$.std.name" == "vnc-desktop"
jsonpath "$.std.capabilities['wasi:sockets']" exists

# 2. Open a session.
POST {{baseurl}}/sessions
Content-Type: application/json
{
  "arguments": {
    "host": "{{vnc_host}}",
    "port": {{vnc_port}}
  }
}
HTTP 201
[Captures]
session_id: jsonpath "$.id"

# 3. Display info — confirms the RFB handshake completed.
POST {{baseurl}}/tools/display_info
Content-Type: application/json
{
  "arguments": {},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200
[Asserts]
jsonpath "$.content[0].mime_type" == "application/cbor"
jsonpath "$.content[0].data.width" >= 100
jsonpath "$.content[0].data.height" >= 100

# 4. Screenshot returns an image/png inside the content-part envelope.
# ACT-HTTP wraps the bytes as base64 in JSON when the response is the
# default JSON envelope (one content-part with mime image/png).
POST {{baseurl}}/tools/screenshot
Content-Type: application/json
{
  "arguments": {},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200
[Asserts]
jsonpath "$.content[0].mime_type" == "image/png"
# Base64-encoded PNG signature: `iVBORw0KGgo` is `\x89PNG\r\n\x1a\n` in b64.
jsonpath "$.content[0].data" startsWith "iVBORw0KGgo"

# 5. Mouse — move + click. We don't observe the remote effect here; we
# just confirm the tool calls return without error.
POST {{baseurl}}/tools/move_pointer
Content-Type: application/json
{
  "arguments": {"x": 0, "y": 0},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200

POST {{baseurl}}/tools/click
Content-Type: application/json
{
  "arguments": {"x": 0, "y": 0},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200

# 6. Keyboard.
POST {{baseurl}}/tools/type_text
Content-Type: application/json
{
  "arguments": {"text": "hello"},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200

POST {{baseurl}}/tools/key
Content-Type: application/json
{
  "arguments": {"combo": "ctrl+a"},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200

# 7. Clipboard write (no Ctrl+V, so we don't paste anywhere visible).
POST {{baseurl}}/tools/paste
Content-Type: application/json
{
  "arguments": {"text": "hello from act", "send_ctrl_v": false},
  "metadata": { "std:session-id": "{{session_id}}" }
}
HTTP 200

# 8. Close.
DELETE {{baseurl}}/sessions/{{session_id}}
HTTP 204
