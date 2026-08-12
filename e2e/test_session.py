"""End-to-end smoke test against a real VNC server — the session.hurl flow.

`client`/`session`/`session_meta` (conftest.py) provision the server, open
one session, and pass its id through every call, matching the original
hurl file's single `session_id` reused across the whole script.
"""

import json
import subprocess


def test_manifest_name_and_sockets_capability(act_command, wasm_path):
    """session.hurl's own step 1 — confirms sockets-only capabilities before
    opening a session against a live VNC server."""
    out = subprocess.run(
        [*act_command, "inspect", "component-manifest", str(wasm_path)],
        capture_output=True, text=True, check=True,
    ).stdout
    manifest = json.loads(out)
    assert manifest["std"]["name"] == "vnc-desktop"
    assert "wasi:sockets" in manifest["std"]["capabilities"]


async def test_session_lifecycle(client, session_meta):
    # 3. Display info — confirms the RFB handshake completed.
    di = await client.call_tool("display_info", {"_meta": session_meta})
    assert di.content[0].meta["dev.actcore/mime-type"] == "application/cbor"
    assert di.structured_content["width"] >= 100
    assert di.structured_content["height"] >= 100

    # 4. Screenshot returns an image/png content part. Over MCP this arrives
    # as a native ImageContent block: the mime type lives on `.mimeType`,
    # not in `_meta["dev.actcore/mime-type"]` — that channel is only used
    # for content whose MCP type carries no type of its own (text blocks).
    # Measured against a real server, not assumed from a mapping table.
    sc = await client.call_tool("screenshot", {"_meta": session_meta})
    assert sc.content[0].mimeType == "image/png"
    # PNG signature `\x89PNG\r\n\x1a\n`, base64-encoded.
    assert sc.content[0].data.startswith("iVBORw0KGgo")

    # 5. Mouse — move + click. The original hurl file doesn't observe the
    # remote effect either; it only confirms the calls return without
    # error, which is the bar kept here.
    move = await client.call_tool("move_pointer", {"x": 0, "y": 0, "_meta": session_meta})
    assert not move.is_error
    click = await client.call_tool("click", {"x": 0, "y": 0, "_meta": session_meta})
    assert not click.is_error

    # 6. Keyboard.
    typed = await client.call_tool("type_text", {"text": "hello", "_meta": session_meta})
    assert not typed.is_error
    keyed = await client.call_tool("key", {"combo": "ctrl+a", "_meta": session_meta})
    assert not keyed.is_error

    # 7. Clipboard write (no Ctrl+V, so nothing pastes anywhere visible).
    pasted = await client.call_tool("paste", {
        "text": "hello from act", "send_ctrl_v": False, "_meta": session_meta,
    })
    assert not pasted.is_error

    # 8. Close happens in the `session` fixture's teardown.
