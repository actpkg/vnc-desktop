"""The VNC password is not an argument — and it is not always needed.

Three properties, driven end to end rather than argued for:

1. `open_session`'s published schema offers nowhere to put a password.
2. Against a server that accepts unauthenticated clients (`x11vnc -nopw`,
   what `conftest.vnc_server` provisions), the component works with **no
   credential store configured at all** — the store is consulted only when
   the server offers the password challenge, so nothing is prompted for and
   nothing is missing.
3. Against a server that demands the challenge (`x11vnc -rfbauth`, which
   offers security type `2` and nothing else, measured), the first tool call
   fails with `std:credential-required` when nothing is stored, and succeeds
   once `act secret set` has written the password into a file-backed store.

Property 3 also pins where the failure now surfaces: `open_session` succeeds
in both cases, because nothing connects until the first tool call.
"""

import asyncio
import json
import os
import socket
import subprocess
import time
from contextlib import AsyncExitStack
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Deliberately not imported from `conftest`: that import only resolves when
# the test directory happens to be on `sys.path`, which conftest's own
# docstring says not to rely on. Both values mirror the ones there.
CONNECT_TIMEOUT = 120
LOG_FILE = Path(".pytest-act-stderr.log")

# A display and port of its own, so this module cannot disturb — or be
# disturbed by — the shared unauthenticated server on :99 / 5900. 5901 is
# inside the component's declared ceiling (act.toml allows 5900-5909).
AUTH_DISPLAY = ":98"
AUTH_HOST = "127.0.0.1"
AUTH_PORT = 5901
PASSWORD = "s3cr3t-vnc"


def _wait_for_port(host: str, port: int, attempts: int = 60, delay: float = 0.5) -> None:
    """Block until `host:port` accepts a TCP connection — the same curl-retry
    equivalent conftest uses, kept local for the same reason the constants are."""
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except OSError as e:
            last_err = e
        time.sleep(delay)
    pytest.fail(f"{host}:{port} never accepted a connection: {last_err}")


@pytest.fixture(scope="module")
def authenticated_vnc(tmp_path_factory) -> tuple[str, int]:
    """An `x11vnc` that demands the RFB password challenge.

    Measured, not assumed: an `x11vnc -rfbauth` server answers the security
    handshake with the single type `[2]` — VNC Auth and nothing else — so it
    is the case where a missing credential must be an error rather than a
    fallback to an anonymous connection.
    """
    root = tmp_path_factory.mktemp("vncauth")
    passfile = root / "vncpass"
    subprocess.run(
        ["x11vnc", "-storepasswd", PASSWORD, str(passfile)],
        check=True, capture_output=True,
    )

    # Same Wayland-stripping as conftest.vnc_server: x11vnc autodetects a
    # Wayland session ahead of the X11 DISPLAY it is told to use and refuses
    # to start against Xvfb otherwise.
    env = {k: v for k, v in os.environ.items()
           if k not in ("WAYLAND_DISPLAY", "XDG_SESSION_TYPE")}
    env["DISPLAY"] = AUTH_DISPLAY

    xvfb = subprocess.Popen(
        ["Xvfb", AUTH_DISPLAY, "-screen", "0", "800x600x24", "-nolisten", "tcp"],
    )
    try:
        for _ in range(40):
            if subprocess.run(["xdpyinfo"], env=env, capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"Xvfb {AUTH_DISPLAY} never became ready")

        subprocess.run(
            ["x11vnc", "-display", AUTH_DISPLAY, "-rfbauth", str(passfile),
             "-rfbport", str(AUTH_PORT), "-localhost", "-listen", AUTH_HOST,
             "-forever", "-shared", "-bg"],
            env=env, check=True, capture_output=True,
        )
        _wait_for_port(AUTH_HOST, AUTH_PORT)
        yield AUTH_HOST, AUTH_PORT
    finally:
        xvfb.terminate()
        xvfb.wait(timeout=5)
        # -bg daemonizes: not a child of this process, so kill it by the
        # command line that started it rather than wait()ing on a handle.
        subprocess.run(["pkill", "-f", f"x11vnc -display {AUTH_DISPLAY}"], check=False)


@pytest.fixture(scope="module")
def credential_store(act_command: list[str], wasm_path: Path, tmp_path_factory) -> str:
    """A `--credentials-backend` argument naming a store holding the VNC
    password under the key vnc-desktop looks for by default.

    Naming the field is not optional: `act secret set` has no default field
    set — a credential IS its named fields — which is exactly what the
    component's own refusal messages print.
    """
    # The only skip: this CLI has no credential store, so the feature under
    # test does not exist here. Everything past this line is a regression.
    probe = subprocess.run([*act_command, "secret", "--help"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("this `act` has no credential store (`act secret`); nothing to drive")

    backend = f"file:{tmp_path_factory.mktemp('credentials')}"
    written = subprocess.run(
        [*act_command, "secret", "set", str(wasm_path), "--key", "default",
         "--field", "vnc:password", "--fields-stdin", "--credentials-backend", backend],
        input=json.dumps({"vnc:password": PASSWORD}),
        capture_output=True, text=True,
    )
    if written.returncode != 0:
        # **Not a skip.** The line above already proved the subcommand exists,
        # so a failure here is a store that broke rather than one that is
        # absent, and skipping would turn these tests green while proving
        # nothing about the component.
        pytest.fail(
            f"`act secret set` failed even though `act secret` exists, so the credential "
            f"store is broken rather than missing:\n{written.stderr.strip()}"
        )
    return backend


def _grant(host: str, port: int) -> str:
    return json.dumps({
        "wasi:sockets": {
            "mode": "allowlist",
            "allow": [{"host": host, "ports": [port], "protocols": ["tcp"]}],
        }
    })


async def _client(act_command, wasm_path, args, stack) -> Client:
    transport = StdioTransport(
        command=act_command[0],
        args=[*act_command[1:], "run", str(wasm_path), "--mcp", *args],
        keep_alive=False,
        log_file=LOG_FILE,
    )
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            return await stack.enter_async_context(Client(transport))
    except TimeoutError:
        pytest.fail(f"MCP client did not connect within {CONNECT_TIMEOUT}s")


@pytest.fixture
async def authed_client(act_command, wasm_path, authenticated_vnc, credential_store):
    """A host that can reach the password-protected server *and* the store."""
    host, port = authenticated_vnc
    async with AsyncExitStack() as stack:
        yield await _client(
            act_command, wasm_path,
            ["--grant", _grant(host, port), "--allow", "act:credentials",
             "--credentials-backend", credential_store],
            stack,
        )


@pytest.fixture
async def storeless_client(act_command, wasm_path, authenticated_vnc):
    """The same host with the class granted but **no store named** — the
    shape of a deployment where nobody ran `act secret set`."""
    host, port = authenticated_vnc
    async with AsyncExitStack() as stack:
        yield await _client(
            act_command, wasm_path,
            ["--grant", _grant(host, port), "--allow", "act:credentials"],
            stack,
        )


# ── 1. the schema ───────────────────────────────────────────────────────


async def test_open_session_offers_nowhere_to_put_a_password(client):
    """The property the whole design exists to protect, asserted against the
    schema an agent actually reads — the virtual `open_session` tool the MCP
    adapter synthesises, not the Rust struct."""
    tools = await client.list_tools()
    open_session = next(t for t in tools if t.name == "open_session")
    props = open_session.inputSchema.get("properties", {})
    for name in props:
        assert not any(
            word in name.lower()
            for word in ("password", "passwd", "pwd", "secret", "token", "auth", "api_key")
        ), f"{name} must never be a session argument"
    assert "credential_key" in props, f"the credential is named, not carried: {props.keys()}"


# ── 2. no credential needed, and none asked for ─────────────────────────


async def test_an_unauthenticated_server_needs_no_credential_store(client, session_meta):
    """The `client` fixture names no `--credentials-backend` at all, so there
    is nothing to fetch. Against `x11vnc -nopw` that is not a problem: the
    server offers security type `None`, so the component never asks."""
    di = await client.call_tool("display_info", {"_meta": session_meta})
    assert not di.is_error
    assert di.structured_content["width"] >= 100


# ── 3. the server demands it ────────────────────────────────────────────


async def test_a_password_protected_server_fails_on_the_first_call_not_at_open(
    storeless_client, authenticated_vnc, expect_error
):
    host, port = authenticated_vnc
    opened = await storeless_client.call_tool(
        "open_session", {"host": host, "port": port}, raise_on_error=False,
    )
    # Nothing connects at open, so this succeeds even though the session can
    # never be used — the failure moved to the first tool call, and the
    # message has to say so.
    assert not opened.is_error, f"open_session must not connect: {opened!r}"
    sid = json.loads(opened.content[0].text)["id"]

    await expect_error(
        storeless_client, "display_info", {"_meta": {"std:session-id": sid}},
        "std:credential-required", contains="act secret set",
    )


async def test_a_stored_credential_authenticates_the_session(
    authed_client, authenticated_vnc
):
    host, port = authenticated_vnc
    opened = await authed_client.call_tool("open_session", {"host": host, "port": port})
    sid = json.loads(opened.content[0].text)["id"]
    meta = {"std:session-id": sid}

    di = await authed_client.call_tool("display_info", {"_meta": meta})
    assert not di.is_error, f"the stored password did not authenticate: {di!r}"
    assert di.structured_content["width"] == 800

    # The connection is cached, not re-handshaked: a second call must not
    # re-fetch the credential, and must still work.
    sc = await authed_client.call_tool("screenshot", {"_meta": meta})
    assert sc.content[0].mimeType == "image/png"

    await authed_client.call_tool("close_session", {"session_id": sid})


async def test_a_wrong_password_is_reported_once_and_not_re_fetched(
    act_command, wasm_path, authenticated_vnc, tmp_path_factory, expect_error
):
    """A rejected password poisons the session: the second call answers from
    the flag rather than going back to the store, which is what stops an
    `ask` policy prompting a human on every single tool call."""
    probe = subprocess.run([*act_command, "secret", "--help"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("this `act` has no credential store (`act secret`); nothing to drive")

    backend = f"file:{tmp_path_factory.mktemp('wrong-credentials')}"
    subprocess.run(
        [*act_command, "secret", "set", str(wasm_path), "--key", "default",
         "--field", "vnc:password", "--fields-stdin", "--credentials-backend", backend],
        input=json.dumps({"vnc:password": "not-the-password"}),
        capture_output=True, text=True, check=True,
    )

    host, port = authenticated_vnc
    async with AsyncExitStack() as stack:
        client = await _client(
            act_command, wasm_path,
            ["--grant", _grant(host, port), "--allow", "act:credentials",
             "--credentials-backend", backend],
            stack,
        )
        opened = await client.call_tool("open_session", {"host": host, "port": port})
        meta = {"std:session-id": json.loads(opened.content[0].text)["id"]}

        await expect_error(
            client, "display_info", {"_meta": meta}, "std:capability-denied",
            contains="rejected",
        )
        # Second call: same kind, and the message is the poisoned-session one,
        # which names the recovery rather than the server's reason.
        await expect_error(
            client, "display_info", {"_meta": meta}, "std:capability-denied",
            contains="open a new session",
        )
