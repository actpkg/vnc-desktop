"""Shared fixtures for the MCP-driven e2e suite.

The suite drives the packed component through `act run --mcp` over stdio with
a real MCP client, so what the tests observe is what an agent observes.

vnc-desktop is a session-provider like sqlite/openapi-bridge: each session
holds one TCP connection to a VNC server, and every real tool call needs
`std:session-id` in its argument metadata (ACT-MCP §3.2), obtained via the
virtual `open_session`/`close_session` tools rather than a host-side
`--session-args` session-of-1 — see components/sqlite/e2e/conftest.py for
the full rationale; nothing here repeats it.
"""

import json
import os
import shlex
import socket
import subprocess
import time
import pytest
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Measured in docs/specs/2026-08-08-e2e-harness-findings.md, question 1.
from mcp.shared.exceptions import McpError

WASM = "target/wasm32-wasip2/release/component_vnc_desktop.wasm"

# ACT's audit trail writes to stderr unconditionally — it is not governed by
# RUST_LOG — so it is redirected to a file rather than left to flood pytest.
LOG_FILE = Path(".pytest-act-stderr.log")

# The X display number Xvfb is given when this fixture provisions its own —
# matches .github/workflows/ci.yml's "Launch Xvfb + x11vnc on :99" step.
DISPLAY_NUM = ":99"
SELF_PROVISIONED_HOST = "127.0.0.1"
SELF_PROVISIONED_PORT = 5900


@pytest.fixture(scope="session")
def act_command() -> list[str]:
    """The ACT invocation, honouring the same override the justfile uses.

    Parsed with shlex, not treated as a single path: the justfile's own
    default for its `act` variable is `npx @actcore/act` — two words — which
    cannot be `argv[0]` for a non-shell `subprocess.run`/`StdioTransport`
    call. A bare `os.environ.get("ACT", "act")` string breaks that default;
    splitting it is what makes both forms ("act" on PATH, and the npx
    two-word default) actually spawn.
    """
    return shlex.split(os.environ.get("ACT", "act"))


@pytest.fixture(scope="session")
def wasm_path(act_command: list[str]) -> Path:
    """The packed component.

    Existence is not enough and neither is a fresh mtime: `cargo build`
    produces a wasm with no `act:component` custom section, and an unpacked
    artifact declares no capability ceiling, so every grant is refused as
    "outside ceiling" and the failures point anywhere but here. This has
    already bitten three components in this workspace, so the fixture checks
    the section rather than the file.
    """
    path = Path(WASM)
    if not path.exists():
        pytest.fail(f"{path} is missing — run `just build` first")
    probe = subprocess.run(
        [*act_command, "inspect", "component-manifest", str(path)],
        capture_output=True, text=True,
    )
    name = json.loads(probe.stdout or "{}").get("std", {}).get("name", "unknown")
    if name in ("", "unknown"):
        pytest.fail(f"{path} is built but not packed — run `just build`")
    return path


def _wait_for_port(host: str, port: int, attempts: int = 60, delay: float = 0.5) -> None:
    """Block until `host:port` accepts a TCP connection — a curl-retry
    equivalent for a raw socket server (VNC isn't HTTP, so there is no
    `/info` to poll)."""
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except OSError as e:
            last_err = e
        time.sleep(delay)
    pytest.fail(f"{host}:{port} never accepted a connection: {last_err}")


@pytest.fixture(scope="session")
def vnc_server():
    """The VNC server this suite drives — `(host, port)`.

    Two provisioning paths, mirroring the two places this happened before:

    1. `VNC_HOST`/`VNC_PORT` already set (CI's e2e job: a separate "Launch
       Xvfb + x11vnc on :99" step runs first and exports both). That
       provisioning is untouched here — this fixture only waits for the
       port to actually accept a connection before any test opens a
       session, instead of starting a call and hoping. Starting a stub and
       hoping cost another component's suite a red CI run.
    2. Neither set (a bare `just test` with no display already up): this
       fixture provisions its own Xvfb + x11vnc, using the exact same
       invocation CI's step does, so the suite is not silently dependent on
       that CI step having run first.
    """
    host = os.environ.get("VNC_HOST")
    port_env = os.environ.get("VNC_PORT")
    if host and port_env:
        port = int(port_env)
        _wait_for_port(host, port)
        yield host, port
        return  # CI's own step started this server; not ours to tear down.

    # Self-provision. `x11vnc` autodetects Wayland ahead of the X11 DISPLAY
    # it's told to use when WAYLAND_DISPLAY/XDG_SESSION_TYPE are set in its
    # environment (measured: it refuses to start against Xvfb otherwise,
    # "Wayland display server detected... Exiting") — stripped here so it
    # actually targets the Xvfb display this fixture just started.
    env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY", "XDG_SESSION_TYPE")}
    env["DISPLAY"] = DISPLAY_NUM

    xvfb = subprocess.Popen(
        ["Xvfb", DISPLAY_NUM, "-screen", "0", "1024x768x24", "-nolisten", "tcp"],
    )
    try:
        for _ in range(40):
            if subprocess.run(["xdpyinfo"], env=env, capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            pytest.fail("Xvfb never became ready (xdpyinfo kept failing)")

        subprocess.run(
            ["x11vnc", "-display", DISPLAY_NUM, "-nopw", "-localhost",
             "-listen", SELF_PROVISIONED_HOST, "-forever", "-shared", "-bg"],
            env=env, check=True, capture_output=True,
        )
        _wait_for_port(SELF_PROVISIONED_HOST, SELF_PROVISIONED_PORT)
        yield SELF_PROVISIONED_HOST, SELF_PROVISIONED_PORT
    finally:
        xvfb.terminate()
        xvfb.wait(timeout=5)
        # x11vnc daemonizes itself (-bg): it is not a child of this
        # process, so there is no handle to wait() on — kill it by the
        # command line that started it so it doesn't outlive the test run.
        subprocess.run(
            ["pkill", "-f", f"x11vnc -display {DISPLAY_NUM}"], check=False,
        )


@pytest.fixture
async def client(act_command: list[str], wasm_path: Path, vnc_server: tuple[str, int]):
    """A connected MCP client, one `act` process per test.

    Grant shape carried verbatim from the old justfile's `--grant`: an
    allowlist scoped to exactly the VNC server's host and port, not the
    component's full declared ceiling (act.toml allows ports 5900-5909 on
    any host).
    """
    host, port = vnc_server
    grant = json.dumps({
        "wasi:sockets": {
            "mode": "allowlist",
            "allow": [{"host": host, "ports": [port], "protocols": ["tcp"]}],
        }
    })
    transport = StdioTransport(
        command=act_command[0],
        args=[*act_command[1:], "run", str(wasm_path), "--mcp", "--grant", grant],
        keep_alive=False,  # stateful component: fresh process per test is not optional here
        log_file=LOG_FILE,
    )
    async with Client(transport) as connected:
        yield connected


@pytest.fixture
async def session(client, vnc_server: tuple[str, int]) -> str:
    """A per-test session against the shared VNC server, opened via the
    virtual `open_session` tool — the path an agent actually uses — and
    closed via `close_session` after the test. `x11vnc -shared` (both
    provisioning paths above) is what lets more than one test's session
    connect to the same display without kicking each other off.
    """
    host, port = vnc_server
    opened = await client.call_tool("open_session", {"host": host, "port": port})
    sid = json.loads(opened.content[0].text)["id"]
    yield sid
    await client.call_tool("close_session", {"session_id": sid})


@pytest.fixture
def session_meta(session: str) -> dict:
    """The `_meta` argument-channel payload every real vnc-desktop tool call
    needs. `std:session-id` keeps its `std:` spelling here — the argument
    channel (ACT-MCP §3.2) is deliberately exempt from the `dev.actcore/`
    respelling that governs MCP's transport-level `_meta` field (§3.1).
    """
    return {"std:session-id": session}


@pytest.fixture
def expect_error():
    """Assert a call fails with a specific ACT error kind.

    Exposed as a fixture rather than a plain function so tests never have to
    import from `conftest` — that import only resolves when the test
    directory happens to be on `sys.path`, which is not something to rely on.

    Measured, not assumed. `call-tool` in `act:tools` returns a bare
    `tool-result` with NO `result<>` wrapper — only `list-tools` has one — so
    a guest reporting a failed tool call can only do it through
    `tool-event::error`, which arrives as a result with `is_error` set and the
    kind in `_meta`. **That is the path a tool test will take.**

    The JSON-RPC error path exists for failures that are not the guest's tool
    body: `list-tools`, the session operations, a wasmtime trap, an
    unreachable actor. It raises `mcp.shared.exceptions.McpError` with the
    payload at `exc.error.data`. Both are handled here so callers need not
    care.
    """

    async def _expect(client, tool: str, arguments: dict, kind: str):
        try:
            result = await client.call_tool(tool, arguments, raise_on_error=False)
        except McpError as exc:
            data = getattr(getattr(exc, "error", None), "data", None) or {}
            assert data.get("dev.actcore/error-kind") == kind, (
                f"expected {kind} on the JSON-RPC error path, got {data!r}"
            )
            return

        assert result.is_error, f"expected {tool} to fail, got {result!r}"
        meta = result.meta or {}
        assert meta.get("dev.actcore/error-kind") == kind, (
            f"expected {kind} on the isError path, got {meta!r}"
        )

    return _expect
