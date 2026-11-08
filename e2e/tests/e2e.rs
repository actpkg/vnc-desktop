//! Drive the packed vnc-desktop component through `act run --mcp` with a
//! real MCP client (rmcp), replacing the python fastmcp suite
//! (conftest.py + test_info/test_tools/test_session/test_credentials).
//!
//! vnc-desktop is a session-provider: every real tool call carries
//! `std:session-id` in its ARGUMENT metadata (ACT-MCP §3.2), obtained via
//! the virtual `open_session`/`close_session` tools.
//!
//! Provisioning mirrors the python conftest's two paths: `VNC_HOST`/`VNC_PORT`
//! already set (CI's Xvfb+x11vnc step exports both), or self-provisioned
//! Xvfb + x11vnc with the exact invocation CI uses. Both need those binaries;
//! a host without them fails at provisioning with that named — the same red
//! the python suite produces there.
//!
//! Env: ACT — the act invocation (whitespace-split), WASM — packed component.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

/// `().serve(transport)` hands back the client-role service running over the
/// child process: role first, the unit client handler second.
type Client = rmcp::service::RunningService<rmcp::service::RoleClient, ()>;

const DISPLAY_NUM: &str = ":99";
const SELF_PROVISIONED_HOST: &str = "127.0.0.1";
const SELF_PROVISIONED_PORT: u16 = 5900;

fn act_argv() -> Vec<String> {
    std::env::var("ACT")
        .unwrap_or_else(|_| "act".into())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn wasm_path() -> PathBuf {
    PathBuf::from(std::env::var("WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/wasm32-wasip3/release/component_vnc_desktop.wasm"
        )
        .into()
    }))
}

fn run_act(args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let argv = act_argv();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn act");
    if let Some(payload) = stdin {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(payload.as_bytes())
            .expect("write stdin payload");
    }
    child.wait_with_output().expect("act subprocess")
}

fn wait_for_port(host: &str, port: u16) {
    // VNC isn't HTTP — there is no /info to poll, so poll the socket.
    for _ in 0..60 {
        if std::net::TcpStream::connect((host, port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("{host}:{port} never accepted a connection");
}

/// One provisioned VNC endpoint. `Xvfb(None)` = external server (CI's
/// `VNC_HOST`/`VNC_PORT` env path): nothing owned, Drop must not pkill
/// a server it did not start.
struct Xvfb(Option<Child>);

fn vnc_endpoint() -> (&'static str, u16) {
    // CI exports VNC_HOST/VNC_PORT after launching its own Xvfb :99 +
    // x11vnc :5900 (ci.yml "Launch Xvfb + x11vnc on :99"); set env means
    // "use that server", unset means "start our own pair". Mirrors python
    // conftest's two provisioning paths.
    static EP: std::sync::OnceLock<(&'static str, u16)> = std::sync::OnceLock::new();
    *EP.get_or_init(|| {
        // Leak the value: `static`-bound endpoint, read once per process.
        let host: &'static str = match std::env::var("VNC_HOST") {
            Ok(h) => Box::leak(h.into_boxed_str()),
            Err(_) => SELF_PROVISIONED_HOST,
        };
        let port = std::env::var("VNC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(SELF_PROVISIONED_PORT);
        (host, port)
    })
}

/// Provision one Xvfb + x11vnc pair. `password`: `None` is `-nopw`
/// (unauthenticated); `Some(passfile)` is `-rfbauth` (VNC Auth challenge).
/// Returns the xvfb child (to terminate in the caller) — x11vnc daemonizes
/// with `-bg` and is killed by its command line instead.
fn provision_vnc(
    display: &str,
    screen: &str,
    listen: (&str, u16),
    password: Option<&PathBuf>,
) -> Xvfb {
    let xvfb = Command::new("Xvfb")
        .arg(display)
        .args(["-screen", "0", screen, "-nolisten", "tcp"])
        .spawn()
        .expect("spawn Xvfb (is it installed? apt install xvfb x11vnc)");

    // Readiness probe: Xvfb's unix socket appearing under /tmp/.X11-unix.
    // No xdpyinfo here — x11-utils is one more apt package whose absence
    // once cost a CI round, and a listening socket is exactly the event
    // x11vnc (and the component) actually need.
    let sock = format!("/tmp/.X11-unix/X{}", display.trim_start_matches(':'));
    let mut ready = false;
    for _ in 0..40 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        ready,
        "Xvfb {display} never became ready ({sock} never accepted a connection)"
    );

    let mut cmd = Command::new("x11vnc");
    cmd.args(["-display", display]);
    match password {
        Some(passfile) => {
            cmd.args(["-rfbauth", passfile.to_str().unwrap(), "-rfbport"]);
            cmd.arg(listen.1.to_string());
        }
        None => {
            cmd.arg("-nopw");
        }
    }
    cmd.args([
        "-localhost",
        "-listen",
        listen.0,
        "-forever",
        "-shared",
        "-bg",
    ]);
    // `Command::env` only adds/overrides: replaying the filtered vars would
    // still leave the inherited WAYLAND_DISPLAY/XDG_SESSION_TYPE in place,
    // and x11vnc then autodetects the compositor session and exits instead
    // of serving the Xvfb display it was pointed at. Remove them outright.
    cmd.env_remove("WAYLAND_DISPLAY");
    cmd.env_remove("XDG_SESSION_TYPE");
    cmd.env("DISPLAY", display);
    let out = cmd.output().expect("run x11vnc");
    assert!(
        out.status.success(),
        "x11vnc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_for_port(listen.0, listen.1);
    Xvfb(Some(xvfb))
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        // External server (the env path): never owned, never killed.
        let Some(child) = self.0.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        // x11vnc daemonized (-bg): not a child of this process, so kill it
        // by the command line that started it.
        let _ = Command::new("pkill")
            .arg("-f")
            .arg("x11vnc -display")
            .output();
    }
}

/// The nopw endpoint the nopw tests talk to: the `VNC_HOST`/`VNC_PORT`
/// server when set (CI pre-launches :99/5900 — connect to it, NOT
/// provision a second pair, which would collide), else self-provisioned
/// :99/5900.
///
/// Shared across tests on a `OnceLock`: libtest runs tests on parallel
/// threads and both paths bind FIXED endpoints (:99/5900, :98/5901) — two
/// tests provisioning the same pair concurrently would race on the port
/// (x11vnc: "could not obtain listening port"). One provisioning, created
/// lazily on first use, never torn down: the process exits right after the
/// last test anyway. This mirrors the python conftest's `scope="session"`
/// `vnc_server` fixture.
fn shared_nopw_vnc() -> &'static Xvfb {
    static NOPW: std::sync::OnceLock<Xvfb> = std::sync::OnceLock::new();
    NOPW.get_or_init(|| {
        let (host, port) = vnc_endpoint();
        if std::env::var_os("VNC_HOST").is_some() || std::env::var_os("VNC_PORT").is_some() {
            // The CI path: the server is already up; just wait for its port.
            wait_for_port(host, port);
            return Xvfb(None);
        }
        provision_vnc(DISPLAY_NUM, "1024x768x24", (host, port), None)
    })
}

/// The auth server: :98 / 5901, `-rfbauth` with [`PASSWORD`]. Same sharing
/// rationale as [`shared_nopw_vnc`]; the passfile lives in a leaked tempdir
/// (`std::mem::forget`) so the daemonized x11vnc keeps reading it for the
/// whole process lifetime.
fn shared_auth_vnc() -> &'static Xvfb {
    static AUTH: std::sync::OnceLock<Xvfb> = std::sync::OnceLock::new();
    AUTH.get_or_init(|| {
        let passdir = tempfile::tempdir().unwrap();
        let passfile = passdir.path().join("vncpass");
        let out = Command::new("x11vnc")
            .args(["-storepasswd", PASSWORD, passfile.to_str().unwrap()])
            .output()
            .expect("run x11vnc -storepasswd");
        assert!(out.status.success(), "x11vnc -storepasswd failed");
        // The passfile must outlive this closure: the daemonized x11vnc
        // re-reads it on every VNC auth challenge, so leak the tempdir
        // instead of letting it delete the file when the guard drops.
        std::mem::forget(passdir);
        provision_vnc(
            AUTH_DISPLAY,
            "800x600x24",
            (AUTH_HOST, AUTH_PORT),
            Some(&passfile),
        )
    })
}

fn spawn_transport(args: &[String]) -> TokioChildProcess {
    let argv = act_argv();
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg("run").arg(wasm_path()).arg("--mcp");
    cmd.args(args);
    TokioChildProcess::new(cmd.configure(|_| {})).expect("spawn act run --mcp")
}

/// The `client` fixture: grant scoped to exactly the VNC server's host and
/// port (not the full declared ceiling), plus the credentials class —
/// checked at component start even when no store is named, which is the
/// point in the credentials suite.
async fn connect(vnc: (&str, u16), extra: &[String]) -> Client {
    let grant = json!({
        "wasi:sockets": {
            "mode": "allowlist",
            "allow": [{ "host": vnc.0, "ports": [vnc.1], "protocols": ["tcp"] }],
        }
    });
    let mut args = vec![
        "--grant".to_string(),
        grant.to_string(),
        "--allow".to_string(),
        "act:credentials".to_string(),
    ];
    args.extend(extra.iter().cloned());
    ().serve(spawn_transport(&args))
        .await
        .expect("rmcp handshake with act run --mcp")
}

fn first_text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|b| match b {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .next()
        .unwrap_or_default()
}

fn arg_meta(session: &str) -> serde_json::Map<String, Value> {
    // `_meta` travels in the ARGUMENT channel, `std:` spelling intact
    // (ACT-MCP §3.2).
    json!({ "_meta": { "std:session-id": session } })
        .as_object()
        .unwrap()
        .clone()
}

async fn open_session(client: &Client, host: &str, port: u16) -> String {
    let opened = client
        .call_tool(
            CallToolRequestParams::new("open_session".to_string()).with_arguments(
                json!({"host": host, "port": port})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("open_session");
    serde_json::from_str::<Value>(&first_text(&opened)).expect("reply is JSON")["id"]
        .as_str()
        .expect("reply carries an id")
        .to_string()
}

async fn expect_error(
    client: &Client,
    tool: &str,
    arguments: Value,
    kind: &str,
    contains: Option<&str>,
) {
    let mut params = CallToolRequestParams::new(tool.to_string());
    if let Some(map) = arguments.as_object() {
        params = params.with_arguments(map.clone());
    }
    match client.call_tool(params).await {
        Err(rmcp::ServiceError::McpError(e)) => {
            let got = e
                .data
                .as_ref()
                .and_then(|d| d.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str());
            assert_eq!(
                got,
                Some(kind),
                "expected {kind} on the JSON-RPC error path"
            );
            if let Some(contains) = contains {
                assert!(
                    e.message.contains(contains),
                    "expected {contains:?} in {:?}",
                    e.message
                );
            }
        }
        Ok(result) => {
            assert_eq!(result.is_error, Some(true), "expected {tool} to fail");
            let got = result
                .meta
                .as_ref()
                .and_then(|m| m.0.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str());
            assert_eq!(got, Some(kind), "expected {kind} on the isError path");
            if let Some(contains) = contains {
                assert!(
                    first_text(&result).contains(contains),
                    "expected {contains:?} in {:?}",
                    first_text(&result)
                );
            }
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// test_info.py / test_tools.py
// ---------------------------------------------------------------------------

#[test]
fn manifest_reports_name_and_version() {
    let out = run_act(
        &[
            "inspect",
            "component-manifest",
            wasm_path().to_str().unwrap(),
        ],
        None,
    );
    assert!(out.status.success(), "inspect failed");
    let manifest: Value = serde_json::from_slice(&out.stdout).expect("manifest is JSON");
    assert_eq!(manifest["std"]["name"], "vnc-desktop");
    assert!(manifest["std"]["version"].is_string());
}

#[test]
fn manifest_name_and_sockets_capability() {
    // session.hurl's own step 1 — sockets-only capabilities, before any
    // session is opened.
    let out = run_act(
        &[
            "inspect",
            "component-manifest",
            wasm_path().to_str().unwrap(),
        ],
        None,
    );
    let manifest: Value = serde_json::from_slice(&out.stdout).expect("manifest is JSON");
    assert!(manifest["std"]["capabilities"]["wasi:sockets"].is_object());
}

#[tokio::test]
async fn component_exposes_its_tools() {
    let _xvfb = shared_nopw_vnc();
    let client = connect(vnc_endpoint(), &[]).await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    assert!(tools.len() >= 1);
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

// ---------------------------------------------------------------------------
// test_session.py — end-to-end smoke against a real VNC server.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_lifecycle() {
    let _xvfb = shared_nopw_vnc();
    let client = connect(vnc_endpoint(), &[]).await;
    let (host, port) = vnc_endpoint();
    let sid = open_session(&client, host, port).await;
    let meta = arg_meta(&sid);

    // Display info — confirms the RFB handshake completed.
    let di = client
        .call_tool(
            CallToolRequestParams::new("display_info".to_string()).with_arguments(meta.clone()),
        )
        .await
        .expect("display_info");
    let text_block = match di.content.first() {
        Some(rmcp::model::ContentBlock::Text(t)) => t,
        other => panic!("expected a text block, got {other:?}"),
    };
    assert_eq!(
        text_block
            .meta
            .as_ref()
            .and_then(|m| m.0.get("dev.actcore/mime-type"))
            .and_then(|v| v.as_str()),
        Some("application/cbor")
    );
    let structured = di
        .structured_content
        .as_ref()
        .expect("display_info returns structured content");
    assert!(structured["width"].as_u64().unwrap_or(0) >= 100);
    assert!(structured["height"].as_u64().unwrap_or(0) >= 100);

    // Screenshot: a native ImageContent block — mime on `.mimeType`, not in
    // the respelled _meta channel. Measured against a real server.
    let sc = client
        .call_tool(
            CallToolRequestParams::new("screenshot".to_string()).with_arguments(meta.clone()),
        )
        .await
        .expect("screenshot");
    match sc.content.first() {
        Some(rmcp::model::ContentBlock::Image(image)) => {
            assert_eq!(image.mime_type, "image/png");
            // PNG signature, base64-encoded.
            assert!(image.data.starts_with("iVBORw0KGgo"));
        }
        other => panic!("expected an image block, got {other:?}"),
    }

    // Mouse, keyboard, clipboard — the calls returning without error is the
    // bar the original hurl file kept too.
    for (tool, args) in [
        ("move_pointer", json!({"x": 0, "y": 0})),
        ("click", json!({"x": 0, "y": 0})),
        ("type_text", json!({"text": "hello"})),
        ("key", json!({"combo": "ctrl+a"})),
        (
            "paste",
            json!({"text": "hello from act", "send_ctrl_v": false}),
        ),
    ] {
        let mut arguments = args.as_object().unwrap().clone();
        arguments.insert("_meta".into(), json!({"std:session-id": sid}));
        let result = client
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(arguments))
            .await
            .expect(tool);
        assert_ne!(result.is_error, Some(true), "{tool} failed");
    }

    // Close happens in the python `session` fixture's teardown; explicit
    // here.
    client
        .call_tool(
            CallToolRequestParams::new("close_session".to_string())
                .with_arguments(json!({"session_id": sid}).as_object().unwrap().clone()),
        )
        .await
        .expect("close_session");
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

// ---------------------------------------------------------------------------
// test_credentials.py — the VNC password is not an argument, and it is not
// always needed. Three properties, driven end to end.
// ---------------------------------------------------------------------------

const AUTH_DISPLAY: &str = ":98";
const AUTH_HOST: &str = "127.0.0.1";
const AUTH_PORT: u16 = 5901; // inside act.toml's declared 5900-5909 ceiling
const PASSWORD: &str = "s3cr3t-vnc";

#[tokio::test]
async fn open_session_offers_nowhere_to_put_a_password() {
    let _xvfb = shared_nopw_vnc();
    let client = connect(vnc_endpoint(), &[]).await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let open = tools
        .iter()
        .find(|t| t.name.as_ref() == "open_session")
        .expect("open_session is among the tools");
    let props = open
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for name in props.keys() {
        let lowered = name.to_lowercase();
        for word in [
            "password", "passwd", "pwd", "secret", "token", "auth", "api_key",
        ] {
            assert!(
                !lowered.contains(word),
                "{name} must never be a session argument"
            );
        }
    }
    assert!(
        props.contains_key("credential_key"),
        "the credential is named, not carried: {:?}",
        props.keys().collect::<Vec<_>>()
    );
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

#[tokio::test]
async fn an_unauthenticated_server_needs_no_credential_store() {
    // The client names no --credentials-backend at all. Against
    // `x11vnc -nopw` that is not a problem: security type None, so the
    // component never asks.
    let _xvfb = shared_nopw_vnc();
    let client = connect(vnc_endpoint(), &[]).await;
    let (host, port) = vnc_endpoint();
    let sid = open_session(&client, host, port).await;
    let di = client
        .call_tool(
            CallToolRequestParams::new("display_info".to_string()).with_arguments(arg_meta(&sid)),
        )
        .await
        .expect("display_info");
    assert_ne!(di.is_error, Some(true));
    assert!(
        di.structured_content.as_ref().expect("structured")["width"]
            .as_u64()
            .unwrap_or(0)
            >= 100
    );
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

/// A store holding the VNC password under the key the component looks for
/// by default; leaked to outlive the test.
fn credential_store(password: &str) -> String {
    let argv = act_argv();
    let probe = {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).args(["secret", "--help"]);
        cmd.output().expect("run act secret --help")
    };
    assert!(
        probe.status.success(),
        "this `act` has no credential store (`act secret`); nothing to drive"
    );
    let root = tempfile::tempdir().expect("create store dir");
    let backend = format!("file:{}", root.path().display());
    let written = run_act(
        &[
            "secret",
            "set",
            wasm_path().to_str().unwrap(),
            "--key",
            "default",
            "--field",
            "vnc:password",
            "--fields-stdin",
            "--credentials-backend",
            &backend,
        ],
        Some(&json!({ "vnc:password": password }).to_string()),
    );
    assert!(
        written.status.success(),
        "`act secret set` failed even though `act secret` exists:\n{}",
        String::from_utf8_lossy(&written.stderr)
    );
    std::mem::forget(root);
    backend
}

#[tokio::test]
async fn a_password_protected_server_fails_on_the_first_call_not_at_open() {
    // Nothing connects at open, so open_session succeeds even though the
    // session can never be used — the failure moved to the first tool call,
    // and the message has to say how to fix it.
    let _xvfb = shared_auth_vnc();

    // The same host with the class granted but NO store named — the shape of
    // a deployment where nobody ran `act secret set`.
    let client = connect((AUTH_HOST, AUTH_PORT), &[]).await;
    let sid = open_session(&client, AUTH_HOST, AUTH_PORT).await;
    assert!(!sid.is_empty());

    expect_error(
        &client,
        "display_info",
        json!({"_meta": {"std:session-id": sid}}),
        "std:credential-required",
        Some("act secret set"),
    )
    .await;
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

#[tokio::test]
async fn a_stored_credential_authenticates_the_session() {
    let _xvfb = shared_auth_vnc();
    let backend = credential_store(PASSWORD);
    let client = connect(
        (AUTH_HOST, AUTH_PORT),
        &["--credentials-backend".to_string(), backend],
    )
    .await;

    let sid = open_session(&client, AUTH_HOST, AUTH_PORT).await;
    let di = client
        .call_tool(
            CallToolRequestParams::new("display_info".to_string()).with_arguments(arg_meta(&sid)),
        )
        .await
        .expect("display_info");
    assert_ne!(
        di.is_error,
        Some(true),
        "the stored password did not authenticate"
    );
    assert_eq!(
        di.structured_content.as_ref().expect("structured")["width"],
        800
    );

    // The connection is cached, not re-handshaked: a second call must not
    // re-fetch the credential, and must still work.
    let sc = client
        .call_tool(
            CallToolRequestParams::new("screenshot".to_string()).with_arguments(arg_meta(&sid)),
        )
        .await
        .expect("screenshot");
    match sc.content.first() {
        Some(rmcp::model::ContentBlock::Image(image)) => assert_eq!(image.mime_type, "image/png"),
        other => panic!("expected an image block, got {other:?}"),
    }

    client
        .call_tool(
            CallToolRequestParams::new("close_session".to_string())
                .with_arguments(json!({"session_id": sid}).as_object().unwrap().clone()),
        )
        .await
        .expect("close_session");
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}

#[tokio::test]
async fn a_wrong_password_is_reported_once_and_not_re_fetched() {
    // A rejected password poisons the session: the second call answers from
    // the flag rather than going back to the store.
    let _xvfb = shared_auth_vnc();
    let backend = credential_store("not-the-password");
    let client = connect(
        (AUTH_HOST, AUTH_PORT),
        &["--credentials-backend".to_string(), backend],
    )
    .await;

    let sid = open_session(&client, AUTH_HOST, AUTH_PORT).await;

    expect_error(
        &client,
        "display_info",
        json!({"_meta": {"std:session-id": sid}}),
        "std:capability-denied",
        Some("rejected"),
    )
    .await;
    // Second call: same kind, and the message is the poisoned-session one,
    // which names the recovery rather than the server's reason.
    expect_error(
        &client,
        "display_info",
        json!({"_meta": {"std:session-id": sid}}),
        "std:capability-denied",
        Some("open a new session"),
    )
    .await;
    client.cancel().await.ok();
    // The shared server is never dropped: other tests reuse it, and the
    // process exit cleans up whatever is left.
}
