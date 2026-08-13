//! `vnc-desktop` — sandboxed desktop control over the RFB / VNC protocol.
//!
//! Each session holds a single `std::net::TcpStream` connected to a VNC
//! server plus the framebuffer geometry negotiated at handshake. Tools
//! identify their session via `std:session-id` metadata.
//!
//! Sandboxing story: the component declares `wasi:sockets` and
//! `act:credentials`. No filesystem, no HTTP, no environment access. The set
//! of reachable `host:port` tuples is fully governed by the host policy.
//!
//! # The password is not an argument
//!
//! `open-session` takes no password and there is no place in its schema to
//! put one. The VNC authentication password comes from the host's credential
//! store (`act:credentials/store`), under the key named by `credential_key`,
//! in the field `vnc:password` — so it never passes through the agent's
//! context, the transcript, or the host's record of the session args.
//!
//! That has one visible consequence, and it is the reason this file is shaped
//! the way it is: **nothing connects at `open-session`.** `get-secret`
//! requires a session the host has already marked live, and the host does
//! that only after `open-session` returns (ACT-AUTH §1.1.4), so the fetch
//! cannot happen there. The RFB handshake picks its security type based on
//! whether a password is available and is not resumable once started, so the
//! connect cannot be split across the two either. TCP connect and handshake
//! both moved into [`component::ensure_connection`], which runs on the first
//! tool call and caches the live connection in the session.
//!
//! So a bad address, an unreachable server or a rejected password now surface
//! on the first tool call instead of at `open-session`. Every message on those
//! paths says so.

use act_sdk::prelude::*;
use std::net::TcpStream;

mod keysyms;
mod rfb;

use rfb::Connection;

#[act_component]
mod component {
    use super::*;
    use act_sdk::constants::ERR_CAPABILITY_DENIED;
    use serde::Serialize;

    // Session state lives in the SDK's SessionRegistry — a per-component
    // session-id -> T map (the wasm runtime is single-threaded).
    thread_local! {
        static SESSIONS: SessionRegistry<SessionState> = SessionRegistry::new("vnc");
    }

    /// The credential field this component reads.
    ///
    /// In this component's own namespace, not `std:`: `ACT-CONSTANTS.md` §8
    /// registers field *types*, not field *names*, `act-build pack` refuses a
    /// `std:`-prefixed field key outright, and the component reading a field
    /// is the party that asked for that name in the first place.
    pub const FIELD_PASSWORD: &str = "vnc:password";

    /// **Delete this when `act-types` exports `ERR_CREDENTIAL_REQUIRED`.**
    /// `ACT-CONSTANTS.md` §9 registers the kind; the constants module in the
    /// SDK has not caught up, and spelling it here is better than reaching
    /// for a near-miss kind that a host would route differently.
    const ERR_CREDENTIAL_REQUIRED: &str = "std:credential-required";

    // ── Session args ────────────────────────────────────────────────────

    /// Arguments accepted by `open-session`, and therefore the published
    /// open-args schema an agent reads before opening one.
    ///
    /// **There is no password field, and there must never be one.** It is
    /// named here and fetched from the credential store on first use; a test
    /// below asserts the generated schema offers nowhere to put one.
    #[derive(Deserialize, JsonSchema, Clone)]
    pub struct OpenArgs {
        /// VNC server hostname or IP address.
        pub host: String,
        /// VNC server port. Defaults to 5900.
        #[serde(default = "default_port")]
        pub port: u16,
        /// Which credential in this component's profile holds the VNC
        /// password. Only consulted if the server asks for one.
        #[serde(default = "default_credential_key")]
        pub credential_key: String,
        /// Shared-desktop flag; true (default) lets other clients stay connected.
        #[serde(default = "default_true")]
        pub shared: bool,
    }

    fn default_port() -> u16 {
        5900
    }
    fn default_credential_key() -> String {
        "default".into()
    }
    fn default_true() -> bool {
        true
    }

    /// One session: what it was opened with, and the connection once there is
    /// one.
    ///
    /// No `Debug`, and nothing here holds the password: it lives in
    /// [`ensure_connection`]'s frame for the length of one handshake and is
    /// dropped when that returns. A cached password would have to be
    /// re-justified at every future edit; a cached *connection* does not.
    pub struct SessionState {
        pub cfg: OpenArgs,
        /// Filled by the first tool call, never by `open-session` — see the
        /// crate docs.
        pub conn: Option<Connection>,
        /// Set when the VNC server rejected the password.
        ///
        /// Without it, every subsequent tool call on this session repeats the
        /// whole sequence *including `get-secret`*, which under an `ask`
        /// policy can put a consent prompt in front of a human on every call.
        /// A rejection is not transient: the key the credential is looked up
        /// under is fixed at open, so no retry inside this session can change
        /// the answer. Transport failures are left retryable, because those do
        /// change on their own.
        pub credential_rejected: bool,
    }

    /// Run `f` against this session's live connection.
    ///
    /// Every caller has already awaited [`ensure_connection`], which is what
    /// makes the `None` arm an internal error rather than a lazy connect: this
    /// closure is synchronous and could not perform one.
    fn with_conn<F, T>(id: &str, f: F) -> ActResult<T>
    where
        F: FnOnce(&mut Connection) -> ActResult<T>,
    {
        SESSIONS
            .with(|r| {
                r.with_mut(id, |s| match s.conn.as_mut() {
                    Some(c) => f(c),
                    None => Err(ActError::internal(
                        "internal: the session has no connection; ensure_connection was skipped",
                    )),
                })
            })
            .ok_or_else(|| unknown_session(id))?
    }

    fn unknown_session(id: &str) -> ActError {
        ActError::session_not_found(format!("Unknown session-id: {id}"))
    }

    /// Longest a `credential_key` or a `host` may be. Both are lookup names,
    /// not prose.
    const MAX_NAME: usize = 64;

    /// The leading credential-key-shaped run of `key`: letters, digits, `-`,
    /// `_` and `.`, up to [`MAX_NAME`] characters.
    ///
    /// Returns the *prefix* so a refusal can name what was asked for without
    /// repeating whatever followed it.
    fn key_prefix(key: &str) -> &str {
        bounded_prefix(key, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
        })
    }

    /// The leading hostname-shaped run of `host`: the key charset plus `:` and
    /// the brackets of an IPv6 literal.
    fn host_prefix(host: &str) -> &str {
        bounded_prefix(host, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'[' | b']')
        })
    }

    fn bounded_prefix(s: &str, ok: impl Fn(u8) -> bool) -> &str {
        let end = s
            .as_bytes()
            .iter()
            .take(MAX_NAME)
            .position(|b| !ok(*b))
            .unwrap_or_else(|| s.len().min(MAX_NAME));
        &s[..end]
    }

    /// Validates arguments and allocates an id. **Contacts nothing** — not the
    /// VNC server and not the credential store. See the crate docs.
    #[session_open]
    fn open(args: OpenArgs) -> ActResult<String> {
        // `host` is not only dialled: it becomes `secret-request.resource`,
        // which leaves this component for the host and is host-visible by
        // contract — a host MAY show it to the human it prompts. A host is an
        // address; bounding it costs nothing and keeps the prompt honest. Only
        // the valid prefix is echoed, in case what followed was pasted from
        // somewhere it should not have been.
        let host_head = host_prefix(&args.host);
        if host_head.is_empty() || host_head.len() != args.host.len() {
            return Err(ActError::invalid_args(format!(
                "host must be a hostname or IP address of 1–{MAX_NAME} characters, and \
                 '{host_head}…' is not one. Credentials do not belong here: vnc-desktop \
                 authenticates from the credential store entry named by credential_key."
            )));
        }
        // `credential_key` is agent-authored text the host pastes into the
        // question a *human* answers when deciding to release a credential.
        // The hazard is not newline forgery — the prompter escapes control and
        // bidi characters — it is plainer: `default (approved by your
        // administrator)` renders in that question exactly as written and the
        // human cannot tell which half the machine wrote. A key is a lookup
        // name, so a bounded token ends the question.
        let key_head = key_prefix(&args.credential_key);
        if key_head.is_empty() || key_head.len() != args.credential_key.len() {
            return Err(ActError::invalid_args(format!(
                "credential_key must be a name: 1–{MAX_NAME} characters of letters, \
                 digits, '-', '_' or '.', and '{key_head}…' is not one. It is a lookup \
                 key in this component's credential profile, not a sentence."
            )));
        }
        Ok(SESSIONS.with(|r| {
            r.insert(SessionState {
                cfg: args,
                conn: None,
                credential_rejected: false,
            })
        }))
    }

    #[session_close]
    fn close(session_id: String) {
        SESSIONS.with(|r| {
            r.remove(&session_id);
        });
    }

    // ── Connecting, lazily ──────────────────────────────────────────────

    /// Connect, authenticate if the server asks, and cache the connection.
    ///
    /// Runs on the first tool call, never at open (ACT-AUTH §1.1.4).
    /// Idempotent: on a session that already holds a connection it returns
    /// without touching the network or the store.
    ///
    /// The order is the design:
    ///
    /// 1. TCP connect and [`Connection::begin`] — RFB version handshake and
    ///    the server's security-type list. No credential is involved.
    /// 2. **The store is consulted only if the server offered the password
    ///    challenge.** Against `x11vnc -nopw`, or any server that offers
    ///    security type `None`, no `get-secret` is made at all, so no consent
    ///    prompt appears and an empty credential store is not a problem.
    /// 3. [`rfb::plan_security`] — the single place the choice is made, and a
    ///    pure function, so its whole policy is driven by host-target tests.
    /// 4. [`rfb::Pending::finish`] on the same stream. The handshake is not
    ///    resumable, which is why steps 1 and 4 cannot be split across
    ///    `open-session` and here.
    ///
    /// **Not de-duplicated across concurrent first calls.** Two tool calls
    /// that arrive before either has connected both run the sequence and the
    /// second overwrites the first's connection (the first is dropped, closing
    /// its stream). The fix is a per-session in-flight latch, which is more
    /// state than the cost justifies: no MCP or HTTP client in this workspace
    /// can currently produce that race, both being request/response.
    pub async fn ensure_connection(session_id: &str) -> ActResult<()> {
        if SESSIONS
            .with(|r| r.with(session_id, |s| s.conn.is_some()))
            .unwrap_or(false)
        {
            return Ok(());
        }
        // Before the store, not after: the whole point of the flag is that
        // `get-secret` is never reached a second time.
        if let Some(e) = poisoned(session_id) {
            return Err(e);
        }
        let cfg = SESSIONS
            .with(|r| r.with(session_id, |s| s.cfg.clone()))
            .ok_or_else(|| unknown_session(session_id))?;

        let addr = format!("{}:{}", cfg.host, cfg.port);
        let stream = TcpStream::connect(&addr).map_err(|e| {
            ActError::internal(format!(
                "VNC connect failed ({addr}): {e}. vnc-desktop connects on the first \
                 tool call, not at open-session, so this is the call that reports an \
                 unreachable server or a host the policy does not allow."
            ))
        })?;
        let pending = Connection::begin(stream)?;

        // Step 2. `None` here means "nothing usable is stored", not "this
        // fails" — whether a missing credential is fatal depends on what else
        // the server offered, and `plan_security` is the one place that
        // decides.
        let password = if pending.offers_vnc_auth() {
            fetch_password(session_id, &cfg).await?
        } else {
            None
        };

        let plan = rfb::plan_security(pending.offered(), password.is_some())?;
        if plan == rfb::SecurityPlan::CredentialRequired {
            return Err(credential_missing(&cfg.credential_key).await);
        }
        let conn = pending
            .finish(plan, password.as_deref(), cfg.shared)
            .inspect_err(|e| {
                // Only an answered authentication failure poisons. A transport
                // failure never reaches this kind, and those are the ones that
                // fix themselves.
                if e.kind == ERR_CAPABILITY_DENIED {
                    let _ =
                        SESSIONS.with(|r| r.with_mut(session_id, |s| s.credential_rejected = true));
                }
            })?;

        SESSIONS
            .with(|r| r.with_mut(session_id, |s| s.conn = Some(conn)))
            .ok_or_else(|| unknown_session(session_id))
    }

    /// The refusal a poisoned session answers with, or `None` if it is still
    /// worth asking the store. See [`SessionState::credential_rejected`].
    ///
    /// A named function rather than an `if` inside [`ensure_connection`]
    /// because only this half is testable on the host target: the other side
    /// falls straight through to a TCP connect and a component import that has
    /// no host implementation here.
    fn poisoned(session_id: &str) -> Option<ActError> {
        SESSIONS
            .with(|r| r.with(session_id, |s| s.credential_rejected))
            .unwrap_or(false)
            .then(|| ActError::new(ERR_CAPABILITY_DENIED, CREDENTIAL_REJECTED))
    }

    const CREDENTIAL_REJECTED: &str = "The VNC server rejected this session's password the first time it was used, and \
         the credential a session authenticates with is fixed when it opens. Fix the \
         stored credential and open a new session; retrying on this one would re-read \
         the same credential and prompt again for nothing.";

    /// What this component asks the credential store for.
    ///
    /// Every field is host-visible **by contract**: a host may show `resource`
    /// and `hint` to the human it prompts, and may record the request in its
    /// audit trail. What goes in one is therefore a disclosure decision, which
    /// is why this is a function with a test rather than a struct literal
    /// inline above.
    ///
    /// `resource` is `host:port`, and the reason it can be is `open`, which
    /// refuses a `host` that is not a bounded hostname. `kind` is `None`:
    /// `secret-kind` names nothing under the current model and MUST NOT filter
    /// retrieval (ACT-AUTH §1.1.6) — this component reads the one field it
    /// declared, by name, and decides for itself.
    fn secret_request(cfg: &OpenArgs) -> act::credentials::types::SecretRequest {
        act::credentials::types::SecretRequest {
            key: cfg.credential_key.clone(),
            kind: None,
            resource: Some(format!("{}:{}", cfg.host, cfg.port)),
            scopes: vec![],
            hint: Some("VNC authentication password".into()),
        }
    }

    /// The stored VNC password, or `None` when nothing usable is stored.
    ///
    /// `not-found` and `denied` both come back as `None` — collapsed on
    /// purpose, because the host decides `denied` before it consults the store
    /// (ACT-AUTH §1.1.7), so telling them apart would invent a difference the
    /// host refuses to disclose and would turn the pair into a way to probe a
    /// profile for keys. The caller turns `None` into either an anonymous
    /// connection or a `std:credential-required` refusal, depending on what
    /// the server offered.
    ///
    /// A credential that *exists* but carries no usable `vnc:password` is an
    /// error even against a server that would have accepted an anonymous
    /// connection. Someone provisioned that entry meaning to authenticate with
    /// it; degrading quietly to an unauthenticated session would hide the
    /// typo and answer a question nobody asked.
    async fn fetch_password(session_id: &str, cfg: &OpenArgs) -> ActResult<Option<String>> {
        use act::credentials::types::SecretError;

        let raw =
            match act::credentials::store::get_secret(session_id.to_string(), secret_request(cfg))
                .await
            {
                Ok(raw) => raw,
                Err(SecretError::NotFound | SecretError::Denied) => return Ok(None),
                Err(SecretError::InvalidSession) => {
                    return Err(ActError::session_not_found(STORE_SESSION_UNKNOWN));
                }
                Err(SecretError::Unavailable(msg)) => return Err(store_unavailable(&msg)),
            };
        // Values cross as CBOR; `from_wit` decodes the field map. Its error
        // names the field and never its bytes.
        let secret = act_sdk::credentials::Secret::from_wit(raw.kind, raw.fields)
            .map_err(|e| ActError::internal(format!("Credential field decode failed: {e}")))?;
        password_from(&secret, &cfg.credential_key).map(Some)
    }

    /// Read the password out of a fetched secret.
    ///
    /// A `std:string` field's value *is* a CBOR string, so it is read by the
    /// name this component declared — there is no shape accessor and no
    /// well-known name to assume. Split from [`fetch_password`] so it can be
    /// driven on the host target, where the store import cannot be called.
    ///
    /// An empty value is not a password: RFC 6143 §7.2.2 would happily
    /// DES-encrypt the challenge with an all-zero key and collect a rejection
    /// that reads like a wrong password rather than an unset one.
    fn password_from(secret: &act_sdk::credentials::Secret, key: &str) -> ActResult<String> {
        secret
            .field_str(FIELD_PASSWORD)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| missing_password_field(key))
    }

    /// The store rejected the session id the component passed it. Nothing the
    /// agent supplied is at fault, so nothing it supplied is quoted.
    const STORE_SESSION_UNKNOWN: &str =
        "the credential store does not recognise this session; open a new one";

    /// The store could not answer. `msg` is host-authored, and ACT-AUTH §1.1.7
    /// requires it to be free of credential material precisely so it can be
    /// passed on like this. Split out so the host-target sweep can reach it —
    /// [`fetch_password`] is `async` and calls an import with no host
    /// implementation.
    fn store_unavailable(msg: &str) -> ActError {
        ActError::internal(format!("The credential store is unavailable: {msg}"))
    }

    /// The server demanded the password challenge and nothing usable is
    /// stored. `not-found` and `denied` are indistinguishable at the store
    /// boundary, so this names both causes and asserts neither.
    async fn credential_missing(key: &str) -> ActError {
        // Best-effort: a policy that denies the store denies the listing too,
        // and then the message simply carries no inventory. Keys are not
        // secret — `list-secrets` exists to hand them to the agent.
        let known: Vec<String> = act::credentials::store::list_secrets(None)
            .await
            .map(|v| v.into_iter().map(|i| i.key).collect())
            .unwrap_or_default();
        ActError::new(
            ERR_CREDENTIAL_REQUIRED,
            credential_missing_message(key, &known),
        )
    }

    /// The message half of [`credential_missing`], separated so it can be
    /// driven on the host target — where the store import cannot be called.
    fn credential_missing_message(key: &str, known: &[String]) -> String {
        let mut msg = format!(
            "This VNC server requires password authentication (RFC 6143 §7.2.2) and no \
             usable credential is stored under key '{key}'. Either it is not set, or \
             policy denies act:credentials for this component. Set one with:\n  \
             act secret set <component-ref> --key {key} --field {FIELD_PASSWORD} \
             --fields-stdin\n  {{\"{FIELD_PASSWORD}\": \"...\"}}\n\
             A server that offers unauthenticated access needs no credential at all — \
             this one does not offer it."
        );
        if !known.is_empty() {
            msg.push_str(&format!(
                "\nThis component's profile has: {}",
                known.join(", ")
            ));
        }
        msg
    }

    /// The credential exists but carries no usable `vnc:password`.
    ///
    /// The kind is `std:credential-required` rather than `std:invalid-args`:
    /// nothing about the *call* was wrong, and the fix is the provisioning
    /// command a host surfaces for exactly this kind (`ACT-CONSTANTS.md` §9).
    fn missing_password_field(key: &str) -> ActError {
        ActError::new(
            ERR_CREDENTIAL_REQUIRED,
            format!(
                "The credential under key '{key}' carries no non-empty {FIELD_PASSWORD} \
                 field. vnc-desktop authenticates with the VNC password challenge only. \
                 Store one with:\n  act secret set <component-ref> --key {key} \
                 --field {FIELD_PASSWORD} --fields-stdin\n  \
                 {{\"{FIELD_PASSWORD}\": \"...\"}}"
            ),
        )
    }

    // ── Per-call metadata ───────────────────────────────────────────────

    #[derive(Deserialize)]
    pub struct ToolMeta {
        #[serde(rename = "std:session-id")]
        session_id: String,
    }

    // ── Mouse ───────────────────────────────────────────────────────────

    #[act_tool(description = "Move the pointer to (x, y) — absolute pixel coordinates.")]
    async fn move_pointer(
        /// X coordinate in pixels.
        x: u16,
        /// Y coordinate in pixels.
        y: u16,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        with_conn(&id, |c| c.pointer(x, y, 0))
    }

    #[act_tool(
        description = "Click a mouse button at (x, y). `button` is left|middle|right. \
                       `count` repeats the click (default 1, e.g. 2 for double-click)."
    )]
    async fn click(
        /// X coordinate in pixels.
        x: u16,
        /// Y coordinate in pixels.
        y: u16,
        /// Mouse button: left (default), middle, or right.
        button: Option<MouseButton>,
        /// Number of clicks (default 1).
        count: Option<u8>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        let mask = button.unwrap_or_default().mask();
        let n = count.unwrap_or(1).max(1);
        with_conn(&id, |c| {
            // Move first so the click registers at the requested spot
            // even if the previous PointerEvent left the cursor elsewhere.
            c.pointer(x, y, 0)?;
            for _ in 0..n {
                c.pointer(x, y, mask)?;
                c.pointer(x, y, 0)?;
            }
            Ok(())
        })
    }

    #[act_tool(description = "Press the mouse button at (x1,y1) and release at (x2,y2).")]
    async fn drag(
        /// Start X.
        x1: u16,
        /// Start Y.
        y1: u16,
        /// End X.
        x2: u16,
        /// End Y.
        y2: u16,
        /// Mouse button (default left).
        button: Option<MouseButton>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        let mask = button.unwrap_or_default().mask();
        with_conn(&id, |c| {
            c.pointer(x1, y1, 0)?;
            c.pointer(x1, y1, mask)?;
            c.pointer(x2, y2, mask)?;
            c.pointer(x2, y2, 0)?;
            Ok(())
        })
    }

    #[act_tool(
        description = "Scroll at (x, y). `direction` is up|down|left|right. `amount` is the \
                       number of scroll clicks (default 3)."
    )]
    async fn scroll(
        /// X coordinate.
        x: u16,
        /// Y coordinate.
        y: u16,
        /// Scroll direction.
        direction: ScrollDirection,
        /// Number of scroll clicks (default 3).
        amount: Option<u8>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        let mask = direction.mask();
        let n = amount.unwrap_or(3).max(1);
        with_conn(&id, |c| {
            c.pointer(x, y, 0)?;
            for _ in 0..n {
                c.pointer(x, y, mask)?;
                c.pointer(x, y, 0)?;
            }
            Ok(())
        })
    }

    // ── Keyboard ────────────────────────────────────────────────────────

    #[act_tool(description = "Type a literal string. Modifier keys are not interpreted.")]
    async fn type_text(
        /// Text to type.
        text: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        with_conn(&id, |c| {
            for ch in text.chars() {
                let keysym = keysyms::char_to_keysym(ch);
                c.key(true, keysym)?;
                c.key(false, keysym)?;
            }
            Ok(())
        })
    }

    #[act_tool(
        description = "Press a key combination like `ctrl+shift+a` or `enter`. \
                       Modifiers: ctrl, alt, shift, meta/super. \
                       Special keys: enter, tab, escape, backspace, delete, \
                       up/down/left/right, home/end/pageup/pagedown, f1..f12."
    )]
    async fn key(
        /// Key or key combo.
        combo: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let keys = keysyms::parse_combo(&combo)
            .map_err(|e| ActError::invalid_args(format!("Bad key combo `{combo}`: {e}")))?;
        ensure_connection(&id).await?;
        with_conn(&id, |c| {
            for k in &keys {
                c.key(true, *k)?;
            }
            for k in keys.iter().rev() {
                c.key(false, *k)?;
            }
            Ok(())
        })
    }

    #[act_tool(description = "Press (and hold) a single key. Pair with `key_up` to release.")]
    async fn key_down(
        /// Key name (see `key` for the vocabulary).
        key: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let k = keysyms::lookup(&key)
            .ok_or_else(|| ActError::invalid_args(format!("Unknown key: {key}")))?;
        ensure_connection(&id).await?;
        with_conn(&id, |c| c.key(true, k))
    }

    #[act_tool(description = "Release a single key previously pressed with `key_down`.")]
    async fn key_up(key: String, ctx: &mut ActContext<ToolMeta>) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let k = keysyms::lookup(&key)
            .ok_or_else(|| ActError::invalid_args(format!("Unknown key: {key}")))?;
        ensure_connection(&id).await?;
        with_conn(&id, |c| c.key(false, k))
    }

    // ── Screen ──────────────────────────────────────────────────────────

    #[act_tool(
        description = "Capture the current framebuffer as a PNG. Returns an `image/png` content-part.",
        read_only
    )]
    async fn screenshot(ctx: &mut ActContext<ToolMeta>) -> ActResult<Content> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        let png = with_conn(&id, |c| c.capture_png())?;
        Ok(Content("image/png", png))
    }

    #[act_tool(
        description = "Return the remote desktop's resolution and pixel format.",
        read_only
    )]
    async fn display_info(ctx: &mut ActContext<ToolMeta>) -> ActResult<DisplayInfo> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        with_conn(&id, |c| {
            Ok(DisplayInfo {
                width: c.width,
                height: c.height,
                bits_per_pixel: c.pixel_format.bits_per_pixel,
                depth: c.pixel_format.depth,
                name: c.name.clone(),
            })
        })
    }

    // ── Clipboard ───────────────────────────────────────────────────────

    #[act_tool(
        description = "Send the text to the remote clipboard via VNC ClientCutText. \
                       Optionally simulate Ctrl+V to paste it at the cursor."
    )]
    async fn paste(
        /// Text to set as the remote clipboard contents.
        text: String,
        /// If true (default), also press Ctrl+V after setting the clipboard.
        send_ctrl_v: Option<bool>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        let send = send_ctrl_v.unwrap_or(true);
        with_conn(&id, |c| {
            c.client_cut_text(&text)?;
            if send {
                let ctrl = keysyms::lookup("ctrl").unwrap();
                let v = keysyms::lookup("v").unwrap();
                c.key(true, ctrl)?;
                c.key(true, v)?;
                c.key(false, v)?;
                c.key(false, ctrl)?;
            }
            Ok(())
        })
    }

    #[act_tool(
        description = "Read the most recent remote-clipboard text received from the server. \
                       Returns the last `ServerCutText` payload, or an empty string if none has \
                       been seen since the session opened."
    )]
    async fn copy(ctx: &mut ActContext<ToolMeta>) -> ActResult<String> {
        let id = ctx.metadata().session_id.clone();
        ensure_connection(&id).await?;
        with_conn(&id, |c| Ok(c.last_clipboard.clone()))
    }

    // ── Argument helpers ────────────────────────────────────────────────

    #[derive(Default, Clone, Copy, Deserialize, JsonSchema)]
    #[serde(rename_all = "lowercase")]
    pub enum MouseButton {
        #[default]
        Left,
        Middle,
        Right,
    }

    impl MouseButton {
        fn mask(self) -> u8 {
            match self {
                MouseButton::Left => 0b0000_0001,
                MouseButton::Middle => 0b0000_0010,
                MouseButton::Right => 0b0000_0100,
            }
        }
    }

    #[derive(Clone, Copy, Deserialize, JsonSchema)]
    #[serde(rename_all = "lowercase")]
    pub enum ScrollDirection {
        Up,
        Down,
        Left,
        Right,
    }

    impl ScrollDirection {
        fn mask(self) -> u8 {
            // RFB scroll-wheel encoding: button 4=up, 5=down, 6=left, 7=right.
            match self {
                ScrollDirection::Up => 0b0000_1000,
                ScrollDirection::Down => 0b0001_0000,
                ScrollDirection::Left => 0b0010_0000,
                ScrollDirection::Right => 0b0100_0000,
            }
        }
    }

    #[derive(Serialize, JsonSchema)]
    pub struct DisplayInfo {
        pub width: u16,
        pub height: u16,
        pub bits_per_pixel: u8,
        pub depth: u8,
        pub name: String,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(host: &str) -> OpenArgs {
            OpenArgs {
                host: host.into(),
                port: 5900,
                credential_key: default_credential_key(),
                shared: true,
            }
        }

        /// Every property name in the schema, at any depth.
        fn property_names(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(map) => {
                    if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                        out.extend(props.keys().cloned());
                    }
                    for value in map.values() {
                        property_names(value, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        property_names(item, out);
                    }
                }
                _ => {}
            }
        }

        /// The security property the whole credential design exists to
        /// protect, asserted instead of eyeballed: a password must not be
        /// nameable in the open-args schema, because everything sent to
        /// `open-session` is agent-visible plaintext.
        ///
        /// The root fields are an **allowlist**, spelled out exactly. A
        /// denylist of secret-sounding words cannot do this job on its own —
        /// it would let `credentials`, `vnc_pass` or `login` through. Having
        /// to edit this list when a field is added is the point: adding one is
        /// a decision about what an agent may hand over, and it should not be
        /// reviewable by accident.
        ///
        /// The word search still runs, over field names at any depth, for the
        /// two things the allowlist does not cover: a secret hidden inside a
        /// nested object or a `$defs` entry, and a failure message that says
        /// what is wrong rather than just what differs.
        #[test]
        fn the_open_args_schema_names_a_credential_but_never_carries_one() {
            let schema = schemars::schema_for!(OpenArgs);
            let json: serde_json::Value = serde_json::to_value(&schema).expect("serializes");

            let mut root: Vec<&str> = json["properties"]
                .as_object()
                .expect("the schema is an object schema")
                .keys()
                .map(String::as_str)
                .collect();
            root.sort_unstable();
            assert_eq!(root, ["credential_key", "host", "port", "shared"]);

            let mut names = Vec::new();
            property_names(&json, &mut names);
            assert!(names.iter().any(|n| n == "credential_key"), "got {names:?}");
            for secret in [
                "password", "passwd", "pwd", "secret", "token", "auth", "api_key",
            ] {
                assert!(
                    !names.iter().any(|n| n.to_lowercase().contains(secret)),
                    "open-args schema offers a place to put a {secret}: {names:?}"
                );
            }
        }

        /// `host` is the one argument with no default; the rest are the
        /// contract an agent opening a session actually gets.
        #[test]
        fn every_argument_but_the_host_has_a_default() {
            let a: OpenArgs = serde_json::from_str(r#"{"host":"10.0.0.5"}"#).expect("deserializes");
            assert_eq!(a.port, 5900);
            assert_eq!(a.credential_key, "default");
            assert!(a.shared);
        }

        /// The declared key in act.toml is the one a session uses by default;
        /// declaring any other there would prompt for a credential this
        /// component never asks for.
        #[test]
        fn the_default_key_matches_the_one_declared_in_act_toml() {
            let declared =
                std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/act.toml"))
                    .expect("act.toml is beside Cargo.toml");
            assert!(
                declared.contains(&format!("key = \"{}\"", default_credential_key())),
                "act.toml declares no [[std.credentials]] entry for the default key"
            );
            assert!(
                declared.contains(&format!("key = \"{FIELD_PASSWORD}\"")),
                "act.toml declares no field named {FIELD_PASSWORD}"
            );
            assert!(
                declared.contains("[std.capabilities.\"act:credentials\"]"),
                "an undeclared class is always denied, so get-secret would never work"
            );
        }

        /// `credential_key` is agent-authored text the host pastes raw into a
        /// human-facing consent prompt.
        #[test]
        fn open_refuses_a_credential_key_that_is_not_a_bounded_token() {
            let mut a = args("10.0.0.5");
            a.credential_key = "default (approved by your administrator)".into();
            let e = open(a).expect_err("refused");
            assert_eq!(e.kind, act_sdk::constants::ERR_INVALID_ARGS);
            assert!(e.message.contains("credential_key"), "got {}", e.message);
            // Only the valid prefix is echoed — never the rest.
            assert!(
                !e.message.contains("approved by"),
                "the refusal echoed the whole string: {}",
                e.message
            );

            for key in ["", " ", "a".repeat(65).as_str(), "erp\nrelease it"] {
                let mut a = args("10.0.0.5");
                a.credential_key = key.into();
                assert!(open(a).is_err(), "accepted {key:?}");
            }
            for key in ["default", "prod.eu-1", "desk_2"] {
                let mut a = args("10.0.0.5");
                a.credential_key = key.into();
                assert!(open(a).is_ok(), "refused {key:?}");
            }
        }

        /// `host` becomes `secret-request.resource`, which a host may show to
        /// the human it prompts.
        #[test]
        fn open_refuses_a_host_that_is_not_an_address() {
            for host in ["", "10.0.0.5 (trusted)", "user:pass@10.0.0.5"] {
                let e = open(args(host)).expect_err("refused");
                assert_eq!(e.kind, act_sdk::constants::ERR_INVALID_ARGS);
                assert!(e.message.contains("host must be"), "got {}", e.message);
            }
            for host in ["10.0.0.5", "vnc.example.com", "[::1]", "desk-01"] {
                assert!(open(args(host)).is_ok(), "refused {host}");
            }
        }

        #[test]
        fn open_allocates_a_prefixed_id_and_connects_to_nothing() {
            // A host nothing is listening on: `open` must still return, which
            // is the whole point of moving the connect to the first call.
            let id = open(args("127.0.0.1")).expect("opens");
            assert!(id.starts_with("vnc_"), "got {id}");
            assert!(
                SESSIONS
                    .with(|r| r.with(&id, |s| s.conn.is_none()))
                    .unwrap(),
                "open must not have connected"
            );
        }

        /// The poison flag's promise: once the server has rejected the
        /// password, no further call reaches `get-secret`. Driven through
        /// `ensure_connection`, which is the caller that matters — a poisoned
        /// session awaits nothing, so this runs on the host target even though
        /// the store import has no implementation here.
        #[test]
        fn a_poisoned_session_refuses_without_touching_the_store() {
            let id = open(args("127.0.0.1")).expect("opens");
            assert!(poisoned(&id).is_none(), "a fresh session is not poisoned");
            SESSIONS.with(|r| r.with_mut(&id, |s| s.credential_rejected = true));

            let e = poisoned(&id).expect("poisoned");
            assert_eq!(e.kind, ERR_CAPABILITY_DENIED);
            assert!(e.message.contains("open a new session"), "{}", e.message);

            // `futures` is not a dependency; the future resolves without ever
            // yielding, so polling it once with a no-op waker is enough — and
            // it is what proves nothing was awaited.
            let e = poll_once(ensure_connection(&id)).expect("poisoned sessions answer at once");
            assert_eq!(e.expect_err("refused").kind, ERR_CAPABILITY_DENIED);
        }

        /// Poll a future exactly once. `Some` means it never awaited anything.
        fn poll_once<F: std::future::Future>(f: F) -> Option<F::Output> {
            use std::pin::pin;
            use std::task::{Context, Poll, Waker};
            match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(v) => Some(v),
                Poll::Pending => None,
            }
        }

        /// Every message on a credential path names the command that fixes it,
        /// and none of them can carry credential material.
        #[test]
        fn every_credential_refusal_names_the_command_that_fixes_it() {
            let messages = [
                credential_missing_message("default", &[]),
                credential_missing_message("prod", &["prod".into(), "staging".into()]),
                missing_password_field("default").message,
                CREDENTIAL_REJECTED.to_string(),
            ];
            for m in &messages[..3] {
                assert!(m.contains("act secret set"), "not actionable: {m}");
                assert!(m.contains(FIELD_PASSWORD), "does not name the field: {m}");
            }
            // The rejection message is the one that cannot name a command with
            // a key in it — the session's key is not in scope there — so it
            // names the recovery instead.
            assert!(messages[3].contains("open a new session"));
        }

        /// A missing credential says so in a kind a host routes to a
        /// provisioning prompt, not as a generic argument error.
        #[test]
        fn a_missing_credential_uses_the_registered_kind() {
            assert_eq!(ERR_CREDENTIAL_REQUIRED, "std:credential-required");
            assert_eq!(
                missing_password_field("default").kind,
                ERR_CREDENTIAL_REQUIRED
            );
        }

        /// The listing is an aid, not a leak: keys are handed to the agent by
        /// `list-secrets` already, and no value ever appears.
        #[test]
        fn the_missing_credential_message_lists_keys_when_it_has_them() {
            let m = credential_missing_message("default", &["desk-a".into(), "desk-b".into()]);
            assert!(m.contains("desk-a, desk-b"), "got {m}");
            assert!(!credential_missing_message("default", &[]).contains("profile has"));
        }

        /// What leaves the component for the host, pinned rather than
        /// eyeballed: a host may show `resource` and `hint` to a human.
        #[test]
        fn the_secret_request_carries_the_address_and_no_shape_filter() {
            let mut cfg = args("vnc.example.com");
            cfg.port = 5901;
            cfg.credential_key = "desk-a".into();
            let want = secret_request(&cfg);
            assert_eq!(want.key, "desk-a");
            assert_eq!(want.resource.as_deref(), Some("vnc.example.com:5901"));
            assert!(want.scopes.is_empty());
            // ACT-AUTH §1.1.6: a kind is a provisioning hint and MUST NOT
            // filter retrieval. This component reads its one declared field by
            // name and decides for itself.
            assert!(want.kind.is_none());
        }

        fn secret(pairs: &[(&str, ciborium::Value)]) -> act_sdk::credentials::Secret {
            act_sdk::credentials::Secret {
                kind: "std:fields".into(),
                fields: pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), v.clone()))
                    .collect(),
            }
        }

        #[test]
        fn the_password_is_read_by_the_name_this_component_declared() {
            let s = secret(&[(FIELD_PASSWORD, ciborium::Value::Text("hunter2".into()))]);
            assert_eq!(password_from(&s, "default").expect("readable"), "hunter2");
        }

        /// Everything that is not a usable password is the same answer, and
        /// that answer names the provisioning command.
        #[test]
        fn an_unusable_password_field_is_refused_rather_than_sent() {
            let cases = [
                // Nothing under the name at all.
                secret(&[("vnc:pass", ciborium::Value::Text("x".into()))]),
                // Present but empty: an all-zero DES key, not a password.
                secret(&[(FIELD_PASSWORD, ciborium::Value::Text(String::new()))]),
                // Present but not a string — an integer field is not a string
                // with extra steps, and coercing would send "42" as a password.
                secret(&[(FIELD_PASSWORD, ciborium::Value::Integer(42.into()))]),
            ];
            for s in &cases {
                let e = password_from(s, "default").expect_err("refused");
                assert_eq!(e.kind, ERR_CREDENTIAL_REQUIRED);
                assert!(e.message.contains("act secret set"), "{}", e.message);
            }
        }

        /// The one property no test may take on trust: a refusal must not
        /// carry the material it is refusing.
        #[test]
        fn no_refusal_echoes_the_stored_value() {
            let s = secret(&[(FIELD_PASSWORD, ciborium::Value::Integer(1234.into()))]);
            let e = password_from(&s, "default").expect_err("refused");
            assert!(
                !e.message.contains("1234"),
                "leaked the value: {}",
                e.message
            );
            // And `Debug` on the secret itself prints names, never values —
            // the SDK guarantees it, and this component relies on it.
            let s = secret(&[(FIELD_PASSWORD, ciborium::Value::Text("sentinel".into()))]);
            assert!(!format!("{s:?}").contains("sentinel"));
        }

        #[test]
        fn the_store_unavailable_message_passes_the_hosts_diagnosis_through() {
            let e = store_unavailable("backend timed out");
            assert_eq!(e.kind, act_sdk::constants::ERR_INTERNAL);
            assert!(e.message.contains("backend timed out"));
        }
    }
}
