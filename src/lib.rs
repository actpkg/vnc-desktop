//! `vnc-desktop` — sandboxed desktop control over the RFB / VNC protocol.
//!
//! Each session holds a single `std::net::TcpStream` connected to a VNC
//! server plus the framebuffer geometry negotiated at handshake. Tools
//! identify their session via `std:session-id` metadata.
//!
//! Sandboxing story: the component declares `wasi:sockets` only.
//! No filesystem, no HTTP, no environment access. The set of reachable
//! `host:port` tuples is fully governed by the host policy.

use act_sdk::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::TcpStream;

mod keysyms;
mod rfb;

use rfb::Connection;

#[act_component]
mod component {
    use super::*;
    use serde::Serialize;

    // The component is single-threaded inside the wasm runtime, so
    // RefCell suffices. A `Mutex` would also work but adds binary size.
    thread_local! {
        static SESSIONS: RefCell<HashMap<String, RefCell<Connection>>> =
            RefCell::new(HashMap::new());
        static NEXT_ID: RefCell<u64> = const { RefCell::new(0) };
    }

    fn alloc_id() -> String {
        NEXT_ID.with(|n| {
            let mut g = n.borrow_mut();
            *g += 1;
            format!("vnc_{}", *g)
        })
    }

    fn with_session<F, T>(id: &str, f: F) -> ActResult<T>
    where
        F: FnOnce(&mut Connection) -> ActResult<T>,
    {
        SESSIONS.with(|reg| {
            let reg = reg.borrow();
            let cell = reg
                .get(id)
                .ok_or_else(|| ActError::session_not_found(format!("Unknown session-id: {id}")))?;
            let mut conn = cell.borrow_mut();
            f(&mut conn)
        })
    }

    // ── Session args ────────────────────────────────────────────────────

    #[derive(Deserialize, JsonSchema)]
    pub struct OpenArgs {
        /// VNC server hostname or IP address.
        pub host: String,
        /// VNC server port. Defaults to 5900.
        #[serde(default = "default_port")]
        pub port: u16,
        /// VNC authentication password. Omit for `None` auth.
        #[serde(default)]
        pub password: Option<String>,
        /// Shared-desktop flag; true (default) lets other clients stay connected.
        #[serde(default = "default_true")]
        pub shared: bool,
    }

    fn default_port() -> u16 {
        5900
    }
    fn default_true() -> bool {
        true
    }

    #[session_open]
    fn open(args: OpenArgs) -> ActResult<String> {
        let addr = format!("{}:{}", args.host, args.port);
        let stream = TcpStream::connect(&addr).map_err(|e| {
            ActError::internal(format!("VNC connect failed ({addr}): {e}"))
        })?;
        let conn = Connection::handshake(stream, args.password.as_deref(), args.shared)?;
        let id = alloc_id();
        SESSIONS.with(|r| r.borrow_mut().insert(id.clone(), RefCell::new(conn)));
        Ok(id)
    }

    #[session_close]
    fn close(session_id: String) {
        SESSIONS.with(|r| {
            r.borrow_mut().remove(&session_id);
        });
    }

    // ── Per-call metadata ───────────────────────────────────────────────

    #[derive(Deserialize)]
    pub struct ToolMeta {
        #[serde(rename = "std:session-id")]
        session_id: String,
    }

    // ── Mouse ───────────────────────────────────────────────────────────

    #[act_tool(description = "Move the pointer to (x, y) — absolute pixel coordinates.")]
    fn move_pointer(
        /// X coordinate in pixels.
        x: u16,
        /// Y coordinate in pixels.
        y: u16,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        with_session(&id, |c| c.pointer(x, y, 0))
    }

    #[act_tool(
        description = "Click a mouse button at (x, y). `button` is left|middle|right. \
                       `count` repeats the click (default 1, e.g. 2 for double-click)."
    )]
    fn click(
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
        let mask = button.unwrap_or_default().mask();
        let n = count.unwrap_or(1).max(1);
        with_session(&id, |c| {
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
    fn drag(
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
        let mask = button.unwrap_or_default().mask();
        with_session(&id, |c| {
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
    fn scroll(
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
        let mask = direction.mask();
        let n = amount.unwrap_or(3).max(1);
        with_session(&id, |c| {
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
    fn type_text(
        /// Text to type.
        text: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        with_session(&id, |c| {
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
    fn key(
        /// Key or key combo.
        combo: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let keys = keysyms::parse_combo(&combo)
            .map_err(|e| ActError::invalid_args(format!("Bad key combo `{combo}`: {e}")))?;
        with_session(&id, |c| {
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
    fn key_down(
        /// Key name (see `key` for the vocabulary).
        key: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let k = keysyms::lookup(&key)
            .ok_or_else(|| ActError::invalid_args(format!("Unknown key: {key}")))?;
        with_session(&id, |c| c.key(true, k))
    }

    #[act_tool(description = "Release a single key previously pressed with `key_down`.")]
    fn key_up(
        key: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let k = keysyms::lookup(&key)
            .ok_or_else(|| ActError::invalid_args(format!("Unknown key: {key}")))?;
        with_session(&id, |c| c.key(false, k))
    }

    // ── Screen ──────────────────────────────────────────────────────────

    #[act_tool(
        description = "Capture the current framebuffer as a PNG. Returns an `image/png` content-part.",
        read_only
    )]
    fn screenshot(
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Content> {
        let id = ctx.metadata().session_id.clone();
        let png = with_session(&id, |c| c.capture_png())?;
        Ok(Content("image/png", png))
    }

    #[act_tool(
        description = "Return the remote desktop's resolution and pixel format.",
        read_only
    )]
    fn display_info(
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<DisplayInfo> {
        let id = ctx.metadata().session_id.clone();
        with_session(&id, |c| {
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
    fn paste(
        /// Text to set as the remote clipboard contents.
        text: String,
        /// If true (default), also press Ctrl+V after setting the clipboard.
        send_ctrl_v: Option<bool>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<()> {
        let id = ctx.metadata().session_id.clone();
        let send = send_ctrl_v.unwrap_or(true);
        with_session(&id, |c| {
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
    fn copy(
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<String> {
        let id = ctx.metadata().session_id.clone();
        with_session(&id, |c| Ok(c.last_clipboard.clone()))
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
}

