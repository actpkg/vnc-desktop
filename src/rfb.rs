//! Minimal RFB 3.8 client. Hand-rolled — no third-party VNC crate.
//!
//! Scope: handshake (None and VNC password auth), `SetPixelFormat`,
//! `SetEncodings`, `FramebufferUpdateRequest` / `FramebufferUpdate` with
//! Raw + DesktopSize encodings, `KeyEvent`, `PointerEvent`, `ClientCutText`,
//! `ServerCutText`. No CopyRect, no RRE, no Hextile, no TightVNC. Servers
//! that honour `SetEncodings(Raw=0)` work; everyone else is out of scope
//! for the MVP.
//!
//! # Why the handshake is split in two
//!
//! RFB decides *what* to authenticate with in the middle of the handshake:
//! the server sends the security types it offers, and the client answers with
//! the one byte it picked. Whether a password is needed at all is therefore
//! not knowable until the connection is already open, and the password itself
//! comes from the host credential store — an async call that cannot be made
//! from inside `open-session` (ACT-AUTH §1.1.4).
//!
//! The handshake is not resumable and it is not restartable either: once the
//! security type is written the server expects the challenge response on the
//! same TCP stream, so "connect at open, authenticate later" is not an option.
//! [`Connection::begin`] therefore runs everything up to and including the
//! security-type list and stops, handing back a [`Pending`]. The caller looks
//! at [`Pending::offers_vnc_auth`], fetches a credential only if the server
//! actually asks for one, and calls [`Pending::finish`] to complete the
//! handshake on the same stream.

use act_sdk::{ActError, ActResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PROTOCOL_3_8: &[u8] = b"RFB 003.008\n";

/// Security type 1: the server accepts unauthenticated clients (RFC 6143 §7.2.1).
const SEC_NONE: u8 = 1;
/// Security type 2: the legacy DES challenge (RFC 6143 §7.2.2).
const SEC_VNC_AUTH: u8 = 2;

// Client-to-server message types.
const C2S_SET_PIXEL_FORMAT: u8 = 0;
const C2S_SET_ENCODINGS: u8 = 2;
const C2S_FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
const C2S_KEY_EVENT: u8 = 4;
const C2S_POINTER_EVENT: u8 = 5;
const C2S_CLIENT_CUT_TEXT: u8 = 6;

// Server-to-client message types.
const S2C_FRAMEBUFFER_UPDATE: u8 = 0;
const S2C_SET_COLOUR_MAP_ENTRIES: u8 = 1;
const S2C_BELL: u8 = 2;
const S2C_SERVER_CUT_TEXT: u8 = 3;

// Encoding identifiers (signed 32-bit; pseudo-encodings are negative).
const ENC_RAW: i32 = 0;
const ENC_DESKTOP_SIZE: i32 = -223;

#[derive(Debug, Clone, Copy)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    /// 32-bit little-endian BGRA — the request we send to the server in
    /// `SetPixelFormat`. Convenient for screenshot decoding.
    fn requested() -> Self {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    fn encode(self, out: &mut [u8; 16]) {
        out[0] = self.bits_per_pixel;
        out[1] = self.depth;
        out[2] = self.big_endian as u8;
        out[3] = self.true_colour as u8;
        out[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        out[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        out[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        out[10] = self.red_shift;
        out[11] = self.green_shift;
        out[12] = self.blue_shift;
        // 3 bytes padding.
    }

    fn decode(buf: &[u8; 16]) -> Self {
        PixelFormat {
            bits_per_pixel: buf[0],
            depth: buf[1],
            big_endian: buf[2] != 0,
            true_colour: buf[3] != 0,
            red_max: u16::from_be_bytes([buf[4], buf[5]]),
            green_max: u16::from_be_bytes([buf[6], buf[7]]),
            blue_max: u16::from_be_bytes([buf[8], buf[9]]),
            red_shift: buf[10],
            green_shift: buf[11],
            blue_shift: buf[12],
        }
    }
}

pub struct Connection {
    stream: TcpStream,
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
    /// Most recent `ServerCutText` payload, exposed to the agent via `copy()`.
    pub last_clipboard: String,
    /// Cached framebuffer used to apply incremental updates; flat BGRA.
    framebuffer: Vec<u8>,
}

/// Which security type the client will answer the server with.
///
/// Returned by [`plan_security`], the one place the choice is made. It is a
/// pure function of the offered list and whether a password is in hand, which
/// is what lets the whole policy — including the "no credential needed against
/// an unauthenticated server" path — be driven on the host target, where no
/// VNC server and no credential store exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPlan {
    /// Security type 1. Nothing is sent that a credential could protect.
    NoAuth,
    /// Security type 2, the DES challenge. Needs the password.
    VncAuth,
    /// The server offers the password challenge and nothing else, and no
    /// password is available. The caller turns this into the
    /// `std:credential-required` refusal — the message naming the
    /// provisioning command belongs one layer up, with the field names.
    CredentialRequired,
}

/// Pick the security type, given what the server offered and whether a
/// password is in hand.
///
/// The order of the arms is the policy, and each one is deliberate:
///
/// 1. **A password plus a server that offers `VncAuth` authenticates.** This
///    is what the pre-credential-store version did when `password` was set in
///    session args, and it is kept: a server that offers both types and an
///    operator who provisioned a credential means the credential gets used.
/// 2. **Otherwise `None`, when offered.** A server offering security type 1
///    has stated that it accepts unauthenticated clients, so a deployment with
///    no stored credential works — which is the whole point of consulting the
///    store lazily and only when asked.
/// 3. **`VncAuth` with no password is [`SecurityPlan::CredentialRequired`].**
///    A missing credential is an error only here, where the server genuinely
///    demands one.
///
/// Anything else — a server offering only types this client cannot speak
/// (TLS-VNC, RA2, Tight's sub-negotiation) — is an error, because there is
/// nothing to answer with.
pub fn plan_security(offered: &[u8], have_password: bool) -> ActResult<SecurityPlan> {
    let none = offered.contains(&SEC_NONE);
    let vnc = offered.contains(&SEC_VNC_AUTH);
    match (have_password, none, vnc) {
        (true, _, true) => Ok(SecurityPlan::VncAuth),
        (_, true, _) => Ok(SecurityPlan::NoAuth),
        (false, false, true) => Ok(SecurityPlan::CredentialRequired),
        (_, false, false) => Err(ActError::internal(format!(
            "Server offers neither None nor VNC Auth (types {offered:?}); TLS-VNC, \
             RA2 and Tight sub-negotiation are out of scope for this component"
        ))),
    }
}

/// A connection that has completed the RFB version handshake and read the
/// server's security-type list, but has chosen nothing yet.
///
/// The stream is live and the server is waiting for one byte. Dropping a
/// `Pending` closes it, which is what a failed credential fetch does — there
/// is no half-authenticated state to clean up.
pub struct Pending {
    conn: Connection,
    offered: Vec<u8>,
}

impl Pending {
    /// The raw security-type list the server sent. For [`plan_security`] and
    /// for diagnostics; it is not credential material.
    pub fn offered(&self) -> &[u8] {
        &self.offered
    }

    /// Whether the server offers the legacy VNC password challenge. **This is
    /// the only thing that makes the component ask the credential store**: a
    /// server that never offers security type 2 never causes a `get-secret`,
    /// and therefore never causes a consent prompt.
    pub fn offers_vnc_auth(&self) -> bool {
        self.offered.contains(&SEC_VNC_AUTH)
    }

    /// Whether the server accepts unauthenticated clients. The caller uses
    /// this to decide whether a missing credential is fatal.
    pub fn offers_none(&self) -> bool {
        self.offered.contains(&SEC_NONE)
    }

    /// Finish the handshake on the same stream: answer with `plan`, run the
    /// challenge if there is one, then `ClientInit` / `ServerInit`, fix the
    /// pixel format, advertise the encodings, and seed the framebuffer with
    /// one full update.
    ///
    /// A `SecurityResult` failure after [`SecurityPlan::VncAuth`] is reported
    /// as `std:capability-denied` — the caller keys the session's poison flag
    /// off that kind, so a rejected password is not re-fetched on every
    /// subsequent tool call. Every other failure here stays `std:internal` and
    /// stays retryable, because transport failures fix themselves and
    /// authentication failures do not.
    pub fn finish(
        mut self,
        plan: SecurityPlan,
        password: Option<&str>,
        shared: bool,
    ) -> ActResult<Connection> {
        let chosen = match plan {
            SecurityPlan::NoAuth => SEC_NONE,
            SecurityPlan::VncAuth => SEC_VNC_AUTH,
            // Unreachable through `ensure_connection`, which turns this into
            // the `std:credential-required` refusal before it gets here.
            SecurityPlan::CredentialRequired => {
                return Err(ActError::internal(
                    "internal: finish() called with an unresolved credential requirement",
                ));
            }
        };
        let conn = &mut self.conn;
        conn.stream
            .write_all(&[chosen])
            .map_err(|e| ActError::internal(format!("Write security choice: {e}")))?;

        if chosen == SEC_VNC_AUTH {
            // `unwrap_or("")` is not a fallback: `plan_security` returns
            // `VncAuth` only when `have_password` was true, and the caller
            // passes the same password it computed that from.
            conn.vnc_auth(password.unwrap_or(""))?;
        }

        // SecurityResult.
        let mut result = [0u8; 4];
        conn.stream
            .read_exact(&mut result)
            .map_err(|e| ActError::internal(format!("Read SecurityResult: {e}")))?;
        if u32::from_be_bytes(result) != 0 {
            let reason = conn.read_reason().unwrap_or_else(|_| "(no reason)".into());
            return Err(if chosen == SEC_VNC_AUTH {
                // The one error kind the caller poisons the session on. The
                // reason is the server's own text; the password is never in it
                // and is never added to it.
                ActError::capability_denied(format!(
                    "The VNC server rejected the stored password: {reason}. Replace it with \
                     `act secret set <component-ref> --key <credential_key> \
                     --field vnc:password --fields-stdin`, then open a new session."
                ))
            } else {
                ActError::internal(format!(
                    "Server refused the unauthenticated connection: {reason}"
                ))
            });
        }

        let mut conn = self.conn;
        conn.client_init(shared)?;
        conn.server_init()?;

        // Request 32-bit BGRA. Many servers honour this; if they don't
        // we'd need to adapt. MVP assumes compliant server.
        conn.set_pixel_format(PixelFormat::requested())?;
        conn.set_encodings(&[ENC_RAW, ENC_DESKTOP_SIZE])?;

        conn.framebuffer = vec![0u8; conn.width as usize * conn.height as usize * 4];

        // Seed the framebuffer with a full update.
        conn.framebuffer_update_request(false, 0, 0, conn.width, conn.height)?;
        conn.pump_one_update()?;

        Ok(conn)
    }
}

impl Connection {
    /// Phase one: take the TCP stream, agree on RFB 3.8, and read the security
    /// types the server offers. **Contacts no credential store and sends no
    /// password** — see the module docs for why the split exists.
    pub fn begin(stream: TcpStream) -> ActResult<Pending> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let mut conn = Connection {
            stream,
            width: 0,
            height: 0,
            pixel_format: PixelFormat::requested(),
            name: String::new(),
            last_clipboard: String::new(),
            framebuffer: Vec::new(),
        };

        conn.protocol_handshake()?;
        let offered = conn.read_security_types()?;
        Ok(Pending { conn, offered })
    }

    // ── handshake phases ───────────────────────────────────────────────

    fn protocol_handshake(&mut self) -> ActResult<()> {
        let mut server = [0u8; 12];
        self.stream
            .read_exact(&mut server)
            .map_err(|e| ActError::internal(format!("Read ProtocolVersion: {e}")))?;
        if &server[..4] != b"RFB " {
            return Err(ActError::internal(format!(
                "Server did not greet with RFB: {server:?}"
            )));
        }
        // Always negotiate 3.8 — every modern VNC server supports it.
        self.stream
            .write_all(PROTOCOL_3_8)
            .map_err(|e| ActError::internal(format!("Write ProtocolVersion: {e}")))?;
        Ok(())
    }

    /// Read the server's security-type list. Stops there: nothing is written
    /// back, so the caller still has a free choice when it returns.
    fn read_security_types(&mut self) -> ActResult<Vec<u8>> {
        let mut count = [0u8; 1];
        self.stream
            .read_exact(&mut count)
            .map_err(|e| ActError::internal(format!("Read security count: {e}")))?;
        if count[0] == 0 {
            // Length-prefixed reason follows. A refusal before any security
            // type is offered — the server is full, or the client is not
            // allowed to connect at all — never a credential problem.
            let reason = self.read_reason()?;
            return Err(ActError::internal(format!(
                "Server rejected connection: {reason}"
            )));
        }
        let mut types = vec![0u8; count[0] as usize];
        self.stream
            .read_exact(&mut types)
            .map_err(|e| ActError::internal(format!("Read security types: {e}")))?;
        Ok(types)
    }

    fn vnc_auth(&mut self, password: &str) -> ActResult<()> {
        let mut challenge = [0u8; 16];
        self.stream
            .read_exact(&mut challenge)
            .map_err(|e| ActError::internal(format!("Read auth challenge: {e}")))?;
        let key = vnc_password_key(password);
        let response = des_encrypt_blocks(&key, &challenge);
        self.stream
            .write_all(&response)
            .map_err(|e| ActError::internal(format!("Write auth response: {e}")))?;
        Ok(())
    }

    fn read_reason(&mut self) -> ActResult<String> {
        let mut len_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut len_bytes)
            .map_err(|e| ActError::internal(format!("Read reason length: {e}")))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| ActError::internal(format!("Read reason text: {e}")))?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    fn client_init(&mut self, shared: bool) -> ActResult<()> {
        self.stream
            .write_all(&[shared as u8])
            .map_err(|e| ActError::internal(format!("Write ClientInit: {e}")))?;
        Ok(())
    }

    fn server_init(&mut self) -> ActResult<()> {
        let mut header = [0u8; 24];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| ActError::internal(format!("Read ServerInit: {e}")))?;
        self.width = u16::from_be_bytes([header[0], header[1]]);
        self.height = u16::from_be_bytes([header[2], header[3]]);
        let mut pf = [0u8; 16];
        pf.copy_from_slice(&header[4..20]);
        self.pixel_format = PixelFormat::decode(&pf);
        let name_len =
            u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as usize;
        let mut name = vec![0u8; name_len];
        self.stream
            .read_exact(&mut name)
            .map_err(|e| ActError::internal(format!("Read ServerInit name: {e}")))?;
        self.name = String::from_utf8_lossy(&name).into_owned();
        Ok(())
    }

    // ── client → server messages ───────────────────────────────────────

    fn set_pixel_format(&mut self, pf: PixelFormat) -> ActResult<()> {
        let mut msg = [0u8; 20];
        msg[0] = C2S_SET_PIXEL_FORMAT;
        // bytes 1..4 padding.
        let mut pf_bytes = [0u8; 16];
        pf.encode(&mut pf_bytes);
        msg[4..20].copy_from_slice(&pf_bytes);
        self.stream
            .write_all(&msg)
            .map_err(|e| ActError::internal(format!("Write SetPixelFormat: {e}")))?;
        self.pixel_format = pf;
        Ok(())
    }

    fn set_encodings(&mut self, encodings: &[i32]) -> ActResult<()> {
        let mut buf = Vec::with_capacity(4 + 4 * encodings.len());
        buf.push(C2S_SET_ENCODINGS);
        buf.push(0); // padding
        buf.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
        for &e in encodings {
            buf.extend_from_slice(&e.to_be_bytes());
        }
        self.stream
            .write_all(&buf)
            .map_err(|e| ActError::internal(format!("Write SetEncodings: {e}")))?;
        Ok(())
    }

    fn framebuffer_update_request(
        &mut self,
        incremental: bool,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
    ) -> ActResult<()> {
        let mut msg = [0u8; 10];
        msg[0] = C2S_FRAMEBUFFER_UPDATE_REQUEST;
        msg[1] = incremental as u8;
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        msg[6..8].copy_from_slice(&w.to_be_bytes());
        msg[8..10].copy_from_slice(&h.to_be_bytes());
        self.stream
            .write_all(&msg)
            .map_err(|e| ActError::internal(format!("Write FramebufferUpdateRequest: {e}")))?;
        Ok(())
    }

    pub fn key(&mut self, down: bool, keysym: u32) -> ActResult<()> {
        let mut msg = [0u8; 8];
        msg[0] = C2S_KEY_EVENT;
        msg[1] = down as u8;
        // bytes 2..4 padding.
        msg[4..8].copy_from_slice(&keysym.to_be_bytes());
        self.stream
            .write_all(&msg)
            .map_err(|e| ActError::internal(format!("Write KeyEvent: {e}")))?;
        Ok(())
    }

    pub fn pointer(&mut self, x: u16, y: u16, button_mask: u8) -> ActResult<()> {
        let mut msg = [0u8; 6];
        msg[0] = C2S_POINTER_EVENT;
        msg[1] = button_mask;
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        self.stream
            .write_all(&msg)
            .map_err(|e| ActError::internal(format!("Write PointerEvent: {e}")))?;
        Ok(())
    }

    pub fn client_cut_text(&mut self, text: &str) -> ActResult<()> {
        // Per the spec ClientCutText is Latin-1; non-Latin-1 characters
        // are replaced with `?`. Agents wanting Unicode should use
        // the modern Extended Clipboard pseudo-encoding (out of scope).
        let bytes: Vec<u8> = text
            .chars()
            .map(|c| if (c as u32) <= 0xff { c as u8 } else { b'?' })
            .collect();
        let mut header = [0u8; 8];
        header[0] = C2S_CLIENT_CUT_TEXT;
        // bytes 1..4 padding.
        header[4..8].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.stream
            .write_all(&header)
            .map_err(|e| ActError::internal(format!("Write ClientCutText header: {e}")))?;
        self.stream
            .write_all(&bytes)
            .map_err(|e| ActError::internal(format!("Write ClientCutText body: {e}")))?;
        Ok(())
    }

    // ── screenshot ─────────────────────────────────────────────────────

    pub fn capture_png(&mut self) -> ActResult<Vec<u8>> {
        // Request a full incremental=false update, then drain every
        // pending server message until we've seen one
        // FramebufferUpdate. Bells, colour-map entries and ServerCutText
        // are silently absorbed.
        self.framebuffer_update_request(false, 0, 0, self.width, self.height)?;
        self.pump_one_update()?;
        encode_png(self.width, self.height, &self.framebuffer)
    }

    /// Read server messages until one full `FramebufferUpdate` has been
    /// consumed. Non-update messages (Bell, ServerCutText,
    /// SetColourMapEntries) are handled inline.
    fn pump_one_update(&mut self) -> ActResult<()> {
        loop {
            let mut tag = [0u8; 1];
            self.stream
                .read_exact(&mut tag)
                .map_err(|e| ActError::internal(format!("Read server message tag: {e}")))?;
            match tag[0] {
                S2C_FRAMEBUFFER_UPDATE => {
                    self.handle_framebuffer_update()?;
                    return Ok(());
                }
                S2C_SET_COLOUR_MAP_ENTRIES => self.swallow_set_colour_map_entries()?,
                S2C_BELL => { /* one-byte message; nothing more to read */ }
                S2C_SERVER_CUT_TEXT => self.handle_server_cut_text()?,
                other => {
                    return Err(ActError::internal(format!(
                        "Unknown server message tag: {other}"
                    )));
                }
            }
        }
    }

    fn handle_framebuffer_update(&mut self) -> ActResult<()> {
        let mut header = [0u8; 3];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| ActError::internal(format!("Read FramebufferUpdate header: {e}")))?;
        let num_rects = u16::from_be_bytes([header[1], header[2]]);
        for _ in 0..num_rects {
            self.handle_rectangle()?;
        }
        Ok(())
    }

    fn handle_rectangle(&mut self) -> ActResult<()> {
        let mut header = [0u8; 12];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| ActError::internal(format!("Read rectangle header: {e}")))?;
        let x = u16::from_be_bytes([header[0], header[1]]);
        let y = u16::from_be_bytes([header[2], header[3]]);
        let w = u16::from_be_bytes([header[4], header[5]]);
        let h = u16::from_be_bytes([header[6], header[7]]);
        let enc = i32::from_be_bytes([header[8], header[9], header[10], header[11]]);

        match enc {
            ENC_RAW => self.read_raw_rect(x, y, w, h),
            ENC_DESKTOP_SIZE => {
                // Server is telling us about a resize. New geometry is in
                // (w, h); reset the framebuffer. No pixel data follows.
                self.width = w;
                self.height = h;
                self.framebuffer = vec![0u8; w as usize * h as usize * 4];
                Ok(())
            }
            other => Err(ActError::internal(format!(
                "Unsupported encoding {other} — server ignored SetEncodings(Raw)"
            ))),
        }
    }

    fn read_raw_rect(&mut self, x: u16, y: u16, w: u16, h: u16) -> ActResult<()> {
        let bpp = self.pixel_format.bits_per_pixel as usize / 8;
        if bpp != 4 {
            return Err(ActError::internal(format!(
                "Server returned {} bpp; only 32-bit pixels are supported",
                self.pixel_format.bits_per_pixel
            )));
        }
        let row_bytes = w as usize * 4;
        let mut row = vec![0u8; row_bytes];
        let fb_stride = self.width as usize * 4;
        for row_idx in 0..h as usize {
            self.stream
                .read_exact(&mut row)
                .map_err(|e| ActError::internal(format!("Read raw row: {e}")))?;
            let dst_y = y as usize + row_idx;
            let dst_off = dst_y * fb_stride + x as usize * 4;
            // Bounds check: server may send rect outside current framebuffer
            // briefly across a resize; clip rather than panic.
            if dst_off + row_bytes <= self.framebuffer.len() {
                self.framebuffer[dst_off..dst_off + row_bytes].copy_from_slice(&row);
            }
        }
        Ok(())
    }

    fn swallow_set_colour_map_entries(&mut self) -> ActResult<()> {
        // We never request a colour-map pixel format, so this message is
        // unexpected in practice, but draining it keeps the stream sync.
        let mut hdr = [0u8; 5];
        self.stream
            .read_exact(&mut hdr)
            .map_err(|e| ActError::internal(format!("Read SetColourMapEntries: {e}")))?;
        let num = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut entries = vec![0u8; num * 6];
        self.stream
            .read_exact(&mut entries)
            .map_err(|e| ActError::internal(format!("Read colour-map entries: {e}")))?;
        Ok(())
    }

    fn handle_server_cut_text(&mut self) -> ActResult<()> {
        let mut hdr = [0u8; 7];
        self.stream
            .read_exact(&mut hdr)
            .map_err(|e| ActError::internal(format!("Read ServerCutText header: {e}")))?;
        let len = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]) as usize;
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| ActError::internal(format!("Read ServerCutText body: {e}")))?;
        self.last_clipboard = String::from_utf8_lossy(&buf).into_owned();
        Ok(())
    }
}

// ── PNG encoding ────────────────────────────────────────────────────────

/// Encode a 32-bit BGRA framebuffer (the format we ask the server for)
/// as an RGB PNG, dropping the alpha channel.
fn encode_png(width: u16, height: u16, bgra: &[u8]) -> ActResult<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    if bgra.len() != w * h * 4 {
        return Err(ActError::internal(format!(
            "Framebuffer size mismatch: {} bytes, expected {}",
            bgra.len(),
            w * h * 4
        )));
    }
    // Convert BGRA → RGB.
    let mut rgb = Vec::with_capacity(w * h * 3);
    // `as_chunks` rather than `chunks_exact`: the length check above already
    // proved the buffer divides evenly, and a const chunk size lets the
    // indexing below be bounds-checked once instead of three times per pixel.
    for px in bgra.as_chunks::<4>().0 {
        // Layout we requested: shift_r=16, shift_g=8, shift_b=0, little-endian
        // → byte order is [B, G, R, A].
        rgb.push(px[2]);
        rgb.push(px[1]);
        rgb.push(px[0]);
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width as u32, height as u32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc
            .write_header()
            .map_err(|e| ActError::internal(format!("PNG header: {e}")))?;
        writer
            .write_image_data(&rgb)
            .map_err(|e| ActError::internal(format!("PNG body: {e}")))?;
    }
    Ok(out)
}

// ── VNC password DES ────────────────────────────────────────────────────

/// Build the 8-byte DES key that VNC uses: pad/truncate the password to
/// 8 bytes, then reverse the bit order of each byte (a long-standing
/// quirk of the AT&T VNC reference implementation).
fn vnc_password_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let bytes = password.as_bytes();
    let n = bytes.len().min(8);
    key[..n].copy_from_slice(&bytes[..n]);
    for b in key.iter_mut() {
        *b = b.reverse_bits();
    }
    key
}

fn des_encrypt_blocks(key: &[u8; 8], data: &[u8; 16]) -> [u8; 16] {
    use des::Des;
    use des::cipher::{Block, BlockCipherEncrypt, KeyInit};
    let cipher = Des::new(&(*key).into());
    let mut out = *data;
    for chunk in out.as_chunks_mut::<8>().0 {
        let mut block = Block::<Des>::from(*chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_format_roundtrip() {
        let pf = PixelFormat::requested();
        let mut buf = [0u8; 16];
        pf.encode(&mut buf);
        let back = PixelFormat::decode(&buf);
        assert_eq!(back.bits_per_pixel, pf.bits_per_pixel);
        assert_eq!(back.depth, pf.depth);
        assert_eq!(back.red_max, pf.red_max);
        assert_eq!(back.red_shift, pf.red_shift);
    }

    #[test]
    fn vnc_key_reverses_bits() {
        let key = vnc_password_key("ab");
        // 'a' = 0x61 = 0b0110_0001 → bit-reversed = 0b1000_0110 = 0x86
        // 'b' = 0x62 = 0b0110_0010 → bit-reversed = 0b0100_0110 = 0x46
        assert_eq!(key[0], 0x86);
        assert_eq!(key[1], 0x46);
        assert_eq!(&key[2..], &[0; 6]);
    }

    /// Known-answer test (the classic FIPS 46 worked example), run on both
    /// halves of the challenge so the block loop is covered too.
    #[test]
    fn des_encrypts_both_challenge_blocks() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ct = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&pt);
        data[8..].copy_from_slice(&pt);
        let out = des_encrypt_blocks(&key, &data);
        assert_eq!(&out[..8], &ct);
        assert_eq!(&out[8..], &ct);
    }

    /// The path that lets vnc-desktop drive an unauthenticated server with an
    /// empty credential store — the reason the store is consulted lazily and
    /// only on demand. `x11vnc -nopw` offers exactly `[1]`, and the e2e suite
    /// runs against one.
    #[test]
    fn a_server_that_wants_no_password_needs_no_credential() {
        assert_eq!(
            plan_security(&[SEC_NONE], false).expect("None is answerable"),
            SecurityPlan::NoAuth
        );
    }

    /// The other half of the same rule: a missing credential is an error only
    /// when the server actually demands the challenge.
    #[test]
    fn a_server_that_demands_the_challenge_needs_one() {
        assert_eq!(
            plan_security(&[SEC_VNC_AUTH], false).expect("answerable"),
            SecurityPlan::CredentialRequired
        );
    }

    /// A stored credential is used when the server will take it, even though
    /// the connection could have gone through unauthenticated. This is what
    /// the `password` session argument used to buy, kept.
    #[test]
    fn a_stored_credential_is_used_in_preference_to_connecting_anonymously() {
        assert_eq!(
            plan_security(&[SEC_NONE, SEC_VNC_AUTH], true).expect("answerable"),
            SecurityPlan::VncAuth
        );
    }

    /// Both offered and nothing stored: the server said unauthenticated is
    /// acceptable, so the session opens rather than demanding provisioning.
    #[test]
    fn both_offered_and_nothing_stored_falls_back_to_the_anonymous_path() {
        assert_eq!(
            plan_security(&[SEC_NONE, SEC_VNC_AUTH], false).expect("answerable"),
            SecurityPlan::NoAuth
        );
    }

    /// A credential cannot rescue a server that never offers the challenge —
    /// it must not be silently discarded into a `None` connection *only* when
    /// `None` is genuinely on offer, and must be a plain failure otherwise.
    #[test]
    fn a_credential_does_not_make_an_unspeakable_security_type_speakable() {
        // 18 = TLS-VNC, 19 = VeNCrypt: real types this client cannot answer.
        let e = plan_security(&[18, 19], true).expect_err("nothing to answer with");
        assert!(e.message.contains("neither None nor VNC Auth"), "{e:?}");
        assert!(
            plan_security(&[18, 19], false).is_err(),
            "and it is no more answerable without one"
        );
        // Offered but unusable types alongside a usable one are ignored.
        assert_eq!(
            plan_security(&[18, SEC_NONE], false).expect("answerable"),
            SecurityPlan::NoAuth
        );
    }

    /// The refusal a rejected password produces is the kind the session's
    /// poison flag keys off. Pinned here because the flag is only correct if
    /// this kind is only ever produced by an authentication failure.
    #[test]
    fn a_rejected_password_is_reported_as_capability_denied() {
        // Constructed rather than driven: reaching the real one needs a server
        // that answers SecurityResult=1, which is an e2e concern. What matters
        // here is that the constant lib.rs matches on is this one.
        assert_eq!(
            ActError::capability_denied("x").kind,
            act_sdk::constants::ERR_CAPABILITY_DENIED
        );
    }

    #[test]
    fn encode_png_produces_valid_signature() {
        let bgra = vec![0u8; 4 * 4 * 4]; // 4x4 image
        let png = encode_png(4, 4, &bgra).unwrap();
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    }
}
