//! Minimal RFB 3.8 client. Hand-rolled — no third-party VNC crate.
//!
//! Scope: handshake (None and VNC password auth), `SetPixelFormat`,
//! `SetEncodings`, `FramebufferUpdateRequest` / `FramebufferUpdate` with
//! Raw + DesktopSize encodings, `KeyEvent`, `PointerEvent`, `ClientCutText`,
//! `ServerCutText`. No CopyRect, no RRE, no Hextile, no TightVNC. Servers
//! that honour `SetEncodings(Raw=0)` work; everyone else is out of scope
//! for the MVP.

use act_sdk::{ActError, ActResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PROTOCOL_3_8: &[u8] = b"RFB 003.008\n";

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

impl Connection {
    /// Open the TCP stream, run the RFB 3.8 handshake, request a fixed
    /// pixel format, advertise the encodings we support, and seed the
    /// local framebuffer with one full update.
    pub fn handshake(
        stream: TcpStream,
        password: Option<&str>,
        shared: bool,
    ) -> ActResult<Self> {
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
        conn.security_handshake(password)?;
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

    fn security_handshake(&mut self, password: Option<&str>) -> ActResult<()> {
        let mut count = [0u8; 1];
        self.stream
            .read_exact(&mut count)
            .map_err(|e| ActError::internal(format!("Read security count: {e}")))?;
        if count[0] == 0 {
            // Length-prefixed reason follows.
            let reason = self.read_reason()?;
            return Err(ActError::internal(format!(
                "Server rejected connection: {reason}"
            )));
        }
        let mut types = vec![0u8; count[0] as usize];
        self.stream
            .read_exact(&mut types)
            .map_err(|e| ActError::internal(format!("Read security types: {e}")))?;

        // Prefer None when offered AND password absent; otherwise pick
        // VNC Auth.
        let none_available = types.contains(&1);
        let vnc_available = types.contains(&2);

        let chosen = match (password, none_available, vnc_available) {
            (None, true, _) => 1u8,
            (_, _, true) => 2u8,
            (None, false, false) => {
                return Err(ActError::internal(
                    "Server offers neither None nor VNC Auth and no fallback is supported",
                ));
            }
            (Some(_), false, false) => {
                return Err(ActError::internal(
                    "Server offers neither None nor VNC Auth and no fallback is supported",
                ));
            }
            (Some(_), true, false) => 1u8, // password supplied but server only offers None
        };
        self.stream
            .write_all(&[chosen])
            .map_err(|e| ActError::internal(format!("Write security choice: {e}")))?;

        if chosen == 2 {
            self.vnc_auth(password.unwrap_or(""))?;
        }

        // SecurityResult.
        let mut result = [0u8; 4];
        self.stream
            .read_exact(&mut result)
            .map_err(|e| ActError::internal(format!("Read SecurityResult: {e}")))?;
        if u32::from_be_bytes(result) != 0 {
            let reason = self.read_reason().unwrap_or_else(|_| "(no reason)".into());
            return Err(ActError::internal(format!(
                "VNC authentication failed: {reason}"
            )));
        }
        Ok(())
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
        let name_len = u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as usize;
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
    for px in bgra.chunks_exact(4) {
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
    use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = Des::new(GenericArray::from_slice(key));
    let mut out = [0u8; 16];
    for chunk in 0..2 {
        let mut block = GenericArray::clone_from_slice(&data[chunk * 8..chunk * 8 + 8]);
        cipher.encrypt_block(&mut block);
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&block);
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

    #[test]
    fn encode_png_produces_valid_signature() {
        let bgra = vec![0u8; 4 * 4 * 4]; // 4x4 image
        let png = encode_png(4, 4, &bgra).unwrap();
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    }
}
