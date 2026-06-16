//! X11 keysym lookup. Only the keys agents reach for routinely —
//! letters, digits, punctuation, common control keys, modifiers, the
//! function row. Anything more exotic should go through `key_down` /
//! `key_up` with a raw keysym lookup added on demand.

/// Map a literal char (as typed by `type_text`) to its X11 keysym.
/// For ASCII the keysym equals the character code; for everything else
/// the codepoint with the X11 "Unicode mark" 0x01000000 — the convention
/// used by X.Org keysymdef.h and accepted by every modern VNC server.
pub fn char_to_keysym(c: char) -> u32 {
    let cp = c as u32;
    if cp <= 0x7f {
        cp
    } else if (0xa0..=0xff).contains(&cp) {
        // Latin-1 supplement matches keysyms 1:1.
        cp
    } else {
        0x0100_0000 | cp
    }
}

/// Parse a key-combo string like `ctrl+shift+a` into a vector of keysyms
/// to press in order (modifiers first, base key last). The returned list
/// is intended to be pressed down in order and released in reverse.
pub fn parse_combo(combo: &str) -> Result<Vec<u32>, &'static str> {
    let parts: Vec<&str> = combo.split('+').map(str::trim).collect();
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err("empty key combo");
    }
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        let k = lookup(p).ok_or("unknown key in combo")?;
        out.push(k);
    }
    Ok(out)
}

/// Look up a single key name (case-insensitive) and return its keysym.
pub fn lookup(name: &str) -> Option<u32> {
    let n = name.to_ascii_lowercase();
    // Single character literal — letter, digit, punctuation.
    if n.chars().count() == 1 {
        let c = n.chars().next().unwrap();
        return Some(char_to_keysym(c));
    }
    Some(match n.as_str() {
        // Modifiers — left variants by convention.
        "ctrl" | "control" => 0xffe3,    // Control_L
        "shift" => 0xffe1,                // Shift_L
        "alt" => 0xffe9,                  // Alt_L
        "meta" | "super" | "win" | "cmd" => 0xffeb, // Super_L

        // Whitespace + editing.
        "return" | "enter" => 0xff0d,
        "tab" => 0xff09,
        "escape" | "esc" => 0xff1b,
        "backspace" => 0xff08,
        "delete" | "del" => 0xffff,
        "space" => 0x0020,
        "insert" | "ins" => 0xff63,

        // Arrows.
        "up" => 0xff52,
        "down" => 0xff54,
        "left" => 0xff51,
        "right" => 0xff53,

        // Navigation.
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" | "pgup" => 0xff55,
        "pagedown" | "pgdn" => 0xff56,

        // Function keys.
        "f1" => 0xffbe,
        "f2" => 0xffbf,
        "f3" => 0xffc0,
        "f4" => 0xffc1,
        "f5" => 0xffc2,
        "f6" => 0xffc3,
        "f7" => 0xffc4,
        "f8" => 0xffc5,
        "f9" => 0xffc6,
        "f10" => 0xffc7,
        "f11" => 0xffc8,
        "f12" => 0xffc9,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passthrough() {
        assert_eq!(char_to_keysym('A'), 0x41);
        assert_eq!(char_to_keysym('a'), 0x61);
        assert_eq!(char_to_keysym(' '), 0x20);
    }

    #[test]
    fn unicode_gets_x11_mark() {
        // €  = U+20AC → 0x010020AC
        assert_eq!(char_to_keysym('€'), 0x0100_20AC);
    }

    #[test]
    fn combo_parses_modifiers() {
        let keys = parse_combo("ctrl+shift+a").unwrap();
        assert_eq!(keys, vec![0xffe3, 0xffe1, 0x61]);
    }

    #[test]
    fn rejects_empty_segment() {
        assert!(parse_combo("ctrl+").is_err());
        assert!(parse_combo("").is_err());
    }

    #[test]
    fn lookup_handles_case() {
        assert_eq!(lookup("Enter"), Some(0xff0d));
        assert_eq!(lookup("F12"), Some(0xffc9));
    }
}
