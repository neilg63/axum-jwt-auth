//! Decode a JWT's payload *without* verifying its signature — useful for
//! inspecting claims (e.g. diagnosing a `prv` mismatch, see the README's
//! Troubleshooting section) before you know whether the secret/key is
//! even correct.
//!
//! ```bash
//! cargo run --example decode -- eyJhbG...
//! ```

fn main() {
    let token = std::env::args().nth(1).unwrap_or_else(usage);
    let payload_b64 = token.split('.').nth(1).unwrap_or_else(|| {
        eprintln!("Not a JWT: expected at least a header.payload segment");
        std::process::exit(1);
    });

    match base64url_decode(payload_b64) {
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(s) => println!("{s}"),
            Err(_) => {
                eprintln!("Decoded payload is not valid UTF-8");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("Failed to base64url-decode payload");
            std::process::exit(1);
        }
    }
}

fn usage() -> String {
    eprintln!("Usage: cargo run --example decode -- <jwt>");
    std::process::exit(1);
}

/// Minimal base64url (no padding) decoder — just enough to read a JWT
/// segment, without pulling in a `base64` dependency for one example.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let chars: Vec<u8> = input.bytes().filter_map(val).collect();
    if chars.len() != input.len() {
        return None; // input contained a character outside the base64url alphabet
    }
    let mut out = Vec::with_capacity(chars.len() * 3 / 4);
    for chunk in chars.chunks(4) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1)?;
        out.push((b0 << 2) | (b1 >> 4));
        if let Some(&b2) = chunk.get(2) {
            out.push((b1 << 4) | (b2 >> 2));
            if let Some(&b3) = chunk.get(3) {
                out.push((b2 << 6) | b3);
            }
        }
    }
    Some(out)
}
