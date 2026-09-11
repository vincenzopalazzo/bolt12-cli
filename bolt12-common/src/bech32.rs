use bech32::primitives::decode::CheckedHrpstring;
use bech32::NoChecksum;

use crate::error::{Error, ErrorKind};

/// Decode a BOLT 12 bech32 string (no checksum) into raw TLV bytes.
///
/// Accepts `+` continuations with optional whitespace after the plus, matching
/// the BOLT 12 encoding rules LDK uses for offers and payer proofs.
pub fn decode_bolt12(encoded: &str, expected_hrp: &str) -> Result<Vec<u8>, Error> {
    let encoded = flatten_continuations(encoded)?;
    let parsed = CheckedHrpstring::new::<NoChecksum>(encoded.as_ref()).map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("bech32 decode failed: {err:?}"),
        )
    })?;
    if parsed.hrp().lowercase_char_iter().ne(expected_hrp.chars()) {
        return Err(Error::new(
            ErrorKind::UnknownHrp,
            format!("expected HRP `{expected_hrp}`"),
        ));
    }
    parsed.validate_segwit_padding().map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("invalid bech32 padding: {err:?}"),
        )
    })?;
    Ok(parsed.byte_iter().collect())
}

enum Bech32String<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl AsRef<str> for Bech32String<'_> {
    fn as_ref(&self) -> &str {
        match self {
            Bech32String::Borrowed(s) => s,
            Bech32String::Owned(s) => s,
        }
    }
}

fn flatten_continuations(s: &str) -> Result<Bech32String<'_>, Error> {
    if !s.contains('+') {
        return Ok(Bech32String::Borrowed(s));
    }

    let mut chunks = s.split('+');
    if let Some(first) = chunks.next() {
        if first.contains(char::is_whitespace) {
            return Err(Error::new(
                ErrorKind::DecodeFailed,
                "BOLT12 string has leading whitespace before '+'",
            ));
        }
        if first.is_empty() {
            return Err(Error::new(
                ErrorKind::DecodeFailed,
                "BOLT12 continuation starts with '+'",
            ));
        }
    }
    for chunk in chunks {
        let chunk = chunk.trim_start();
        if chunk.is_empty() || chunk.contains(char::is_whitespace) {
            return Err(Error::new(
                ErrorKind::DecodeFailed,
                "invalid BOLT12 '+' continuation",
            ));
        }
    }

    Ok(Bech32String::Owned(
        s.chars()
            .filter(|c| *c != '+' && !c.is_whitespace())
            .collect(),
    ))
}
