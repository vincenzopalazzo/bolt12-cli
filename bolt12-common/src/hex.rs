use crate::error::{Error, ErrorKind};

pub fn encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_32(hex: &str) -> Result<[u8; 32], Error> {
    if hex.len() != 64 {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            format!("preimage must be 64 hex characters, got {}", hex.len()),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk)
            .map_err(|_| Error::new(ErrorKind::InvalidArgument, "preimage is not valid hex"))?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| Error::new(ErrorKind::InvalidArgument, "preimage is not valid hex"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw = [0xabu8; 32];
        let encoded = encode(&raw);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_32(&encoded).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_32("aa").is_err());
    }
}
