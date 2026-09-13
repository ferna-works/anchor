use crate::HexError;

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decodes a hex string, accepting an optional `0x` prefix.
pub fn decode(input: &str) -> Result<Vec<u8>, HexError> {
    let input = input.strip_prefix("0x").unwrap_or(input);

    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }

    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| HexError::InvalidDigit))
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn round_trips_bytes_through_hex() -> Result<()> {
        let bytes = [0x00, 0x01, 0x7f, 0xff];

        assert_eq!(decode(&encode(&bytes))?, bytes);

        Ok(())
    }

    #[test]
    fn decode_accepts_an_0x_prefix() -> Result<()> {
        assert_eq!(decode("0xff")?, vec![0xff]);

        Ok(())
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(matches!(decode("xyz"), Err(HexError::OddLength)));
    }

    #[test]
    fn decode_rejects_invalid_digits() {
        assert!(matches!(decode("xy"), Err(HexError::InvalidDigit)));
    }
}
