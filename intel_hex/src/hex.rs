use std::fmt;

const DIGITS_PER_BYTE: usize = 2;

pub fn hex_string_to_bytes(hex_string: &[u8]) -> Result<Vec<u8>> {
    assert!(hex_string.len() % DIGITS_PER_BYTE == 0, "hex string must consist of pairs of hex digits");
    let mut bytes = Vec::new();
    for hex_digit_pair in  hex_string.chunks(DIGITS_PER_BYTE) {
        let high_byte = decode_hex_digit(hex_digit_pair[0])?;
        let low_byte = decode_hex_digit(hex_digit_pair[1])?;
        bytes.push(high_byte << 8 | low_byte);
    }
    Ok(bytes)
}

fn decode_hex_digit(digit: u8) -> Result<u8> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a'),
        b'A'..=b'F' => Ok(digit - b'A'),
        d => Err(InvalidHexDigit(d)),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidHexDigit(u8);

impl fmt::Display for InvalidHexDigit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hex digit '{}'", self.0 as char)
    }
}

impl std::error::Error for InvalidHexDigit {}

type Result<T> = std::result::Result<T, InvalidHexDigit>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_digits() {
        assert_eq!(decode_hex_digit(b'0'), Ok(0));
        assert_eq!(decode_hex_digit(b'1'), Ok(1));
        assert_eq!(decode_hex_digit(b'2'), Ok(2));
        assert_eq!(decode_hex_digit(b'3'), Ok(3));
        assert_eq!(decode_hex_digit(b'4'), Ok(4));
        assert_eq!(decode_hex_digit(b'5'), Ok(5));
        assert_eq!(decode_hex_digit(b'6'), Ok(6));
        assert_eq!(decode_hex_digit(b'7'), Ok(7));
        assert_eq!(decode_hex_digit(b'8'), Ok(8));
        assert_eq!(decode_hex_digit(b'9'), Ok(9));
        assert_eq!(decode_hex_digit(b'a'), Ok(10));
        assert_eq!(decode_hex_digit(b'b'), Ok(11));
        assert_eq!(decode_hex_digit(b'c'), Ok(12));
        assert_eq!(decode_hex_digit(b'd'), Ok(13));
        assert_eq!(decode_hex_digit(b'e'), Ok(14));
        assert_eq!(decode_hex_digit(b'f'), Ok(15));
        assert_eq!(decode_hex_digit(b'A'), Ok(10));
        assert_eq!(decode_hex_digit(b'B'), Ok(11));
        assert_eq!(decode_hex_digit(b'C'), Ok(12));
        assert_eq!(decode_hex_digit(b'D'), Ok(13));
        assert_eq!(decode_hex_digit(b'E'), Ok(14));
        assert_eq!(decode_hex_digit(b'F'), Ok(15));
    }

    #[test]
    fn fails_to_decode_invalid_hex_digit() {
        assert_eq!(decode_hex_digit(b'g'), Err(InvalidHexDigit(b'g')));
    }

    #[test]
    fn decodes_hex_string() {
        let input = b"0123456789abcdefABCDEF";
        assert_eq!(hex_string_to_bytes(input), Ok(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef]));
    }
}