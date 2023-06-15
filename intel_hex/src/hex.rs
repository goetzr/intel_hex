use std::fmt;

const DIGITS_PER_BYTE: usize = 2;

// pub fn hex_to_bytes(hex_string: &AsciiStr) -> Result<Vec<u8>> {
//     hex_string.as_slice().chunks()
//     unimplemented!();
// }

// TODO ditch the ascii crate and just check is_ascii
fn decode_hex_digit() -> Result<u8> {
    let digit = digit.as_char();
    match digit {
        '0'..='9' => Ok(digit as u8 - '0' as u8),
        'a'..='f' | 'A'..='F' => Ok(digit.to_ascii_lowercase() as u8 - 'a' as u8),
        'A'..='F' => Ok(digit as u8 - 'A' as u8),
        d => Err(HexError::InvalidHexDigit(d)),
    }
}

#[derive(Debug, PartialEq)]
enum HexError {
    InvalidHexDigit(AsciiChar),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", "Error")
    }
}

impl std::error::Error for HexError {}

type Result<T> = std::result::Result<T, HexError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_digits() {
        assert_eq!(decode_hex_digit(AsciiChar::new('0')), Ok(0));
        assert_eq!(decode_hex_digit(AsciiChar::new('1')), Ok(1));
        assert_eq!(decode_hex_digit(AsciiChar::new('2')), Ok(2));
        assert_eq!(decode_hex_digit(AsciiChar::new('3')), Ok(3));
        assert_eq!(decode_hex_digit(AsciiChar::new('4')), Ok(4));
        assert_eq!(decode_hex_digit(AsciiChar::new('5')), Ok(5));
        assert_eq!(decode_hex_digit(AsciiChar::new('6')), Ok(6));
        assert_eq!(decode_hex_digit(AsciiChar::new('7')), Ok(7));
        assert_eq!(decode_hex_digit(AsciiChar::new('8')), Ok(8));
        assert_eq!(decode_hex_digit(AsciiChar::new('9')), Ok(9));
        assert_eq!(decode_hex_digit(AsciiChar::new('a')), Ok(10));
        assert_eq!(decode_hex_digit(AsciiChar::new('b')), Ok(11));
        assert_eq!(decode_hex_digit(AsciiChar::new('c')), Ok(12));
        assert_eq!(decode_hex_digit(AsciiChar::new('d')), Ok(13));
        assert_eq!(decode_hex_digit(AsciiChar::new('e')), Ok(14));
        assert_eq!(decode_hex_digit(AsciiChar::new('f')), Ok(15));
        assert_eq!(decode_hex_digit(AsciiChar::new('A')), Ok(10));
        assert_eq!(decode_hex_digit(AsciiChar::new('B')), Ok(11));
        assert_eq!(decode_hex_digit(AsciiChar::new('C')), Ok(12));
        assert_eq!(decode_hex_digit(AsciiChar::new('D')), Ok(13));
        assert_eq!(decode_hex_digit(AsciiChar::new('E')), Ok(14));
        assert_eq!(decode_hex_digit(AsciiChar::new('F')), Ok(15));
    }

    // #[test]
    // fn decodes_hex_string() {
    //     let input = AsciiStr::from_ascii(b"0123456789abcdefABCDEF").unwrap();
    //     assert_eq!(hex_to_bytes(input), Ok(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef]));
    // }
}