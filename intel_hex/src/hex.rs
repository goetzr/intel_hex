use std::fmt;

use ascii::AsciiStr;

const DIGITS_PER_BYTE: usize = 2;

pub fn hex_to_bytes(hex_string: &AsciiStr) -> Result<Vec<u8>> {
    hex_string.as_slice().chunks()
    unimplemented!();
}

#[derive(Debug, PartialEq)]
enum Error {

}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", "Error")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_string() {
        let input = AsciiStr::from_ascii(b"0123456789abcdefABCDEF").unwrap();
        assert_eq!(hex_to_bytes(input), Ok(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef]));
    }
}