use std::error::Error as StdError;
use std::fmt;
use std::num::ParseIntError;

use ascii::{AsciiStr, AsciiChar};

pub fn records<'c>(content: &'c AsciiStr) -> Records<'c> {
    Records::new(content)
}

pub struct Records<'c> {
    lines: Vec<&'c AsciiStr>,
    line_idx: usize,
}

impl<'c> Records<'c> {
    fn new(content: &'c AsciiStr) -> Self {
        let lines = content.lines().collect();
        Records { lines, line_idx: 0 }
    }
}

impl<'c> Iterator for Records<'c> {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.line_idx == self.lines.len() {
            return None;
        }

        let line = match self.lines[self.line_idx..]
            .iter()
            .map(|&l| {
                self.line_idx += 1;
                l
            })
            .filter(|l| !l.is_empty())
            .next()
        {
            Some(line) => line,
            None => return None,
        };

        // self.line_idx was incremented above, so it holds the line number of line.
        match parse_record(self.line_idx, line) {
            Ok(rec) => Some(Ok(rec)),
            Err(e) => Some(Err(e)),
        }
    }
}

fn parse_record(line_no: usize, line: &AsciiStr) -> Result<Record> {
    let parser = RecordParser::new(line_no, line);
    parser.parse()
}

#[derive(Default)]
struct RecordParser<'c> {
    line_no: usize,
    line: &'c AsciiStr,
    byte_count: u8,
    addr: u16,
    kind: RecordKind,
    data: Vec<u8>,
    cs_data_start: usize,
    cs_data_end: usize,
    checksum: u8,
}

/*
Find start code
Parse remaining hex digit string as byte vector
Parse fields from byte vector using bytes crate
Call Buf::copy_to_bytes to shallow copy data into separate Bytes instance
    Is this worth it? Copying data may be faster as data is short.
 */

impl<'c> RecordParser<'c> {
    fn new(line_no: usize, line: &'c AsciiStr) -> Self {
        RecordParser {
            line_no,
            line,
            ..Default::default()
        }
    }

    const START_CODE_CHAR: AsciiChar = AsciiChar::new(':');
    const BYTE_COUNT_NUM_DIGITS: usize = 2;
    const ADDRESS_NUM_DIGITS: usize = 4;
    const TYPE_NUM_DIGITS: usize = 2;
    const DIGITS_PER_BYTE: usize = 2;
    const CS_NUM_DIGITS: usize = 2;

    fn remaining(&self) -> &'c AsciiStr {
        &self.line[self.index..]
    }

    fn advance(&mut self, amount: usize) {
        self.index += amount;
    }

    fn error_result(&self, kind: ErrorKind) -> Result<()> {
        Err(self.error(kind))
    }

    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            line_no: self.line_no,
            kind,
        }
    }

    fn parse(mut self) -> Result<Record> {
        self.skip_start_code()?;
        self.parse_byte_count()?;
        self.parse_address()?;
        self.parse_type()?;
        self.parse_data()?;
        self.parse_checksum()?;
        self.verify_checksum()?;

        // A record should end with its checksum.
        let remaining = self.remaining();
        if !remaining.is_empty() {
            return Err(Error {
                line_no: self.line_no,
                kind: ErrorKind::ExtraData(remaining.to_string()),
            });
        }

        Ok(Record {
            kind: self.kind,
            addr: self.addr,
            data: self.data,
        })
    }

    fn skip_start_code(&mut self) -> Result<()> {
        let remaining = self.remaining();
        let parts: Vec<&AsciiStr> = remaining.split(RecordParser::START_CODE_CHAR).collect();
        if parts.len() == 1 {
            return self.error_result(ErrorKind::Incomplete(RecordField::StartCode));
        }
        if parts.len() > 2 {
            return self.error_result(ErrorKind::MultipleStartCodes);
        }

        // Skip over any characters before the start code and the start code itself.
        self.advance(parts[0].len() + 1);

        // The bytes to verify with the checksum start immediately after the start code.
        self.cs_data_start = self.index;

        Ok(())
    }

    fn parse_byte_count(&mut self) -> Result<()> {
        let remaining = self.remaining();
        if remaining.len() < RecordParser::BYTE_COUNT_NUM_DIGITS {
            return self.error_result(ErrorKind::Incomplete(RecordField::ByteCount));
        }
        
        let digits = remaining[..RecordParser::BYTE_COUNT_NUM_DIGITS].to_string();
        self.advance(RecordParser::BYTE_COUNT_NUM_DIGITS);

        self.byte_count = u8::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::ByteCount,
                error: e,
            })
        })?;

        Ok(())
    }

    fn parse_address(&mut self) -> Result<()> {
        let remaining = self.remaining();
        if remaining.len() < RecordParser::ADDRESS_NUM_DIGITS {
            return self.error_result(ErrorKind::Incomplete(RecordField::Address));
        }

        let digits = remaining[RecordParser::ADDRESS_NUM_DIGITS].to_string();
        self.advance(RecordParser::ADDRESS_NUM_DIGITS);

        self.addr = u16::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Address,
                error: e,
            })
        })?;

        Ok(())
    }

    fn parse_type(&mut self) -> Result<()> {
        let remaining = self.remaining();
        if remaining.len() < RecordParser::TYPE_NUM_DIGITS {
            return self.error_result(ErrorKind::Incomplete(RecordField::Type));
        }

        let digits = remaining[..RecordParser::TYPE_NUM_DIGITS].to_string();
        self.advance(RecordParser::TYPE_NUM_DIGITS);

        let kind = u8::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Type,
                error: e,
            })
        })?;
        self.kind = RecordKind::from_int(kind).ok_or(self.error(ErrorKind::InvalidType(kind)))?;

        Ok(())
    }

    fn parse_data(&mut self) -> Result<()> {
        // Return success immediately if the data field is omitted.
        if self.byte_count == 0 {
            return Ok(());
        }

        let remaining = self.remaining();
        let num_digits = self.byte_count as usize * RecordParser::DIGITS_PER_BYTE;
        if remaining.len() < num_digits {
            return self.error_result(ErrorKind::Incomplete(RecordField::Data));
        }

        let digits = &remaining[..num_digits];
        self.advance(num_digits);

        self.data = self.hex_to_bytes(digits)?;

        Ok(())
    }

    fn parse_checksum(&mut self) -> Result<()> {
        let remaining = self.remaining();
        if remaining.len() < RecordParser::CS_NUM_DIGITS {
            return self.error_result(ErrorKind::Incomplete(RecordField::Checksum));
        }

        let digits = remaining[..RecordParser::CS_NUM_DIGITS].to_string();
        self.advance(RecordParser::CS_NUM_DIGITS);

        self.checksum = u8::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Checksum,
                error: e,
            })
        })?;
        
        Ok(())
    }

    fn verify_checksum(&mut self) -> Result<()> {
        todo!();
        //const CS_NUM_DIGITS: usize = 2;
        //let bytes_to_verify = &self.bytes_to_verify[..self.bytes_to_verify.len() - CS_NUM_DIGITS];
        // TODO extract function that iterates over digit pairs and returns Vec<u8> then have this function and parse_data call it
        //self.byte_vals

        // let subs = string.as_bytes()
        //     .chunks(sub_len)
        //     .map(|buf| unsafe { str::from_utf8_unchecked(buf) })
        //     .collect::<Vec<&str>>();
    }

    fn hex_to_bytes(&self, hex_digits: &AsciiStr) -> std::result::Result<Vec<u8>, ParseIntError> {
        const DPB: usize = RecordParser::DIGITS_PER_BYTE;
        assert!(hex_digits.len() % DPB == 0, "invalid hex digit string");
        let num_bytes = hex_digits.len() / DPB;
        let mut bytes = Vec::with_capacity(num_bytes);
        for pair_start in (0..hex_digits.len()).step_by(DPB) {
            let pair_end = pair_start + DPB;
            let digits_pair = &hex_digits[pair_start..pair_end];
            let byte_val = u8::from_str_radix(digits_pair.as_str(), 16).map_err(|e| {
                self.error(ErrorKind::ParseBytes {
                    digits: digits_pair.to_string(),
                    offset: pair_start,
                    error: e,
                })
            })?;
            bytes.push(byte_val);
        }
        Ok(bytes)
    }

    fn hex_to_bytes2(&self, hex_digits: &AsciiStr) -> std::result::Result<Vec<u8>, ParseIntError> {
        const DIGITS_PER_BYTE: usize = 2;
        assert!(hex_digits.len() % DIGITS_PER_BYTE == 0, "hex string must contain an even number of hex digits");
        let num_bytes = hex_digits.len() / DIGITS_PER_BYTE;
        let mut bytes = Vec::with_capacity(num_bytes);
        for digit_pair in hex_digits.as_slice().chunks(DIGITS_PER_BYTE) {
            let byte_val = u8::from_str_radix(, 16).map_err(|e| {
                self.error(ErrorKind::ParseBytes {
                    digits: digit_pair.to_string(),
                    offset: pair_start,
                    error: e,
                })
            })?;
            bytes.push(byte_val);
        }
        Ok(bytes)
    }
}

#[derive(Default)]
pub struct Record {
    kind: RecordKind,
    addr: u16,
    data: Vec<u8>,
}

#[derive(Default)]
pub enum RecordKind {
    #[default]
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

impl RecordKind {
    fn from_int(kind: u8) -> Option<Self> {
        use RecordKind::*;
        match kind {
            0 => Some(Data),
            1 => Some(EndOfFile),
            2 => Some(ExtendedSegmentAddress),
            3 => Some(StartSegmentAddress),
            4 => Some(ExtendedLinearAddress),
            5 => Some(StartLinearAddress),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Error {
    line_no: usize,
    kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    Incomplete(RecordField),
    MultipleStartCodes,
    ParseIntField {
        digits: String,
        field: HexIntField,
        error: ParseIntError,
    },
    ParseData {
        digits: String,
        offset: usize,
        error: ParseIntError,
    },
    InvalidType(u8),
    ExtraData(String),
}

#[derive(Debug)]
pub enum RecordField {
    StartCode,
    ByteCount,
    Address,
    Type,
    Data,
    Checksum,
}

#[derive(Debug)]
pub enum HexIntField {
    ByteCount,
    Address,
    Type,
    Checksum,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse record")
    }
}

impl StdError for Error {}

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_start_code() -> Result<()> {
        let line = ":0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code()
    }

    #[test]
    fn returns_error_when_start_code_missing() {
        let line = "0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        let result = parser.skip_start_code();
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            Error {
                line_no: 7,
                kind: ErrorKind::Incomplete(RecordField::StartCode)
            }
        ));
    }

    #[test]
    fn skips_characters_before_start_code() -> Result<()> {
        let line = "abcd:0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code()
    }

    #[test]
    fn parses_byte_count() -> Result<()> {
        let line = ":0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())?;
        assert_eq!(parser.byte_count, 11);
        Ok(())
    }

    #[test]
    fn returns_error_when_byte_count_invalid() {
        let line = ":0H0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        let result = parser.parse_byte_count();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::ByteCount,
                error: _,
            } if digits == "0H" => (),
            _ => panic!(),
        };
    }

    #[test]
    fn returns_error_when_byte_count_incomplete() {
        let line = ":0";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        let result = parser.parse_byte_count();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::Incomplete(RecordField::ByteCount) => (),
            _ => panic!(),
        };
    }

    #[test]
    fn parses_address() -> Result<()> {
        let line = ":0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())?;
        assert_eq!(parser.addr, 16);
        Ok(())
    }

    #[test]
    fn returns_error_when_address_invalid() {
        let line = ":0B00H0006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        parser.parse_byte_count().unwrap();
        let result = parser.parse_address();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Address,
                error: _,
            } if digits == "00H0" => (),
            _ => panic!(),
        };
    }

    #[test]
    fn returns_error_when_address_incomplete() {
        let line = ":0B001";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        parser.parse_byte_count().unwrap();
        let result = parser.parse_address();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::Incomplete(RecordField::Address) => (),
            _ => panic!(),
        };
    }

    #[test]
    fn parses_type_when_data() -> Result<()> {
        let line = ":0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::Data);
        Ok(())
    }

    #[test]
    fn parses_type_when_eof() -> Result<()> {
        let line = ":0B0010016164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::EndOfFile);
        Ok(())
    }

    #[test]
    fn parses_type_when_ext_seg_addr() -> Result<()> {
        let line = ":0B0010026164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::ExtendedSegmentAddress);
        Ok(())
    }

    #[test]
    fn parses_type_when_start_seg_addr() -> Result<()> {
        let line = ":0B0010036164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::StartSegmentAddress);
        Ok(())
    }

    #[test]
    fn parses_type_when_ext_lin_addr() -> Result<()> {
        let line = ":0B0010046164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::ExtendedLinearAddress);
        Ok(())
    }

    #[test]
    fn parses_type_when_start_lin_addr() -> Result<()> {
        let line = ":0B0010056164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())?;
        matches!(parser.kind, RecordKind::StartLinearAddress);
        Ok(())
    }

    #[test]
    fn returns_error_when_type_invalid() {
        let line = ":0B0010066164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        parser.parse_byte_count().unwrap();
        parser.parse_address().unwrap();
        let result = parser.parse_type();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::InvalidType(6) => (),
            _ => panic!(),
        };
    }

    #[test]
    fn returns_error_when_type_incomplete() {
        let line = ":0B00100";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        parser.parse_byte_count().unwrap();
        parser.parse_address().unwrap();
        let result = parser.parse_type();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::Incomplete(RecordField::Type) => (),
            _ => panic!(),
        };
    }

    #[test]
    fn parses_data() -> Result<()> {
        let line = ":0B0010006164647265737320676170A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())
            .and_then(|()| parser.parse_data())?;
        assert_eq!(
            parser.data,
            vec![0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x67, 0x61, 0x70]
        );
        Ok(())
    }

    #[test]
    fn ignores_empty_data() -> Result<()> {
        let line = ":00001000A7";
        let mut parser = RecordParser::new(7, line);
        parser
            .skip_start_code()
            .and_then(|()| parser.parse_byte_count())
            .and_then(|()| parser.parse_address())
            .and_then(|()| parser.parse_type())
            .and_then(|()| parser.parse_data())?;
        assert!(!parser.line.is_empty());
        Ok(())
    }

    #[test]
    fn returns_error_when_data_incomplete() {
        let line = ":0B00100061646472657373206761";
        let mut parser = RecordParser::new(7, line);
        parser.skip_start_code().unwrap();
        parser.parse_byte_count().unwrap();
        parser.parse_address().unwrap();
        parser.parse_type().unwrap();
        let result = parser.parse_data();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.line_no, 7);
        match err.kind {
            ErrorKind::Incomplete(RecordField::Data) => (),
            _ => panic!(),
        };
    }
}
