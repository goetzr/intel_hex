use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io;
use std::num::ParseIntError;
use std::path::Path;

/// Parses the binary content from the specified Hex file.
/// NOTE: For efficiency, it's assumed that the specified Hex file contains only ASCII characters.
pub fn parse_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let data = fs::read_to_string(path).map_err(|e| Error::ReadFile(e))?;

    parse_from_str(data.as_str())
}

/// Parses the binary content from the specified Hex file contents.
/// NOTE: For efficiency, it's assumed that the specified Hex file contents contains only ASCII characters.
pub fn parse_from_str(hex_file_contents: &str) -> Result<Vec<u8>> {
    let mut parser = FileContentParser::new(hex_file_contents);
    parser.parse()
}

struct FileContentParser<'a> {
    data: &'a str,
    base_addr: u32,
}

impl<'a> FileContentParser<'a> {
    fn new(data: &'a str) -> Self {
        FileContentParser { data, base_addr: 0 }
    }

    fn parse(&mut self) -> Result<Vec<u8>> {
        for (line_idx, line) in self.data.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
            let line_no = line_idx + 1;
            let mut parser = RecordParser::new(line_no, line);
            let record = parser.parse()?;
        }

        Ok(vec![])
    }
}

#[derive(Default)]
struct RecordParser<'a> {
    line_no: usize,
    line: &'a str,
    byte_count: u8,
    addr: u16,
    kind: u8,
    data: Vec<u8>,
}

impl<'a> RecordParser<'a> {
    fn new(line_no: usize, line: &'a str) -> Self {
        RecordParser {
            line_no,
            line,
            ..Default::default()
        }
    }

    fn error_result(&self, kind: ParseRecordKind) -> Result<()> {
        Err(self.error(kind))
    }

    fn error(&self, kind: ParseRecordKind) -> Error {
        Error::ParseRecord(ParseRecord::new(self.line_no, kind))
    }

    fn parse(&mut self) -> Result<Record> {
        self.skip_start_code()?;
        self.parse_byte_count()?;
        self.parse_address()?;
        self.parse_type()?;
        self.parse_data()?;

        // TODO: Verify checksum
        todo!()
    }

    fn skip_start_code(&mut self) -> Result<()> {
        if let Some((_, remaining)) = self.line.split_once(':') {
            self.line = remaining;
            Ok(())
        } else {
            self.error_result(ParseRecordKind::Incomplete(RecordField::StartCode))
        }
    }

    fn parse_byte_count(&mut self) -> Result<()> {
        const BYTE_COUNT_NUM_DIGITS: usize = 2;
        if self.line.len() < BYTE_COUNT_NUM_DIGITS {
            return self.error_result(ParseRecordKind::Incomplete(RecordField::ByteCount));
        }
        let digits = self.line[0..BYTE_COUNT_NUM_DIGITS].to_string();
        self.line = &self.line[BYTE_COUNT_NUM_DIGITS..];
        self.byte_count = u8::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ParseRecordKind::ParseHexDigits {
                digits,
                field: HexDigitsField::ByteCount,
                error: e,
        })
        })?;
        Ok(())
    }

    fn parse_address(&mut self) -> Result<()> {
        const ADDRESS_NUM_DIGITS: usize = 4;
        if self.line.len() < ADDRESS_NUM_DIGITS {
            return self.error_result(ParseRecordKind::Incomplete(RecordField::Address));
        }
        let digits = self.line[0..ADDRESS_NUM_DIGITS].to_string();
        self.line = &self.line[ADDRESS_NUM_DIGITS..];
        self.addr = u16::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ParseRecordKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Address,
                error: e,
        })
        })?;
        Ok(())
    }

    fn parse_type(&mut self) -> Result<()> {
        const TYPE_NUM_DIGITS: usize = 2;
        if self.line.len() < TYPE_NUM_DIGITS {
            return self.error_result(ParseRecordKind::Incomplete(RecordField::Type));
        }
        let digits = self.line[0..TYPE_NUM_DIGITS].to_string();
        self.line = &self.line[TYPE_NUM_DIGITS..];
        self.kind = u8::from_str_radix(digits.as_str(), 16).map_err(|e| {
            self.error(ParseRecordKind::ParseHexDigits {
                digits,
                field: HexDigitsField::Type,
                error: e,
            })
        })?;
        Ok(())
    }

    fn parse_data(&mut self) -> Result<()> {
        let num_digits = self.byte_count as usize * 2;
        if self.line.len() < num_digits {
            return self.error_result(ParseRecordKind::Incomplete(RecordField::Data));
        }
        let digits = &self.line[0..num_digits];
        self.line = &self.line[num_digits..];
        let digit_pair_offsets: Vec<usize> = (0..self.byte_count as usize).collect();
        self.data = (0..self.byte_count as usize)
            .map(|byte_idx| {
                let digits_pair_idx = byte_idx * 2;
                let digits_pair = &digits[digits_idx..digits_idx + 2];
                let byte_val = u8::from_str_radix(digits_pair, 16)
                    .map_err(|e| {
                        self.error(ParseRecordKind::ParseData {
                            digits: digits_pair,
                            offset: (), error: () })
                    })
            })
        // self.data = digits
        //     .windows(2)
        //     .enumerate()
        //     .map(|(win_idx, digits)| {
        //         let digits_str = String::from_utf8(digits.to_vec()).unwrap();
        //     })
        //     .collect()
        //     .map_err(|e| {
        //         self.error(ParseRecordKind::ParseData {
        //             digits,
        //             HexDigitsField::ByteCount,
        //             e,
        //     })
        //     })?;
        
        Ok(())
    }
}

#[derive(Default)]
struct Record {
    addr: u16,
    data: Vec<u8>,
    kind: RecordKind,
}

#[derive(Default)]
enum RecordKind {
    #[default]
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

impl RecordKind {
    fn new(kind: u8) -> std::result::Result<Self, u8> {
        use RecordKind::*;
        match kind {
            0 => Ok(Data),
            1 => Ok(EndOfFile),
            2 => Ok(ExtendedSegmentAddress),
            3 => Ok(StartSegmentAddress),
            4 => Ok(ExtendedLinearAddress),
            5 => Ok(StartLinearAddress),
            t => Err(t),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ReadFile(io::Error),
    NotAscii,
    ParseRecord(ParseRecord),
}

#[derive(Debug)]
pub struct ParseRecord {
    line_no: usize,
    kind: ParseRecordKind,
}

impl ParseRecord {
    fn new(line_no: usize, kind: ParseRecordKind) -> Self {
        ParseRecord { line_no, kind }
    }
}

#[derive(Debug)]
pub enum ParseRecordKind {
    Incomplete(RecordField),
    ParseHexDigits {
        digits: String,
        field: HexDigitsField,
        error: ParseIntError,
    },
    ParseData {
        digits: Vec<u8>,
        offset: usize,
        error: ParseIntError,
    },
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
enum HexDigitsField {
    ByteCount,
    Address,
    Type,
    Data,
    Checksum,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            ReadFile(e) => write!(f, "failed to read the file: {e}"),
            NotAscii => write!(f, "file contents not ASCII"),
            ParseRecord(pr) => write!(f, "failed to parse record"),
        }
    }
}

impl StdError for Error {}

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
