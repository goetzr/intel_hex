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
        self.advance_past_start_code()?;
        self.parse_byte_count()?;
        

        // TODO: Verify checksum
        todo!()
    }

    fn advance_past_start_code(&mut self) -> Result<()> {
        if let Some((_, remaining)) = self.line.split_once(':') {
            self.line = remaining;
            Ok(())
        } else {
            self.error_result(ParseRecordKind::Incomplete(RecordField::StartCode))
        }
    }

    fn parse_byte_count(&mut self) -> Result<()> {
        if self.line.len() < 2 {
            return self.error_result(ParseRecordKind::Incomplete(RecordField::ByteCount));
        }
        let digits = self.line[0..2].to_string();
        self.line = &self.line[2..];
        self.byte_count = u8::from_str_radix(digits.as_str(), 16)
            .map_err(|e| self.error(ParseRecordKind::InvalidByteCount(digits, e)))?;
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
    InvalidByteCount(String, ParseIntError),
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
