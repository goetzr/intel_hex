use std::fmt;

/// let content = std::fs::read("/path/to/intel_hex_file");
/// let parser = HexFileParser::new(&content)?;
/// for rec in parser.records() {
///     // process rec
/// }

struct HexFileParser<'a> {
    content: &'a [u8],
}

impl<'a> HexFileParser<'a> {
    fn new(content: &'a [u8]) -> Result<Self> {
        if content.is_ascii() {
            Ok(HexFileParser { content })
        } else {
            Err(Error::NotAscii)
        }
    }

    fn records(&self) -> Records {
        Records::new(self.content)
    }
}

pub struct Records<'a> {
    content: &'a [u8],
}

impl<'a> Records<'a> {
    fn new(content: &'a [u8]) -> Self {
        Records { content }
    }

    fn find_next_record(&mut self) -> Option<&[u8]> {
        if let Some(pos) = self.content.iter().position(|&b| b == START_CODE_CHAR) {
            Some(&self.content[(pos + 1)..])
        } else {
            None
        }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.content = match self.find_next_record() {
            Some(record_start) => record_start,
            None => return None
        };
    }
}

const START_CODE_CHAR: u8 = b':';

pub struct Record {
    kind: RecordKind,   // Record type
    addr: u16,          // Address
    data: Vec<u8>,      // Byte count, Data
}

pub enum RecordKind {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

#[derive(Debug)]
enum Error {
    NotAscii,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;