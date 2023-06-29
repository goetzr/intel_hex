use std::fmt;
use std::path::Path;
use std::fs;
use std::io;

mod hex;

/*
let records = parse_hex_file("/path/to/hexfile")?;  // takes AsRef<Path>, returns Result<Vec<Record>>
let results = process_records(&records);            // takes &[Record], returns ProcessResults
let blocks = flash_blocks::<512>(&results.chunks);  // takes &[Chunk], returns Vec<FlashBlock>

struct ProcessResults {
    chunks: Vec<Chunk>,
    segment_start: Option<SegmentStart>,
    linear_start: Option<u32>,
    ended_with_eof_record: bool,
}

pub struct SegmentStart {
    pub cs: u16,
    pub ip: u16,
}

pub struct Chunk {
    pub addr: u32,
    pub data: Vec<u8>,
}

impl Chunk {
    pub fn len(&self) -> usize {
        self.data.len()
    }
}
*/

pub fn parse_hex_file<P>(path: P) -> Result<Vec<Record>>
where P: AsRef<Path>
{
    let content = fs::read(path).map_err(Error::ReadFile)?;
    if !content.is_ascii() {
        return Err(Error::NotAscii);
    }

    HexFileParser::new(&content).parse()
}

struct HexFileParser<'a> { 
    cursor: &'a [u8],
    record_idx: usize,
}

impl<'a> HexFileParser<'a> {
    fn new(content: &'a [u8]) -> Self {
        HexFileParser { cursor: content, record_idx: 0 }
    }

    fn parse(&mut self) -> Result<Vec<Record>> {
        let mut records = Vec::new();

        while let Some(record_pos) = self.find_next_record() {
            self.advance_to_record(record_pos);

            self.parse_byte_count()?;

            self.record_idx += 1;
        }
            

            /*
            bytes_to_checksum: Vec<u8>,
            byte_count: u8,
            address: u16,
            kind: RecordKind,
            data: Vec<u8>,
            checksum: u16,
             */

        Ok(records)
    }

    fn parse_byte_count(&mut self) -> Result<u8> {
        const BYTE_COUNT_DIGITS: usize = 2;

        if self.cursor.len() == 0 {
            return Err(self.missing_field(Field::ByteCount));
        }
        if self.cursor.len() < BYTE_COUNT_DIGITS {

        }
        hex::hex_string_to_bytes(hex_string)
    }

    fn check_space_for_field(field: Field) -> Result<()> {
        // TODO store size of each field in hash
    }

    fn missing_field(&self, field: Field) -> Error {
        missing_field(self.record_idx, field)
    }

    fn incomplete_field(&self, field: Field) -> Error {
        incomplete_field(self.record_idx, field)
    }

    fn advance_to_record(&mut self, record_pos: usize) {
        self.cursor = &self.cursor[record_pos..];
    }

    fn find_next_record(&self) -> Option<usize> {
        const START_CODE_CHAR: u8 = b':';
        if let Some(pos) = self.cursor.iter().position(|&b| b == START_CODE_CHAR) {
            Some(pos + 1)
        } else {
            None
        }
    }
}

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
pub enum Error {
    ReadFile(io::Error),
    NotAscii,
    ParseRecord {
        record_idx: usize,
        kind: ParseRecordError,
    },
    ParseField(hex::InvalidHexDigit),
}

fn missing_field(record_idx: usize, field: Field) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::MissingField(field) }
}

fn incomplete_field(record_idx: usize, field: Field) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::IncompleteField(field) }
}

#[derive(Debug)]
enum ParseRecordError {
    MissingField(Field),
    IncompleteField(Field),
}

#[derive(Debug)]
enum Field {
    ByteCount,
    Address,
    Type,
    Data,
    Checksum,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;