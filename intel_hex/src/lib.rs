use std::fmt;
use std::path::Path;
use std::fs;
use std::io;

use bytes::Buf;

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

        while let Some(next_record_pos) = self.find_next_record() {
            self.advance_to_record(next_record_pos);
            let mut to_checksum = Vec::new();

            let byte_count = self.parse_byte_count(&mut to_checksum)?;
            let addr = self.parse_address(&mut to_checksum)?;
            let kind_val = self.parse_type(&mut to_checksum)?;
            let kind = RecordKind::from_int(kind_val).ok_or(invalid_type_error(self.record_idx, kind_val))?;

            if let Some(fixed_byte_count_kind) = FixedByteCountRecord::try_from(kind).ok() {
                let expected_byte_count = record_byte_count(fixed_byte_count_kind);
                if byte_count != expected_byte_count {
                    return Err(invalid_byte_count(self.record_idx, fixed_byte_count_kind, expected_byte_count))
                }
            }

            let mut data = None;
            if byte_count > 0 {
                data = Some(self.parse_data(byte_count, &mut to_checksum)?);
            }

            let checksum = self.parse_checksum()?;
            if !is_checksum_valid(&to_checksum, checksum) {
                return Err(checksum_mismatch_error(self.record_idx));
            }

            let record = Record { addr, kind, data };
            records.push(record);

            self.record_idx += 1;
        }

        Ok(records)
    }

    fn parse_byte_count(&mut self, to_checksum: &mut Vec<u8>) -> Result<u8> {
        let field_size = size_of_field(ConstantSizeField::ByteCount);
        self.check_space_for_field(Field::ByteCount, field_size)?;
        let field_bytes = self.parse_field_hex_string(Field::ByteCount, field_size)?;
        to_checksum.extend_from_slice(&field_bytes);
        Ok(field_bytes.as_slice().get_u8())
    }

    fn parse_address(&mut self, to_checksum: &mut Vec<u8>) -> Result<u16> {
        let field_size = size_of_field(ConstantSizeField::Address);
        self.check_space_for_field(Field::Address, field_size)?;
        let field_bytes = self.parse_field_hex_string(Field::Address, field_size)?;
        to_checksum.extend_from_slice(&field_bytes);
        Ok(field_bytes.as_slice().get_u16())
    }

    fn parse_type(&mut self, to_checksum: &mut Vec<u8>) -> Result<u8> {
        let field_size = size_of_field(ConstantSizeField::Type);
        self.check_space_for_field(Field::Type, field_size)?;
        let field_bytes = self.parse_field_hex_string(Field::Type, field_size)?;
        to_checksum.extend_from_slice(&field_bytes);
        Ok(field_bytes.as_slice().get_u8())
    }

    fn parse_data(&mut self, byte_count: u8, to_checksum: &mut Vec<u8>) -> Result<Vec<u8>> {
        let field_size = byte_count as usize * 2;
        self.check_space_for_field(Field::Data, field_size)?;
        let field_bytes = self.parse_field_hex_string(Field::Data, field_size)?;
        to_checksum.extend_from_slice(&field_bytes);
        Ok(field_bytes)
    }

    fn parse_checksum(&mut self) -> Result<u8> {
        let field_size = size_of_field(ConstantSizeField::Checksum);
        self.check_space_for_field(Field::Checksum, field_size)?;
        let field_bytes = self.parse_field_hex_string(Field::Checksum, field_size)?;
        Ok(field_bytes.as_slice().get_u8())
    }

    fn check_space_for_field(&self, field: Field, field_size: usize) -> Result<()> {
        if self.cursor.is_empty() {
            Err(missing_field_error(self.record_idx, field))
        }
        else if self.cursor.len() < field_size {
            Err(incomplete_field_error(self.record_idx, field))
        } else {
            Ok(())
        }
    }

    fn parse_field_hex_string(&mut self, field: Field, field_size: usize) -> Result<Vec<u8>> {
        let hex_string = self.get_field_hex_string(field_size);
        hex::hex_string_to_bytes(hex_string).map_err(|e| invalid_hex_error(self.record_idx, field, e))
    }

    fn get_field_hex_string(&mut self, field_size: usize) -> &[u8] {
        let hex_string = &self.cursor[..field_size];
        self.cursor = &self.cursor[field_size..];
        hex_string
    }

    fn advance_to_record(&mut self, record_pos: usize) {
        self.cursor = &self.cursor[record_pos..];
    }

    fn find_next_record(&self) -> Option<usize> {
        const START_CODE_CHAR: u8 = b':';
        self.cursor.iter().position(|&b| b == START_CODE_CHAR).map(|pos| pos + 1)
    }
}

fn is_checksum_valid(to_checksum: &[u8], checksum: u8) -> bool {
    let mut calculated: u16 = 0;
    for &value in to_checksum {
        calculated = (calculated + value as u16) & 0xff;
    }
    // Two's complement: flip each bit then add 1.
    calculated = (calculated ^ 0xff) + 1;
    (calculated & 0xff) as u8 == checksum
}

pub fn process_records(records: Vec<Record>) -> ProcessRecordResults {
    let mut chunks = Vec::with_capacity(records.len());
    let mut base_addr: u32 = 0;
    let mut segment_start: Option<SegmentStart> = None;
    let mut linear_start: Option<u32> = None;
    let mut ended_with_eof_record = false;

    for record in records {
        /*match record.kind {
            RecordKind::Data => {
                
            }
            RecordKind::EndOfFile => ,
            RecordKind::ExtendedSegmentAddress => ,
            RecordKind::StartSegmentAddress => ,
            RecordKind::ExtendedLinearAddress => ,
            RecordKind::StartLinearAddress => ,
        }*/
    }

    ProcessRecordResults {
        chunks,
        segment_start,
        linear_start,
        ended_with_eof_record,
    }
}

pub struct ProcessRecordResults {
    chunks: Vec<Chunk>,
    segment_start: Option<SegmentStart>,
    linear_start: Option<u32>,
    ended_with_eof_record: bool,
}

pub struct Chunk {
    pub addr: u32,
    data: Vec<u8>,
}

impl Chunk {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

pub struct SegmentStart {
    pub cs: u16,
    pub ip: u16,
}

pub struct Record {
    addr: u16,
    kind: RecordKind,
    data: Option<Vec<u8>>,
}

#[derive(Copy, Clone)]
pub enum RecordKind {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

#[derive(Debug, Copy, Clone)]
pub enum FixedByteCountRecord {
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

impl fmt::Display for FixedByteCountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FixedByteCountRecord::*;
        match self {
            EndOfFile => write!(f, "EndOfFile"),
            ExtendedSegmentAddress => write!(f, "ExtendedSegmentAddress"),
            StartSegmentAddress => write!(f, "StartSegmentAddress"),
            ExtendedLinearAddress => write!(f, "ExtendedLinearAddress"),
            StartLinearAddress => write!(f, "StartLinearAddress"),
        }
    }
}

impl TryFrom<RecordKind> for FixedByteCountRecord {
    type Error = ();

    fn try_from(kind: RecordKind) -> std::result::Result<Self, Self::Error> {
        match kind {
            RecordKind::Data => Err(()),
            RecordKind::EndOfFile => Ok(FixedByteCountRecord::EndOfFile),
            RecordKind::ExtendedSegmentAddress => Ok(FixedByteCountRecord::ExtendedSegmentAddress),
            RecordKind::StartSegmentAddress => Ok(FixedByteCountRecord::StartSegmentAddress),
            RecordKind::ExtendedLinearAddress => Ok(FixedByteCountRecord::ExtendedLinearAddress),
            RecordKind::StartLinearAddress => Ok(FixedByteCountRecord::StartLinearAddress),
        }
    }
}

fn record_byte_count(record: FixedByteCountRecord) -> u8 {
    use FixedByteCountRecord::*;
    match record {
        EndOfFile => 0,
        ExtendedSegmentAddress => 2,
        StartSegmentAddress => 4,
        ExtendedLinearAddress => 2,
        StartLinearAddress => 4,
    }
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
}

fn missing_field_error(record_idx: usize, field: Field) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::ParseField { field, kind: ParseFieldError::Missing } }
}

fn incomplete_field_error(record_idx: usize, field: Field) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::ParseField { field, kind: ParseFieldError::Incomplete } }
}

fn invalid_hex_error(record_idx: usize, field: Field, error: hex::InvalidHexString) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::ParseField { field, kind: ParseFieldError::InvalidHex(error) } }
}

fn invalid_type_error(record_idx: usize, kind: u8) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::InvalidType(kind) }
}

fn checksum_mismatch_error(record_idx: usize) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::ChecksumMismatch }
}

fn invalid_byte_count(record_idx: usize, record_type: FixedByteCountRecord, expected_byte_count: u8) -> Error {
    Error::ParseRecord { record_idx, kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count } }
}

#[derive(Debug)]
pub enum ParseRecordError {
    ParseField {
        field: Field,
        kind: ParseFieldError
    },
    InvalidType(u8),
    ChecksumMismatch,
    InvalidByteCount {
        record_type: FixedByteCountRecord,
        expected_byte_count: u8,
    },
}

#[derive(Debug)]
pub enum ParseFieldError {
    Missing,
    Incomplete,
    InvalidHex(hex::InvalidHexString),
}

#[derive(Debug, Clone, Copy)]
pub enum Field {
    ByteCount,
    Address,
    Type,
    Data,
    Checksum,
}

enum ConstantSizeField {
    ByteCount,
    Address,
    Type,
    Checksum,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Field::*;
        match self {
            ByteCount => write!(f, "ByteCount"),
            Address => write!(f, "Address"),
            Type => write!(f, "Type"),
            Data => write!(f, "Data"),
            Checksum => write!(f, "Checksum"),
        }
    }
}

fn size_of_field(field: ConstantSizeField) -> usize {
    use ConstantSizeField::*;
    match field {
        ByteCount => 2,
        Address => 4,
        Type => 2,
        Checksum => 2,
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match &self {
            ReadFile(io_error) => write!(f, "error reading the file: {io_error}"),
            NotAscii => write!(f, "not all characters are ASCII"),
            ParseRecord { record_idx, kind } => {
                write!(f, "failed to parse record at index {record_idx}: ")?;
                use ParseRecordError::*;
                match kind {
                    ParseField { field, kind } => {
                        write!(f, "failed to parse {field} field: ")?;
                        use ParseFieldError::*;
                        match kind {
                            Missing => write!(f, "field missing"),
                            Incomplete => write!(f, "field incomplete"),
                            InvalidHex(error) => write!(f, "{error}"),
                        }
                    },
                    InvalidType(kind) => write!(f, "invalid type: {kind}"),
                    ChecksumMismatch => write!(f, "checksum mismatch"),
                    InvalidByteCount { record_type, expected_byte_count} => {
                        write!(f, "byte count must be {expected_byte_count} for {record_type} records")
                    }
                }
            }
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use super::*;

    use std::path::PathBuf;

    fn test_file_path(name: &str) -> PathBuf {
        let mut path: PathBuf = ["..", "test"].iter().collect();
        path.push(name);
        path
    }

    #[test]
    fn single_valid_data_record() {
        let path = test_file_path("single_valid_data_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert!(records.len() == 1);
    }

    #[test]
    fn invalid_byte_count() {
        let path = test_file_path("invalid_byte_count.hex");
        let records = parse_hex_file(path);
        let record_type2 = FixedByteCountRecord::ExtendedLinearAddress;
        let expected_byte_count = record_byte_count(record_type2);
        assert!(matches!(records,
            Err(Error::ParseRecord {
                record_idx: _,
                kind: ParseRecordError::InvalidByteCount {
                    record_type: record_type2,
                    expected_byte_count: expected_byte_count
                }
            }
        )));
    }
}