use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

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
where
    P: AsRef<Path>,
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
        HexFileParser {
            cursor: content,
            record_idx: 0,
        }
    }

    fn parse(&mut self) -> Result<Vec<Record>> {
        let mut records = Vec::new();

        while let Some(next_record_pos) = self.find_next_record() {
            self.advance_to_record(next_record_pos);
            let mut to_checksum = Vec::new();

            let byte_count = self.parse_byte_count(&mut to_checksum)?;
            let addr = self.parse_address(&mut to_checksum)?;
            let kind_val = self.parse_type(&mut to_checksum)?;
            let kind = RecordKind::from_int(kind_val)
                .ok_or(invalid_type_error(self.record_idx, kind_val))?;

            if let Ok(fixed_byte_count_kind) = FixedByteCountRecord::try_from(kind) {
                let expected_byte_count = record_byte_count(fixed_byte_count_kind);
                if byte_count != expected_byte_count {
                    return Err(invalid_byte_count(
                        self.record_idx,
                        fixed_byte_count_kind,
                        expected_byte_count,
                    ));
                }
            } else {
                // Must be a Data record.
                if byte_count == 0 {
                    return Err(empty_data_record(self.record_idx));
                }
            }

            let mut data = None;
            if byte_count > 0 {
                data = Some(self.parse_data(byte_count, &mut to_checksum)?);
            }

            let checksum = self.parse_checksum()?;
            let calculated_checksum = calculate_checksum(&to_checksum);
            if checksum != calculated_checksum {
                return Err(checksum_mismatch_error(self.record_idx, calculated_checksum));
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
        } else if self.cursor.len() < field_size {
            Err(incomplete_field_error(self.record_idx, field))
        } else {
            Ok(())
        }
    }

    fn parse_field_hex_string(&mut self, field: Field, field_size: usize) -> Result<Vec<u8>> {
        let hex_string = self.get_field_hex_string(field_size);
        hex::hex_string_to_bytes(hex_string)
            .map_err(|e| invalid_hex_error(self.record_idx, field, e))
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
        self.cursor
            .iter()
            .position(|&b| b == START_CODE_CHAR)
            .map(|pos| pos + 1)
    }
}

fn calculate_checksum(to_checksum: &[u8]) -> u8 {
    let mut calculated: u16 = 0;
    for &value in to_checksum {
        calculated = (calculated + value as u16) & 0xff;
    }
    // Two's complement: flip each bit then add 1.
    calculated = (calculated ^ 0xff) + 1;
    (calculated & 0xff) as u8
}

pub fn process_records(records: Vec<Record>) -> ProcessResult {
    let mut chunks = Vec::with_capacity(records.len());
    let mut base_addr: u32 = 0;
    let mut start_addr: Option<StartAddress> = None;

    let mut eof_records = Vec::new();
    let mut start_addr_records = Vec::new();
    let mut ext_addr_records = Vec::new();

    let num_records = records.len();
    for (idx, record) in records.into_iter().enumerate() {
        match record.kind {
            RecordKind::Data => {
                // Data records are not allowed to be empty.
                let chunk = Chunk {
                    addr: base_addr + record.addr as u32,
                    data: record.data.unwrap(),
                };
                chunks.push(chunk);
            }
            RecordKind::EndOfFile => eof_records.push(idx),
            RecordKind::ExtendedSegmentAddress => {
                // Already verified to have 2 bytes of data.
                base_addr = record.data.unwrap().as_slice().get_u16() as u32 * 16;

                let idx_type_pair = IndexTypePair {
                    index: idx,
                    kind: record.kind,
                };
                ext_addr_records.push(idx_type_pair);
            }
            RecordKind::StartSegmentAddress => {
                // Already verified to have 4 bytes of data.
                let data = record.data.unwrap();
                let mut cursor = data.as_slice();
                let cs = cursor.get_u16();
                let ip = cursor.get_u16();
                let _ = start_addr.replace(StartAddress::Segment(SegmentStart { cs, ip }));

                let idx_type_pair = IndexTypePair {
                    index: idx,
                    kind: record.kind,
                };
                start_addr_records.push(idx_type_pair);
            }
            RecordKind::ExtendedLinearAddress => {
                // Already verified to have 2 bytes of data.
                base_addr = (record.data.unwrap().as_slice().get_u16() as u32) << 16;

                let idx_type_pair = IndexTypePair {
                    index: idx,
                    kind: record.kind,
                };
                ext_addr_records.push(idx_type_pair);
            }
            RecordKind::StartLinearAddress => {
                // Already verified to have 4 bytes of data.
                let _ = start_addr.replace(StartAddress::Linear(
                    record.data.unwrap().as_slice().get_u32(),
                ));

                let idx_type_pair = IndexTypePair {
                    index: idx,
                    kind: record.kind,
                };
                start_addr_records.push(idx_type_pair);
            }
        }
    }

    match eof_records.len() {
        0 => return Err(ProcessError::MissingEofRecord),
        1 => {
            let eof_idx = eof_records[0];
            if eof_idx != num_records - 1 {
                return Err(ProcessError::EofRecordNotLast(eof_idx));
            }
        }
        _ => return Err(ProcessError::MultipleEofRecords(eof_records)),
    };

    if start_addr_records.len() > 1 {
        return Err(ProcessError::MultipleStartAddrRecords(start_addr_records));
    }

    if ext_addr_records.len() > 1 {
        let first_ext_rec = &ext_addr_records[0];
        if !ext_addr_records[1..]
            .iter()
            .all(|pair| pair.kind == first_ext_rec.kind)
        {
            return Err(ProcessError::MixedExtendedAddrRecords(start_addr_records));
        }
    }

    Ok(ProcessOutput { chunks, start_addr })
}

pub struct ProcessOutput {
    pub chunks: Vec<Chunk>,
    pub start_addr: Option<StartAddress>,
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub enum StartAddress {
    Segment(SegmentStart),
    Linear(u32),
}

pub struct SegmentStart {
    pub cs: u16,
    pub ip: u16,
}

pub struct Record {
    pub addr: u16,
    pub kind: RecordKind,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RecordKind::*;
        match self {
            Data => write!(f, "Data"),
            EndOfFile => write!(f, "EndOfFile"),
            ExtendedSegmentAddress => write!(f, "ExtendedSegmentAddress"),
            StartSegmentAddress => write!(f, "StartSegmentAddress"),
            ExtendedLinearAddress => write!(f, "ExtendedLinearAddress"),
            StartLinearAddress => write!(f, "StartLinearAddress"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
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
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::ParseField {
            field,
            kind: ParseFieldError::Missing,
        },
    }
}

fn incomplete_field_error(record_idx: usize, field: Field) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::ParseField {
            field,
            kind: ParseFieldError::Incomplete,
        },
    }
}

fn invalid_hex_error(record_idx: usize, field: Field, error: hex::InvalidHexString) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::ParseField {
            field,
            kind: ParseFieldError::InvalidHex(error),
        },
    }
}

fn invalid_type_error(record_idx: usize, kind: u8) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::InvalidType(kind),
    }
}

fn checksum_mismatch_error(record_idx: usize, expected: u8) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::ChecksumMismatch { expected },
    }
}

fn invalid_byte_count(
    record_idx: usize,
    record_type: FixedByteCountRecord,
    expected_byte_count: u8,
) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::InvalidByteCount {
            record_type,
            expected_byte_count,
        },
    }
}

fn empty_data_record(record_idx: usize) -> Error {
    Error::ParseRecord {
        record_idx,
        kind: ParseRecordError::EmptyDataRecord,
    }
}

#[derive(Debug)]
pub enum ParseRecordError {
    ParseField {
        field: Field,
        kind: ParseFieldError,
    },
    InvalidType(u8),
    ChecksumMismatch {
        expected: u8,
    },
    InvalidByteCount {
        record_type: FixedByteCountRecord,
        expected_byte_count: u8,
    },
    EmptyDataRecord,
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
                    }
                    InvalidType(kind) => write!(f, "invalid type: {kind}"),
                    ChecksumMismatch { expected } => write!(f, "checksum mismatch, expected {:2x}", expected),
                    InvalidByteCount {
                        record_type,
                        expected_byte_count,
                    } => {
                        write!(
                            f,
                            "byte count must be {expected_byte_count} for {record_type} records"
                        )
                    }
                    EmptyDataRecord => write!(f, "data record is empty"),
                }
            }
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum ProcessError {
    MultipleStartAddrRecords(Vec<IndexTypePair>),
    MixedExtendedAddrRecords(Vec<IndexTypePair>),
    MissingEofRecord,
    EofRecordNotLast(usize),
    MultipleEofRecords(Vec<usize>),
}

#[derive(Debug)]
pub struct IndexTypePair {
    pub index: usize,
    pub kind: RecordKind,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to process records: ")?;
        use ProcessError::*;
        match self {
            MultipleStartAddrRecords(index_type_pairs) => {
                write!(f, "multiple start address records: ")?;
                let pairs_str = index_type_pairs
                    .iter()
                    .map(|pair| format!("{{index={}, type={}}}", pair.index, pair.kind))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{pairs_str}")
            }
            MixedExtendedAddrRecords(index_type_pairs) => {
                write!(f, "mixed segmented/linear extended address records: ")?;
                let pairs_str = index_type_pairs
                    .iter()
                    .map(|pair| format!("{{index={}, type={}}}", pair.index, pair.kind))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{pairs_str}")
            }
            MissingEofRecord => write!(f, "EOF record missing"),
            EofRecordNotLast(index) => write!(f, "EOF record not last: located at index {index}"),
            MultipleEofRecords(indices) => {
                let indices_str = indices
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "multiple EOF records: located at indices {indices_str}")
            }
        }
    }
}

impl std::error::Error for ProcessError {}

pub type ProcessResult = std::result::Result<ProcessOutput, ProcessError>;

#[cfg(test)]
mod test {
    use super::*;

    use std::{os::windows::process, path::PathBuf};

    fn test_file_path(name: &str) -> PathBuf {
        let mut path: PathBuf = ["..", "test_files"].iter().collect();
        path.push(name);
        path
    }

    #[test]
    fn single_valid_data_record() {
        let path = test_file_path("single_valid_data_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.addr, 0x8000);
        assert_eq!(record.kind, RecordKind::Data);
        assert!(record.data.is_some());
        let data = record.data.as_ref().unwrap();
        assert_eq!(
            data,
            &vec![
                0x00, 0x06, 0x02, 0x20, 0xED, 0x8C, 0x00, 0x08, 0x75, 0x79, 0x0E, 0x08, 0x81, 0x82,
                0x00, 0x08
            ]
        );
    }

    #[test]
    fn not_terminated_with_newlines() {
        let path = test_file_path("not_terminated_with_newlines.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn comments_between_records() {
        let path = test_file_path("comments_between_records.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn empty_data_record() {
        let path = test_file_path("empty_data_record.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::EmptyDataRecord,
                ..
            })
        );
    }

    #[test]
    fn eof_record_invalid_byte_count() {
        let path = test_file_path("eof_record_invalid_byte_count.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count },
                ..
            }) if record_type == FixedByteCountRecord::EndOfFile &&
                  expected_byte_count == record_byte_count(FixedByteCountRecord::EndOfFile)
        );
    }

    #[test]
    fn ext_seg_addr_record_invalid_byte_count() {
        let path = test_file_path("ext_seg_addr_record_invalid_byte_count.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count },
                ..
            }) if record_type == FixedByteCountRecord::ExtendedSegmentAddress &&
                  expected_byte_count == record_byte_count(FixedByteCountRecord::ExtendedSegmentAddress)
        );
    }

    #[test]
    fn start_seg_addr_record_invalid_byte_count() {
        let path = test_file_path("start_seg_addr_record_invalid_byte_count.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count },
                ..
            }) if record_type == FixedByteCountRecord::StartSegmentAddress &&
                  expected_byte_count == record_byte_count(FixedByteCountRecord::StartSegmentAddress)
        );
    }

    #[test]
    fn ext_lin_addr_record_invalid_byte_count() {
        let path = test_file_path("ext_lin_addr_record_invalid_byte_count.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count },
                ..
            }) if record_type == FixedByteCountRecord::ExtendedLinearAddress &&
                  expected_byte_count == record_byte_count(FixedByteCountRecord::ExtendedLinearAddress)
        );
    }

    #[test]
    fn start_lin_addr_record_invalid_byte_count() {
        let path = test_file_path("start_lin_addr_record_invalid_byte_count.hex");
        let records = parse_hex_file(path);
        matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidByteCount { record_type, expected_byte_count },
                ..
            }) if record_type == FixedByteCountRecord::StartLinearAddress &&
                  expected_byte_count == record_byte_count(FixedByteCountRecord::StartLinearAddress)
        );
    }

    #[test]
    fn data_record() {
        let path = test_file_path("data_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::Data);
    }

    #[test]
    fn eof_record() {
        let path = test_file_path("eof_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::EndOfFile);
    }

    #[test]
    fn ext_seg_addr_record() {
        let path = test_file_path("ext_seg_addr_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::ExtendedSegmentAddress);
    }

    #[test]
    fn start_seg_addr_record() {
        let path = test_file_path("start_seg_addr_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::StartSegmentAddress);
    }

    #[test]
    fn ext_lin_addr_record() {
        let path = test_file_path("ext_lin_addr_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::ExtendedLinearAddress);
    }

    #[test]
    fn start_lin_addr_record() {
        let path = test_file_path("start_lin_addr_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.kind, RecordKind::StartLinearAddress);
    }

    #[test]
    fn invalid_record_type() {
        let path = test_file_path("invalid_record_type.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::InvalidType(6),
                ..
            })
        ));
    }

    #[test]
    fn missing_byte_count() {
        let path = test_file_path("missing_byte_count.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::ByteCount,
                    kind: ParseFieldError::Missing
                },
                ..
            })
        ));
    }

    #[test]
    fn missing_address() {
        let path = test_file_path("missing_address.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Address,
                    kind: ParseFieldError::Missing
                },
                ..
            })
        ));
    }

    #[test]
    fn missing_type() {
        let path = test_file_path("missing_type.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Type,
                    kind: ParseFieldError::Missing
                },
                ..
            })
        ));
    }

    #[test]
    fn missing_data() {
        let path = test_file_path("missing_data.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Data,
                    kind: ParseFieldError::Missing
                },
                ..
            })
        ));
    }

    #[test]
    fn missing_checksum() {
        let path = test_file_path("missing_checksum.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Checksum,
                    kind: ParseFieldError::Missing
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_byte_count() {
        let path = test_file_path("incomplete_byte_count.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::ByteCount,
                    kind: ParseFieldError::Incomplete
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_address() {
        let path = test_file_path("incomplete_address.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Address,
                    kind: ParseFieldError::Incomplete
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_type() {
        let path = test_file_path("incomplete_type.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Type,
                    kind: ParseFieldError::Incomplete
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_data() {
        let path = test_file_path("incomplete_data.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Data,
                    kind: ParseFieldError::Incomplete
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_data_bleeds_into_next_record() {
        let path = test_file_path("incomplete_data_bleeds_into_next_record.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Data,
                    kind: ParseFieldError::InvalidHex(_)
                },
                ..
            })
        ));
    }

    #[test]
    fn incomplete_checksum() {
        let path = test_file_path("incomplete_checksum.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ParseField {
                    field: Field::Checksum,
                    kind: ParseFieldError::Incomplete
                },
                ..
            })
        ));
    }

    #[test]
    fn checksum_mismatch() {
        let path = test_file_path("checksum_mismatch.hex");
        let records = parse_hex_file(path);
        assert!(matches!(
            records,
            Err(Error::ParseRecord {
                kind: ParseRecordError::ChecksumMismatch { expected: _ },
                ..
            })
        ));
    }

    #[test]
    fn start_addr_set_segmented() {
        let path = test_file_path("start_addr_set_segmented.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records).expect("process failed");
        assert!(matches!(
            output.start_addr,
            Some(StartAddress::Segment(SegmentStart { cs, ip }))
                if cs == 0x1234 && ip == 0x5678
        ));
    }
}
