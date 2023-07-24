use std::fmt;

use bytes::Buf;

use crate::common::{Record, RecordKind};

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
            return Err(ProcessError::MixedExtendedAddrRecords(ext_addr_records));
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

#[derive(Debug)]
pub enum ProcessError {
    MultipleStartAddrRecords(Vec<IndexTypePair>),
    MixedExtendedAddrRecords(Vec<IndexTypePair>),
    MissingEofRecord,
    EofRecordNotLast(usize),
    MultipleEofRecords(Vec<usize>),
}

#[derive(Debug, PartialEq)]
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
    use crate::parse::parse_hex_file;
    use crate::common::test::test_file_path;

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

    #[test]
    fn start_addr_set_linear() {
        let path = test_file_path("start_addr_set_linear.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records).expect("process failed");
        assert!(matches!(
            output.start_addr,
            Some(StartAddress::Linear(addr))
                if addr == 0x12345678
        ));
    }

    #[test]
    fn base_addr_set_segmented() {
        let path = test_file_path("base_addr_set_segmented.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records).expect("process failed");
        assert_eq!(output.chunks.len(), 1);
        assert_eq!(output.chunks[0].addr, 0x179b8);
    }

    #[test]
    fn base_addr_set_linear() {
        let path = test_file_path("base_addr_set_linear.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records).expect("process failed");
        assert_eq!(output.chunks.len(), 1);
        assert_eq!(output.chunks[0].addr, 0x12345678);
    }

    #[test]
    fn multiple_base_addrs() {
        let path = test_file_path("multiple_base_addrs.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records).expect("process failed");
        assert_eq!(output.chunks.len(), 2);
        assert_eq!(output.chunks[0].addr, 0x12345678);
        assert_eq!(output.chunks[1].addr, 0x56785678);
    }

    #[test]
    fn missing_eof_record() {
        let path = test_file_path("missing_eof_record.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records);
        assert!(matches!(
            output,
            Err(ProcessError::MissingEofRecord)
        ));
    }

    #[test]
    fn eof_record_not_last() {
        let path = test_file_path("eof_record_not_last.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records);
        assert!(matches!(
            output,
            Err(ProcessError::EofRecordNotLast(0))
        ));
    }

    #[test]
    fn multiple_eof_records() {
        let path = test_file_path("multiple_eof_records.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records);
        assert!(matches!(
            output,
            Err(ProcessError::MultipleEofRecords(indices))
                if indices == vec![0, 2]
        ));
    }

    #[test]
    fn multiple_start_addr_records() {
        let path = test_file_path("multiple_start_addr_records.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records);
        assert!(matches!(
            output,
            Err(ProcessError::MultipleStartAddrRecords(indices))
                if indices == vec![
                    IndexTypePair { index: 0, kind: RecordKind::StartLinearAddress },
                    IndexTypePair { index: 2, kind: RecordKind::StartLinearAddress },
                ]
        ));
    }

    #[test]
    fn mixed_extended_addr_records() {
        let path = test_file_path("mixed_extended_addr_records.hex");
        let records = parse_hex_file(path).expect("parse failed");
        let output = process_records(records);
        assert!(matches!(
            output,
            Err(ProcessError::MixedExtendedAddrRecords(indices))
                if indices == vec![
                    IndexTypePair { index: 0, kind: RecordKind::ExtendedLinearAddress },
                    IndexTypePair { index: 2, kind: RecordKind::ExtendedSegmentAddress },
                ]
        ));
    }
}