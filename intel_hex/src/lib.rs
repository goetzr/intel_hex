use std::fmt;
use std::path::Path;
use std::fs;
use std::io;

/*
let records = parse_hex_file("/path/to/hexfile")?;  // takes AsRef<Path>, returns Result<Vec<Record>>
let results = process(&records);                    // takes &[Record], returns ProcessResults
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

pub fn parse<P>(path: P) -> Result<Vec<Record>>
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
}

impl<'a> HexFileParser<'a> {
    fn new(content: &'a [u8]) -> Self {
        HexFileParser { cursor: content }
    }

    fn parse(self) -> Result<Vec<Record>> {
        unimplemented!();
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
    ReadFile(io::Error),
    NotAscii,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;