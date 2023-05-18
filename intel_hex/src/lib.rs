use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

pub fn parse_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let data = fs::read_to_string(path).map_err(|e| Error::ReadFile(e))?;
    parse_from_str(data.as_str())
}

pub fn parse_from_str(data: &str) -> Result<Vec<u8>> {
    let mut parser = Parser::new(data);
    parser.parse()
}

struct Parser<'a> {
    data: &'a str,
    base_addr: u32,
}

impl<'a> Parser<'a> {
    fn new(data: &'a str) -> Self {
        Parser { data, base_addr: 0 }
    }

    fn parse(&mut self) -> Result<Vec<u8>> {
        for line in self.data.lines().filter(|l| !l.is_empty()) {
            let record = Record::parse(line)?;
        }

        Ok(vec![])
    }
}

struct Record {
    addr: u16,
    data: Vec<u8>,
    kind: RecordKind,
}

impl Record {
    fn parse(line: &str) -> Result<Record> {
        if !line.starts_with(':') {
            let start_code: u8 = Into<u32>::into(line.chars().next().unwrap()) as u8;
            return Err(Error::ParseRecord(ParseRecord::InvalidStartCode(line.chars().first().)));
        }

        todo!()
    }
}

enum RecordKind {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

impl RecordKind {
    fn new(kind: u8) -> Result<Self> {
        use RecordKind::*;
        match kind {
            0 => Ok(Data),
            1 => Ok(EndOfFile),
            2 => Ok(ExtendedSegmentAddress),
            3 => Ok(StartSegmentAddress),
            4 => Ok(ExtendedLinearAddress),
            5 => Ok(StartLinearAddress),
            t => Err(Error::ParseRecord(ParseRecord::InvalidType(t))),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ReadFile(io::Error),
    ParseRecord(ParseRecord),
}

#[derive(Debug)]
enum ParseRecord {
    InvalidStartCode(u8),
    InvalidType(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            ReadFile(e) => write!(f, "failed to read the file: {e}"),
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
