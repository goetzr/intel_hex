use std::fmt;
use std::path::Path;
use std::fs;
use std::io;

pub struct HexFileParser<'a> {
    content: Content<'a>,
    cursor: &'a [u8],
}

enum Content<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for Content<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self {
            Content::Borrowed(content) => content,
            Content::Owned(content) => &content,
        }
    }
}

impl<'a> HexFileParser<'a> {
    /// Creates an Intel Hex file parser from the file's contents.
    /// 
    /// # Errors
    /// 
    /// This function will return an error if an error is encountered reading the file.
    /// 
    /// It will also return an error if the content is not ASCII.
    /// 
    /// # Examples
    /// 
    /// ```
    /// When exactly don't we have a file????????????????????????????????????????????????
    /// fn parse_hex_file(content: &[u8]) {
    ///     let parser = HexFileParser::from_content(content).expect("")
    /// }
    /// ```
    pub fn from_content<T: AsRef<[u8]>>(content: T) -> Result<Self> {
        let content = content.as_ref();
        if content.is_ascii() {
            Ok(HexFileParser { content: Content::Borrowed(content), cursor: content })
        } else {
            Err(Error::NotAscii)
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read(path).map_err(Error::ReadFile)?;
        if content.is_ascii() {
            Ok(HexFileParser { content: Content::Owned(content), cursor: &content })
        } else {
            Err(Error::NotAscii)
        }
    }

    /// Returns an iterator over the records in the Intel Hex file.
    /// 
    /// # Examples
    /// 
    /// Basic usage:
    /// 
    /// ```
    /// let content = std::fs::read("/path/to/intel_hex_file");
    /// let parser = HexFileParser::new(&content)?;
    /// for rec in parser.records() {
    ///     println!("#?", rec);
    /// }
    /// ```
    pub fn records(&self) -> Records {
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