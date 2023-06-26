/// let content = std::fs::read("/path/to/intel_hex_file");
/// for rec in records(&content) {
///     // process rec
/// }
pub fn records(content: &[u8]) -> Records {
    Records::new(content)
}

pub struct Records<'a> {
    content: &'a [u8],
}

impl<'a> Records<'a> {
    fn new(content: &'a [u8]) -> Self {
        // TODO: Ensure contents are ASCII. Return result.
        Records { content }
    }

    fn skip_to_next_record(&mut self) {
        self.content.
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
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