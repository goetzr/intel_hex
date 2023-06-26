use std::path::Path;
use std::fmt;
use std::fs;
use std::io;

mod flash;

pub struct HexFileParser {
    contents: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    ReadFile(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ERROR")
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl HexFileParser {
    pub fn new<P: AsRef<Path>>(hex_file_path: P) -> Result<Self> {
        let contents = fs::read(hex_file_path).map_err(Error::ReadFile)?;
        Ok(HexFileParser { contents })
    }

    // Hex files do not need to contain contiguous data.
    // Bytes not specified in the hex file should not be set.
    // The data in hex files is not intended to be written to files.
    // It's intended to be written to EEPROM.
    //
    // Line endings are not required. Start code marks the start of the next record.
    // Only return Data records. Return these as Chunks.
    //
    // Ignore Start Segment Address and Start Linear Address records.
    // Process Extended Segment Address and Extended Linear Address records as they are encountered.
    //
    // Return iterator.
    // What to do if the hex file doesn't end with a End of File record?

    /*
    // The records iterator is the main iterator that parses out the records from the file.
    for rec in hex_file.records() {
        // process record
    }

    // The data chunks iterator uses the records iterator, processing Address records to resolve data records into data chunks.
    for chunk in hex_file.data_chunks() {
        // process chunk
    }

    // All records should be processed for an Intel Hex file.
    // Only processing the first n records or skipping over certain types of records doesn't really make sense.
    // The only records you may want to skip over would be Start Address records, which you 
    let hex_file = IntelHexFile::parse("path/to/file")?;

     */
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_FILE: &'static str = "/home/rgoetz/projects/intel_hex/arduplane.hex";

    #[test]
    fn reads_hex_file() {
        let parser = HexFileParser::new(HEX_FILE).expect("HexFileParser failed to read the hex file");
        let contents = fs::read(HEX_FILE).expect("fs::read failed to read the hex file");
        assert_eq!(parser.contents, contents);
    }

    #[test]
    fn fails_to_read_missing_hex_file() {
        assert!(matches!(HexFileParser::new("/path/to/missing"), Err(Error::ReadFile(_))));
    }

    // #[test]
    // fn parsing_works() {
    //     unimplemented!()
    //     // const INPUT: &'static str = "/home/rgoetz/projects/intel_hex/arduplane.hex";
    //     // let parser = HexFileParser::new(INPUT)?;
    //     // for record in parser.records() {

    //     // }
    // }

    // fn building_works() {
    //     unimplemented!()
    //     // const OUTPUT: &'static str = "/home/rgoetz/projects/intel_hex/arduplane.bin";
    //     // let parser = HexFileParser::new(INPUT)?;
    // }
}