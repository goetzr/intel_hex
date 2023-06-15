use std::path::Path;
use std::fmt;
use std::fs;
use std::io;

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

    // How should parsing work?
    // If we return an iterator, we could process each record as it's parsed.
    // Nothing about the hex file says that the records need to write to consecutive memory addresses,
    // so we'd be forced to seek around in the output file.
    // To avoid this we could write to memory, but the iterator approach doesn't give us
    // the full size of the binary file, so we can't allocate the memory upfront.
    //
    // Another approach would be to parse all the records at once, storing each parsed
    // record in the parser.
    // Only Data records would be stored. Other records would be processed inline.
    // Think about End of File records.
    // Ignore Start Segment/Linear Address records.
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