use intel_hex::*;

use std::path::PathBuf;

fn test_file_path(name: &str) -> PathBuf {
    let mut path: PathBuf = ["..", "test_files"].iter().collect();
    path.push(name);
    path
}

#[test]
    fn realistic_file() {
        let path = test_file_path("arduplane.hex");
        let records = parse_hex_file(path).expect("parse failed");
        assert_eq!(records.len(), 106_962);
    }