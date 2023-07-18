use intel_hex::*;

use std::path::PathBuf;

fn test_file_path(name: &str) -> PathBuf {
    let mut path: PathBuf = ["..", "test_files"].iter().collect();
    path.push(name);
    path
}

#[test]
fn parse_realistic_file() {
    let path = test_file_path("arduplane.hex");
    let records = parse_hex_file(path).expect("parse failed");
    assert_eq!(records.len(), 106_962);
}

#[test]
fn process_realistic_file() {
    let path = test_file_path("arduplane.hex");
    let records = parse_hex_file(path).expect("parse failed");
    let num_data_recs = records
        .iter()
        .filter(|rec| rec.kind == RecordKind::Data)
        .count();
    let output = process_records(records).expect("process failed");
    assert!(output.start_addr.is_none());
    assert_eq!(output.chunks.len(), num_data_recs);
    assert_eq!(output.chunks[0].addr >> 16, 0x0800);
}
