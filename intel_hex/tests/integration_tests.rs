use intel_hex::*;

use std::path::PathBuf;
use std::process;
use std::sync::OnceLock;

static WORKSPACE_PATH: OnceLock<PathBuf> = OnceLock::new();

fn test_file_path(name: &str) -> PathBuf {
    let workspace_path = WORKSPACE_PATH.get_or_init(|| {
        let output = process::Command::new(env!("CARGO"))
            .arg("locate-project")
            .arg("--workspace")
            .arg("--message-format=plain")
            .output()
            .unwrap()
            .stdout;
        let cargo_toml_path = String::from_utf8(output).unwrap();
        PathBuf::from(cargo_toml_path).join("..")
    });

    let mut file_path = workspace_path.clone();
    file_path.push("test_files");
    file_path.push(name);
    file_path
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
