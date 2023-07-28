use std::path::PathBuf;
use std::process;
use std::sync::OnceLock;

use intel_hex::*;

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

#[test]
fn flash_realistic_file() {
    let path = test_file_path("arduplane.hex");
    let records = parse_hex_file(path).expect("parse failed");
    let output = process_records(records).expect("process failed");
    let total_bytes_read: usize = output.chunks.iter().map(|c| c.data().len()).sum();
    let flash_blocks: Vec<_> = flash_blocks::<_, 512>(output.chunks.into_iter()).collect();
    let total_bytes_written: usize = flash_blocks
        .iter()
        .map(|b| b.initialized().iter().filter(|&b| *b).count())
        .sum();
    println!(
        "Read a total of {} data bytes from the hex file",
        total_bytes_read
    );
    println!("Wrote {} blocks to flash", flash_blocks.len());
    println!(
        "Wrote a total of {} data bytes to flash",
        total_bytes_written
    );
}
