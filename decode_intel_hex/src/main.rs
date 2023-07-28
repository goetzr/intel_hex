use clap::Parser;

use intel_hex::*;

/*
Usage:
  decode_intel_hex -i arduplane.exe -o arduplane.bin

  NOTE: Both arguments are required.

 */

fn main() {
    if let Err(e) = try_main() {
        eprintln!("ERROR: {}", e);
    } 
}

fn try_main() -> anyhow::Result<()> {
    let records = parse_hex_file("test_files/arduplane.hex")?;
    let output = process_records(records)?;
    println!("{} chunks", output.chunks.len());
    Ok(())
}