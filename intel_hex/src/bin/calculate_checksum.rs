/// Calculates the Intel hex format checksum of a series of bytes specified as a hex string.
/// 
/// Usage:
///   calculate_checksum HEX-STRING
/// 
/// Example:
///   calculate_checksum 12345678
///     prints
///   ec

 use std::env;

fn main() {
    // Input: "12345678"
    // Output: 0xec
    let args: Vec<_> = env::args().skip(1).collect();
    assert_eq!(args.len(), 1);
    let hex_string = &args[0];
    let cs = calculate_checksum(to_bytes(hex_string));
    println!("{:02x}", cs);
}

fn to_bytes(hex_string: &str) -> Vec<u8> {
    assert!(hex_string.len() % 2 == 0, "hex string must have an even number of digits");
    hex_string
        .as_bytes()
        .chunks(2)
        .map(|digit_pair| {
            let high_nibble = to_hex_digit(digit_pair[0]).expect("invalid hex digit");
            let low_nibble = to_hex_digit(digit_pair[1]).expect("invalid hex digit");
            (high_nibble << 4) | low_nibble
        })
        .collect()
}

fn to_hex_digit(val: u8) -> Option<u8> {
    match val {
        b'0' ..= b'9' => Some(val - b'0'),
        b'a' ..= b'f' => Some(10 + (val - b'a')),
        b'A' ..= b'F' => Some(10 + (val - b'A')),
        _ => None
    }
}

fn calculate_checksum(vals: Vec<u8>) -> u8 {
    let mut sum: u16 = 0;
    for val in vals {
        sum = (sum + val as u16) & 0xff;
    }
    ((!sum + 1) & 0xff) as u8
}