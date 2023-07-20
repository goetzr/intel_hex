fn main() {
    // Input: "12345678"
    // Output: 0xec

}

fn to_bytes(hex_string: &str) -> Vec<u8> {
    // hex_string
    //     .as_bytes()
    //     .chunks(2)

    Vec::<u8>::new()
}

fn to_hex_digit(val: u8) -> u8 {
    match val {
        b'0' ..= b'9' => val - b'0',
        b'a' ..= b'f' => 10 + (val - b'a'),
        b'A' ..= b'F' => 10 + (val - b'A'),
        _ => panic!("invalid hex digit: {}", val),
    }
}