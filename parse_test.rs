use std::fs;

fn main() {
    let content = fs::read_to_string("phalanx.conf").unwrap();
    println!("File loaded");
}
