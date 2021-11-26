//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. For testing purpose.
use std::io::prelude::*;
use std::io::stdout;

use concrete_csprng::{seeders, Aesni, RandomBytesGenerator, RandomGenerator, Seeder};

pub fn main() {
    let aes_key = seeders::hardware::x86_64::RDSeed::try_new()
        .and_then(|mut s| s.seed_key())
        .unwrap();
    let mut generator = RandomGenerator::<Aesni>::try_new(aes_key).unwrap();
    let mut stdout = stdout();
    let mut buffer = [0u8; 16];
    loop {
        generator.generate_bytes_exact(&mut buffer).unwrap();
        stdout.write_all(&buffer).unwrap();
    }
}
