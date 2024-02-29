use ed25519_dalek::{SigningKey as DalekSigningKey, Signer};
use rand::rngs::OsRng;
use borsh::{BorshSerialize};
use std::fs::File;
use std::io::Write;

const NUM_LINES: usize = 25;
const NUM_ENTRIES: usize = 100g;

fn main() {
    let mut file = File::create("output.txt").unwrap();

    for _ in 0..NUM_LINES {
        let input = generate_data();
        let serialized = input.try_to_vec().unwrap();
        writeln!(file, "{}", hex::encode(serialized)).unwrap();
    }
}

fn generate_data() -> Vec<(Vec<u8>, Vec<u8>, [u8;32])> {
    let mut csprng = OsRng{};
    let mut data = Vec::with_capacity(NUM_ENTRIES);

    for _ in 0..NUM_ENTRIES {
        let sk = DalekSigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        let msg: Vec<u8> = (0..512).map(|_| rand::random::<u8>()).collect();
        let sig = sk.sign(&msg);

        data.push((msg, sig.to_bytes().to_vec(), pk.to_bytes()));
    }

    data
}
