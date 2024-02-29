// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{
    ED_VERIFIER_ELF, ED_VERIFIER_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use borsh::{BorshDeserialize};
use std::fs::File;
use std::io::{BufReader, BufRead,  BufWriter, Write};
use std::path::Path;
use std::time::Instant;

fn main() {
    env_logger::init();

    let path = Path::new("output.txt");
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);

    let proofs_file = File::create("proofs.txt").unwrap();
    let mut writer = BufWriter::new(proofs_file);

    for (c, line) in reader.lines().enumerate() {
        let encoded = line.unwrap();
        let decoded = hex::decode(&encoded).unwrap();
        let input: Vec<(Vec<u8>, Vec<u8>, [u8;32])> = Vec::try_from_slice(&decoded).unwrap();

        let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
        let start = Instant::now();
        println!("started proving line {}: num sigs: {}", c+1, input.len());
        let prover = default_prover();
        let receipt = prover.prove(env, ED_VERIFIER_ELF).unwrap();
        let elapsed = start.elapsed();
        println!("Proof generated in {:.2?} seconds", elapsed.as_secs_f32());
        let serialized_receipt = hex::encode(bincode::serialize(&receipt).unwrap());
        writeln!(writer, "{}", serialized_receipt).unwrap();
        receipt.verify(ED_VERIFIER_ID).expect("Proof verification should succeed");
    }
    writer.flush().unwrap();
}
