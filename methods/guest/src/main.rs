#![no_main]

use std::convert::TryInto;
use risc0_zkvm::guest::env;
use ed25519_dalek::{
    Signature as DalekSignature, VerifyingKey as DalekPublicKey,Verifier
};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let input: Vec<(Vec<u8>,Vec<u8>,[u8;32])> = env::read();
    let mut verif = true;
    for (msg, raw_sig, raw_pubkey) in input {
        let pubkey = DalekPublicKey::from_bytes(&raw_pubkey).unwrap();
        let sig = DalekSignature::from_bytes(&raw_sig.try_into().unwrap());
        verif = verif && pubkey.verify(&msg,&sig).is_ok();
    }
    env::commit(&verif);
}
