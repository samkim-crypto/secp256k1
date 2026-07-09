use {
    k256::ecdsa::SigningKey,
    mollusk_svm::{result::Check, Mollusk},
    sha3::{Digest, Keccak256},
    solana_pubkey::Pubkey,
    solana_secp256k1_program::verify,
    std::{env, path::PathBuf},
};

const PROGRAM_SO_STEM: &str = "solana_secp256k1_program";

fn setup_sbf_env() -> Option<String> {
    let out_dir = "../target/deploy";
    env::set_var("SBF_OUT_DIR", out_dir);

    let path = PathBuf::from(out_dir).join(PROGRAM_SO_STEM);
    let so_path = path.with_extension("so");

    if !so_path.exists() {
        eprintln!(
            "SBF artifact not found at {}; run `cargo build-sbf` first",
            so_path.display()
        );
        return None;
    }

    Some(PROGRAM_SO_STEM.to_string())
}

fn make_mollusk() -> Option<(Mollusk, Pubkey)> {
    let program_name = setup_sbf_env()?;
    let program_id = Pubkey::new_unique();

    let mollusk = Mollusk::new(&program_id, &program_name);

    Some((mollusk, program_id))
}

#[test]
fn test_secp256k1_verify_success() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };

    let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();

    let msg = b"Hello, Pinocchio and Mollusk!";
    let msg_hash = Keccak256::digest(msg);

    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();

    let encoded_point = verifying_key.to_encoded_point(false);
    let uncompressed_pubkey = encoded_point.as_bytes();

    let pubkey_hash = Keccak256::digest(&uncompressed_pubkey[1..65]);
    let mut evm_address = [0u8; 20];
    evm_address.copy_from_slice(&pubkey_hash[12..32]);

    let instruction = verify(
        program_id,
        evm_address,
        signature.to_bytes().into(),
        recovery_id.to_byte(),
        msg,
    );

    mollusk.process_and_validate_instruction(&instruction, &[], &[Check::success()]);
}
