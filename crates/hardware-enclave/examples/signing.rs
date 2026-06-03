// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT
#![cfg(any(feature = "signing", feature = "encryption"))]

//! Demonstrates signing key lifecycle and ECDSA P-256 signing.
//!
//! Run with real hardware:
//!
//! ```text
//! cargo run --example signing
//! ```
//!
//! Run with software mock (CI-safe, no hardware required):
//!
//! ```text
//! ENCLAVE_MOCK=1 cargo run --example signing --features mock
//! ```
//!
//! When `ENCLAVE_MOCK=1` is set the example sets `ENCLAVEAPP_MOCK_STORAGE=1`
//! and uses a software key backend backed by a temporary directory — no
//! Secure Enclave, TPM, or system keyring is accessed.

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let mock_mode = std::env::var("ENCLAVE_MOCK").as_deref() == Ok("1");
    if mock_mode {
        // Route through software mock — same public API, no hardware required.
        std::env::set_var("ENCLAVEAPP_MOCK_STORAGE", "1");
    }

    run_with_hardware()
}

fn run_with_hardware() -> Result<(), Box<dyn std::error::Error>> {
    use hardware_enclave::{create_signer, AccessPolicy, EnclaveConfig};

    let mode = if std::env::var("ENCLAVEAPP_MOCK_STORAGE").is_ok() {
        "[mock]"
    } else {
        "[hardware]"
    };
    println!("{mode} Using platform signing backend.");

    let config = EnclaveConfig::new("enclave-example", "example-signing-key");
    let signer = create_signer(&config)?;

    // Clean up any leftover key from a previous run.
    if signer.key_exists("example-signing-key")? {
        println!("{mode} Removing leftover key from previous run.");
        signer.delete_key("example-signing-key")?;
    }

    // 1. Generate a hardware-backed P-256 signing key.
    let pubkey = signer.generate_key("example-signing-key", AccessPolicy::None)?;
    println!(
        "{mode} Generated key. Public key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    // 2. Sign data.
    let message = b"hello from the signing example";
    let sig = signer.sign("example-signing-key", message)?;
    println!(
        "{mode} Signature ({} bytes): {}...",
        sig.len(),
        bytes_to_hex(&sig[..8])
    );

    // 3. Verify the DER format.
    assert_eq!(
        sig[0], 0x30,
        "DER ECDSA signature must start with SEQUENCE tag 0x30"
    );
    println!("{mode} Signature format validated.");

    // 4. Verify cryptographically.
    verify_signature(&pubkey, message, &sig)?;
    println!("{mode} Signature cryptographically verified.");

    // 5. list_keys.
    let keys = signer.list_keys()?;
    println!("{mode} list_keys() -> {} key(s)", keys.len());
    assert!(!keys.is_empty(), "at least one key should exist");

    // 6. key_exists.
    assert!(signer.key_exists("example-signing-key")?);

    // 7. delete_key.
    signer.delete_key("example-signing-key")?;
    println!("{mode} Deleted key.");

    // 8. key_exists — false after deletion.
    assert!(!signer.key_exists("example-signing-key")?);
    println!("{mode} Signing example complete.");

    Ok(())
}

fn verify_signature(
    pub_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
    let point = p256::EncodedPoint::from_bytes(pub_bytes)
        .map_err(|e| format!("invalid public key point: {e}"))?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| format!("invalid verifying key: {e}"))?;
    let sig =
        DerSignature::from_bytes(sig_bytes).map_err(|e| format!("invalid DER signature: {e}"))?;
    vk.verify(message, &sig)
        .map_err(|e| format!("signature verification failed: {e}").into())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
