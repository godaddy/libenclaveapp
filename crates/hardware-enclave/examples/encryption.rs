// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT
#![cfg(any(feature = "signing", feature = "encryption"))]

//! Demonstrates encryption key lifecycle and ECIES encrypt/decrypt.
//!
//! Run with real hardware:
//! ```text
//! cargo run --example encryption
//! ```
//! Run with software mock (CI-safe, no hardware required):
//! ```text
//! ENCLAVE_MOCK=1 cargo run --example encryption --features mock
//! ```

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if std::env::var("ENCLAVE_MOCK").as_deref() == Ok("1") {
        std::env::set_var("ENCLAVEAPP_MOCK_STORAGE", "1");
    }

    run()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    use hardware_enclave::{create_encryptor, AccessPolicy, EnclaveConfig};

    let mode = if std::env::var("ENCLAVEAPP_MOCK_STORAGE").is_ok() {
        "[mock]"
    } else {
        "[hardware]"
    };
    println!("{mode} Using platform encryption backend.");

    let config = EnclaveConfig::new("enclave-example", "example-enc-key");
    let enc = create_encryptor(&config)?;

    if enc.key_exists("example-enc-key")? {
        enc.delete_key("example-enc-key")?;
    }

    let pubkey = enc.generate_key("example-enc-key", AccessPolicy::None)?;
    println!(
        "{mode} Generated key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    let plaintext = b"my secret credential";
    let ciphertext = enc.encrypt("example-enc-key", plaintext)?;
    println!(
        "{mode} Encrypted {} bytes → {} bytes.",
        plaintext.len(),
        ciphertext.len()
    );

    assert_eq!(ciphertext[0], 0x01, "ECIES version byte must be 0x01");
    let expected_len = 1 + 65 + 12 + plaintext.len() + 16;
    assert_eq!(ciphertext.len(), expected_len);
    println!("{mode} Ciphertext format validated.");

    let decrypted = enc.decrypt("example-enc-key", &ciphertext)?;
    assert_eq!(decrypted.as_slice(), plaintext);
    println!(
        "{mode} Decrypt roundtrip verified: {:?}",
        std::str::from_utf8(&decrypted)?
    );

    let ct2 = enc.encrypt("example-enc-key", plaintext)?;
    assert_ne!(
        ciphertext, ct2,
        "Each encryption must produce different ciphertext"
    );
    println!("{mode} Fresh encryption produces different ciphertext.");

    enc.delete_key("example-enc-key")?;
    assert!(!enc.key_exists("example-enc-key")?);
    println!("{mode} Encryption example complete.");
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
