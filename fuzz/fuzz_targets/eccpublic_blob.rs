#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the BCRYPT_ECCKEY_BLOB parser (TPM public key export format).
    let _ = enclaveapp_windows::convert::eccpublic_blob_to_sec1(data);
});
