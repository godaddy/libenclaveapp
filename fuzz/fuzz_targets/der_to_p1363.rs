#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the DER-to-P1363 signature format converter.
    let _ = enclaveapp_windows::convert::der_to_p1363(data);
});
