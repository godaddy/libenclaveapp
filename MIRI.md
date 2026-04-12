# Running Miri Tests

Miri validates memory safety of pure-Rust code, catching undefined behavior,
out-of-bounds access, use-after-free, and other memory safety violations.

## Prerequisites

```sh
rustup toolchain install nightly
rustup +nightly component add miri
```

## Running

```sh
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p enclaveapp-core --lib
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p enclaveapp-windows --lib
```

### What runs under Miri

| Crate | Passed | Ignored | Notes |
|-------|--------|---------|-------|
| enclaveapp-core | 37 | 22 | config + metadata file I/O tests ignored |
| enclaveapp-windows | 31 | 0 | All tests pass (pure byte manipulation) |

### What is NOT tested

Tests marked `#[cfg_attr(miri, ignore)]` use platform FFI that Miri cannot interpret:

- `libc::umask` / `libc::chmod` (POSIX FFI) used by `ensure_dir` and `restrict_file_permissions`
- `dirs::data_dir()` / `dirs::config_dir()` call `getpwuid_r` (POSIX FFI)
- File I/O with `mkdir` under Miri isolation mode

These tests still run normally under `cargo test`.

## Notes

- `--lib` is required to skip doc-tests, which have toolchain compatibility issues with Miri.
- `-Zmiri-disable-isolation` is needed because `SystemTime::now()` requires clock access.
- `cargo +nightly` syntax requires rustup proxy; use `rustup run nightly cargo` instead if it fails.
