# Codex Changes Review Report

**Date:** 2026-04-14
**Scope:** All commits from `e1d1c9a` (2026-04-13 14:59) through `b0895f9` (2026-04-14 12:01)
**Commits reviewed:** 19 non-merge commits across 37 files, +2264/-1445 lines
**Current state:** Build passes, all tests pass, clippy clean, fmt clean

---

## Summary

The changes fall into several categories:
1. Security hardening (label validation, path traversal prevention, atomic writes)
2. Bridge protocol evolution (`biometric: bool` replaced by `AccessPolicy`)
3. Key lifecycle consistency (duplicate detection, cleanup on failure, delete behavior)
4. Platform-specific improvements (WSL UTF-16, Swift bridge delete, CNG error handling)
5. New shared state module for Windows (`state.rs`)
6. Linux TPM encryption support added to `app-storage`

Overall the changes are directionally good and address real defects. However, there are two critical issues that need to be fixed before this can be considered production-ready.

---

## FOLLOW-UP

### 1. Bridge client has zero functional test coverage

**File:** `crates/enclaveapp-bridge/src/client.rs`

The bridge crate has 20 tests in `protocol.rs` (serialization roundtrips) but only 1 trivial test in `client.rs`. The `call_bridge` / `bridge_init` / `bridge_encrypt` / `bridge_decrypt` / `bridge_destroy` functions have no test coverage for their spawn-write-read-wait pipeline.

**Recommendation: Add tests.** Use shell script stubs to verify the pipeline works correctly, including error cases (bridge returns error, bridge exits non-zero, empty response).

---

## Consuming App Verification

All three consuming apps were checked against the current libenclaveapp HEAD.

### awsenc (`~/awsenc`)

- **Build:** PASSES
- **Tests:** All 59 tests pass
- **Clippy:** Clean
- **FIXED:** Bridge `access_policy` field mismatch resolved in godaddy/awsenc#15.

### sshenc (`~/sshenc`)

- **Build:** PASSES
- **Tests:** All 345 tests pass
- **Clippy:** Clean
- **No issues found.**

### sso-jwt (`~/sso-jwt`)

- **Build:** PASSES
- **Tests:** 156 passed, 1 failed (pre-existing test pollution bug in `config_dir_ends_in_sso_jwt`, unrelated to libenclaveapp)
- **Clippy:** Clean
- **FIXED:** Bridge `access_policy` field mismatch resolved in godaddy/sso-jwt#12.

---

## Summary of Action Items

| Priority | Item | Recommendation |
|----------|------|----------------|
| FOLLOW-UP | Bridge client has no functional tests (#1) | Add shell-script-based tests for the spawn/communicate pipeline |
