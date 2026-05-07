# Design: meta-HMAC trust anchor — close the migration-attack window

**Status:** Draft, pre-implementation
**Date:** 2026-05-06
**Author:** Jay Gowdy
**Supersedes (in part):** `design-cross-platform-meta-hmac.md` §"Migration"
**Repos:** `libenclaveapp`, `sshenc`

## TL;DR

The shipped `verify_meta_integrity` blesses any `.meta` whose `.meta.hmac` sidecar is absent — it auto-migrates by computing a fresh HMAC over the on-disk meta and writing it as the new sidecar. A same-UID attacker who can edit `.meta` and `rm .meta.hmac` gets that tampered meta authenticated for them. The sidecar promise is null whenever this branch can fire.

This design closes the window with two moves:

1. **Keychain-attribute trust anchor (new keys).** At keygen, the expected meta-HMAC tag is stored as a custom attribute on the per-key wrapping-key Keychain item — same ACL boundary as the wrapping key itself. Tamper without our entitled binary is not possible. Sidecars become a derivable cache, not the root of trust.

2. **Explicit one-shot migration (legacy keys).** Existing keys that pre-date this change have no keychain-stored tag yet. The agent never auto-migrates them. The user runs `sshenc migrate-meta` once after upgrade. The subcommand prints fingerprints, requires explicit `yes`, and writes both the keychain attribute and the sidecar atomically.

After (1) and (2) ship, the agent's verify path has no migrate branch. Missing sidecar OR missing keychain tag is **always tamper**. The auto-migrate hole is gone.

## The flaw, explicitly

Today, `enclaveapp-app-storage::platform::verify_meta_integrity` does:

```text
load .meta from disk
  |
  +-- .meta.hmac present + matches  -> OK
  +-- .meta.hmac present + mismatch -> Err(KeyInitFailed)  // tamper detected
  +-- .meta.hmac missing            -> migrate_meta_to_hmac()  // SILENT BLESS
                                      writes a fresh sidecar over current .meta
```

The migrate branch was added so users upgrading from a pre-HMAC build don't get locked out. That's a real ergonomic concern. But the design conflates two distinct states: "this is a legacy key that has never been sidecar'd" and "this key was tampered with by removing its sidecar." From the agent's perspective on disk, those are indistinguishable.

Concrete attack:

1. Attacker has same UID as the agent, FS access to `~/.sshenc/keys/`.
2. Attacker edits `default.meta`: flips `presence_mode: strict → none`, or relaxes `access_policy`.
3. Attacker `rm default.meta.hmac`.
4. Next agent op (sign / list / inspect) → `verify_meta_integrity` hits the migrate branch → writes fresh `default.meta.hmac` over the tampered meta.
5. Tampered policy is now authenticated. The Touch ID prompt the user expected on every signature is gone. Subsequent ops sign silently.

The defense the prior design promised — "tamper without keychain access is caught" — does not hold in the presence of this branch.

## Threat model recap

We defend against:

- **Same-UID FS attacker:** can read/write any file in `~/.sshenc/`, `~/.ssh/`, `~/.config/sshenc/`. Cannot use our entitled signed binary's Keychain access (different code signature ⇒ different ACL identity).
- **Backup/restore drift:** user restores an old `.meta` from a Time Machine snapshot but not the matching `.meta.hmac`. This looks identical to the attacker case. Treating it as tamper is correct (user's own remediation: `sshenc migrate-meta` after they've inspected the restored state).

We do not defend against:

- **Root / kernel attacker:** can read the keychain directly and bypass the signed-binary ACL. Out of scope.
- **Same-binary attacker:** an attacker who has compromised the signed `sshenc-agent` binary itself. Out of scope (then they can sign anything they want anyway).

The prior design's claim "attacker without keychain access is caught" is the standard we want to actually meet for new keys, with no auto-migrate escape hatch.

## Design

### Component 1 — keychain-attribute trust anchor (new keys)

**On macOS today**, every sshenc key has a per-key Keychain item under service `com.godaddy.sshenc` with account `<label>` storing the wrapped handle blob. The item's ACL is bound to our signed bundle's code signature; cross-binary access fires the approval prompt. This is already our trust anchor for the wrapping key.

We extend that item to also carry the expected HMAC tag of the key's `.meta` JSON, in the Keychain item's `kSecAttrGeneric` attribute (8 bytes max in the C API, but `kSecAttrComment` or a custom-encoded blob inside the existing data field works for arbitrary length — implementation will pick whichever is cleanest).

Concretely:

- **At keygen** (`enclaveapp-apple/src/keychain.rs::generate_and_save_key`):
  - Compute meta JSON as today.
  - Compute `tag = HMAC-SHA256(meta_hmac_key, meta_json_bytes)`.
  - Write `<label>.meta` (atomic).
  - Write `<label>.meta.hmac` (atomic, hex-encoded tag) — derivable cache.
  - Persist the wrapping key + tag together to the Keychain in a single `SecItemAdd`. Tag lives in a stable attribute so subsequent `SecItemCopyMatching` returns it alongside the wrapped blob.

- **At per-op load** (`keychain.rs::load_handle_with_context` and friends):
  - Read the Keychain item once. Get back wrapped handle AND expected tag.
  - Recompute tag of on-disk `.meta`. Compare in constant time to the keychain tag.
    - Match → OK, proceed.
    - Mismatch → `Err(KeyOperation { operation: META_HMAC_VERIFY_OP, ... })`. Refuse to use the key.
  - If `<label>.meta.hmac` is missing on disk, write it from the keychain tag (cache rebuild). This is safe: the keychain tag is the authority, not the file.

- **What about Windows / Linux?** Symmetric: the per-key wrapping-key store on each platform gets the analogous attribute.
  - Windows CNG: use `NCryptSetProperty` on the persisted key handle with a custom property name. (NCrypt allows user-defined properties on persisted keys.)
  - Linux TPM: the `.handle` file on disk is already the per-key wrapping artifact; we extend it with a length-prefixed tag field. Format-versioned to allow future evolution.
  - Linux keyring: the kernel keyring entry for the wrapping key gets the tag in its description or a paired entry. Detail TBD in implementation.

The cross-platform invariant: **the trust anchor for `.meta` integrity is the per-key wrapping-key store, not a free-floating sidecar.** The sidecar exists only as a fast path / crash-resilience cache.

### Component 2 — explicit migration for legacy keys (`sshenc migrate-meta`)

Pre-existing keys (anything generated before Component 1 ships) have no keychain-stored tag. They cannot be safely auto-migrated by the agent because the agent cannot tell tamper from legacy.

We introduce a `sshenc migrate-meta` subcommand — user-driven, interactive by default, scriptable with `--yes`. Behavior:

1. Enumerate keys in `~/.sshenc/keys/`. For each:
   - Compute SHA-256 fingerprint of the current `.meta` JSON.
   - Read current policy fields (`presence_mode`, `access_policy`) for display.
2. Print a summary table:
   ```
   Migrating 3 keys to authenticated metadata. Verify these match what you expect:
     default              policy=strict  fingerprint=ab12…
     github-personal      policy=cached  fingerprint=cd34…
     test-key-a-151317-376 policy=none    fingerprint=ef56…
   Continue? [y/N]
   ```
3. On `y`: for each key, write the keychain-stored tag (Component 1's attribute) AND the on-disk sidecar atomically. If any keychain write fails, abort and report which keys are partially migrated; the command is rerunnable.
4. After all keys migrate, print "Done. Future tampering with .meta will be detected."

**Rationale for the prompt:**
- Human-in-the-loop confirmation is the only thing that distinguishes "I'm upgrading my own install" from "an attacker tampered with my .meta and is about to get me to sign their version." The user reading the fingerprints is the trust signal.
- One-time UX cost. No additional prompts on the steady-state path.
- `--yes` exists for CI / scripted installers, with the explicit understanding that those environments accept the risk.

**The agent never auto-migrates.** Period. After this design ships, the agent's `verify_meta_integrity` collapses to:

```text
read keychain item -> get wrapping blob + stored tag
read .meta from disk
  |
  +-- stored_tag matches HMAC(.meta)  -> OK; rebuild .meta.hmac sidecar if missing
  +-- stored_tag mismatch              -> Err(verify) // tamper
  +-- keychain item has no stored tag  -> Err(legacy_meta) // user must run migrate-meta
```

The legacy_meta error message points the user at `sshenc migrate-meta`.

### Component 3 — kill the existing auto-migrate branch

`enclaveapp-app-storage::platform::verify_meta_integrity` loses its migrate branch entirely:

- Missing sidecar AND missing keychain tag → `Err(StorageError::KeyInitFailed)` with detail pointing at `sshenc migrate-meta` (or, for awsenc/sso-jwt/npmenc, their equivalent).
- Missing sidecar AND keychain tag present → silently rebuild sidecar from keychain tag. No user-visible change. (This is the post-migrate steady state when something deletes the sidecar — the keychain tag is authoritative.)
- Sidecar present + mismatch → tamper, refuse.
- Sidecar present + matches keychain tag → OK.
- Sidecar present + matches HMAC of meta but no keychain tag → still legacy_meta error. The sidecar alone is not the trust anchor anymore.

`enclaveapp-core::metadata::migrate_meta_to_hmac` stays as a public helper but is no longer called from the agent's hot path. It becomes the building block for `sshenc migrate-meta` and similar tools in the other apps.

## What changes in the threat model doc

Today's threat model says "attacker without keychain access is caught for `.meta` tamper." That's currently aspirational on macOS and false in any branch where the auto-migrate path can fire.

Post-design, the threat model entry becomes:

- **For keys generated post-vN.N.N (Component 1 ships):** attacker without keychain access cannot tamper with `.meta` undetected. Mismatch is a hard error at every op.
- **For keys generated pre-vN.N.N:** until the user runs `sshenc migrate-meta`, the agent refuses to use them. The migration command requires interactive confirmation of fingerprints. Trust-on-first-use is explicit and one-shot.

## Out of scope

- **Cross-app migration UX.** awsenc / sso-jwt / npmenc each get their own `<app> migrate-meta` (or equivalent flag on an existing subcommand). Not part of this design — they have different lifecycle stories. We just provide the building block.
- **Backwards compat with existing `.meta.hmac` sidecars that have no keychain tag.** Treating them as legacy_meta is a deliberate choice: if a user already ran the old auto-migrate path, we do not retroactively bless those sidecars, because we cannot tell which were legitimate and which were attacker-induced. The migrate subcommand re-blesses them under the new model.
- **Hardware key attestation.** A future improvement would bind the meta tag to the SE / TPM key's attestation, removing the meta-HMAC key as a separate secret. Out of scope here.

## Rollout

| Step | Repo | Description |
| ---- | ---- | ----------- |
| 1 | libenclaveapp | Add keychain-attribute storage on all platforms. New keygen writes both attribute and sidecar. |
| 2 | libenclaveapp | Read path uses keychain attribute as authority. Sidecar becomes cache. |
| 3 | libenclaveapp | Remove `migrate_meta_to_hmac` call from `verify_meta_integrity`. Hard error on legacy state. |
| 4 | sshenc | Add `sshenc migrate-meta` subcommand with interactive fingerprint confirmation. |
| 5 | libenclaveapp + sshenc | Update threat model doc to reflect the new guarantees. |
| 6 | sshenc | Release notes call out the migrate-meta requirement for upgrading existing installs. |

Steps 1–3 ship as one libenclaveapp PR. Step 4 ships as the matching sshenc PR (depends on the libenclaveapp release tag bumping). Steps 5–6 are doc-only.

## Test plan

### Unit tests

- `verify_meta_integrity` returns `legacy_meta` error when keychain has no tag, regardless of sidecar state.
- `verify_meta_integrity` rebuilds sidecar from keychain tag when sidecar is deleted.
- `verify_meta_integrity` returns tamper error when keychain tag and on-disk meta disagree.
- New keygen writes keychain attribute and sidecar atomically; partial-failure leaves no half-state (transactional rollback already exists in `enclaveapp-core::backup`).

### Integration tests (per platform)

- macOS: sign on a freshly-generated key works; tamper `.meta`; sign returns tamper error; restore `.meta`; sign works again. Each step zero approval prompts on signed bundle.
- Windows: same suite against TPM-backed keys.
- Linux keyring: same suite.
- Linux TPM: same suite.

### End-to-end migration tests

- sshenc: pre-existing key with no keychain tag; `sshenc list` errors with legacy_meta message pointing at migrate-meta; `sshenc migrate-meta --yes` succeeds; subsequent `sshenc list` works; tamper detection holds afterward.
- sshenc: simulated attacker — generate key, drop sidecar, edit meta, run any agent op → must error, must NOT silently re-sign.

### Manual / observational

- Prompt audit: full keygen + sign + list + inspect cycle on signed bundle, count Touch ID prompts. Must equal current count (no regression).

## UX strings — locked

The user-facing language must frame `migrate-meta` as a **one-time
cutover for the version that introduces the keychain tag**, not as a
"run after every upgrade" routine. If users develop a reflex of
running `migrate-meta` after every release, the attack surface from
§"The flaw, explicitly" is restored — just with a user pressing Enter
instead of an automated path. The wording below is chosen to make that
reflex impossible.

Treat the version number `vX.Y.0` as a placeholder — the implementing
release substitutes its own version into the strings below.

### Where the migration marker lives

The marker that distinguishes "first time after upgrade" from "second
time, this is suspicious" is stored **in the legacy macOS Keychain**
under service `com.godaddy.<app>.migrate-marker` / account
`__completed__`, **not in a file**. A file marker (e.g.,
`~/.config/<app>/.meta-migration-completed`) is a trivial deletion
primitive: a same-UID FS attacker simply `rm`s it to fake "first time
after upgrade" and gets the gentle migrate-meta UI back, restoring
the auto-migrate hole the trust anchor closes. The keychain-stored
marker shares the signed-binary ACL with the per-key meta-tags;
attacker without the agent's code signature can neither read nor
delete it.

The agent owns reads and writes via two RPCs
(`SSH_AGENTC_SSHENC_CHECK_MIGRATION_MARKER`,
`SSH_AGENTC_SSHENC_SET_MIGRATION_MARKER`); the CLI never touches the
Keychain directly, preserving the cross-binary ACL invariant.

### Agent `legacy_meta` error message

Printed when the agent encounters a key with no keychain tag (no
`migrate-marker` present in the keychain — i.e., this user has never
migrated):

```
Error: key 'github-personal' has no integrity tag.

This is a one-time migration required by the vX.Y.0 upgrade and is not
something future upgrades will repeat. If you have already run
`sshenc migrate-meta` on this machine, treat this as a tamper signal
— do not run it again. Regenerate the affected key instead.

Before migrating, verify the key's current policy looks correct:
    sshenc inspect github-personal

To migrate: sshenc migrate-meta
```

Stronger variant when `migrate-marker` IS present (user has already
migrated; this should never recur in legitimate use):

```
Error: key 'github-personal' has no integrity tag.

migrate-meta has already been run on this install, so this should not
have recurred. This is a strong tamper signal. Recommended: regenerate
this key. Do NOT run migrate-meta again unless you can independently
explain why this key's tag is missing (e.g., manual restore from
backup of an unrelated machine).

Audit log: ~/.sshenc/agent.err.log
```

### `sshenc migrate-meta` confirmation prompt

```
migrate-meta is the one-time fix for the vX.Y.0 upgrade. Once it
finishes successfully, you will not see this prompt again — future
upgrades will NOT ask you to run it. If this command is ever
suggested again later, it likely means someone has tampered with
your key metadata; regenerate affected keys instead of re-running.

Keys to migrate:
  default                policy=cached  fingerprint=ab12cd34ef56...
  github-personal        policy=cached  fingerprint=ff89aa11bb22...
  test-key-a-151317-376  POLICY=NONE !! fingerprint=cc33dd44ee55...
                         (no biometric required — verify this is
                         intentional before continuing)

Type 'yes' (full word) to migrate, or anything else to cancel.
> _
```

Policy-field highlighting: any key with `presence_mode: none` or
`access_policy: None` prints with the `POLICY=NONE !!` marker and the
explanatory parenthetical. Forces the user to look at the row.

### `sshenc inspect <label>` integrity line

Adds one line at top of existing output:

```
Integrity: OK
```

or

```
Integrity: LEGACY — run `sshenc migrate-meta` (one-time, vX.Y.0 cutover)
```

or (the screaming case after marker is set):

```
Integrity: TAMPER — keychain tag mismatch. Regenerate the key.
```

### `--yes` flag for CI

`sshenc migrate-meta --yes` exists for scripted environments
(unattended installers, CI fixtures). Prints the same warning block
to stderr but skips the interactive confirmation. The man page and
`--help` text call out that `--yes` bypasses the human-review step
that exists for security reasons.

A second-run attempt always requires `--force-rerun-i-understand`
even with `--yes`, so the marker-present strong warning cannot be
short-circuited by ambient automation.

## Cross-platform follow-ups

The macOS-first PR (libenclaveapp #122 + sshenc #196) closes the
auto-migrate hole **for sshenc on macOS only**. Three follow-up
tracks remain. Each is a self-contained PR; the macOS implementation
is the reference template for files / function shapes.

Reference points to mirror:

| Concept | Reference (macOS) |
| --- | --- |
| Per-key keychain meta-tag store | `crates/enclaveapp-apple/src/meta_tag.rs` |
| Migration marker | `crates/enclaveapp-apple/src/meta_migration_marker.rs` |
| Read-only meta-HMAC key access | `enclaveapp_apple::meta_hmac::load_existing` |
| Per-op verify entry point | `crates/enclaveapp-apple/src/keychain.rs::ensure_meta_integrity` |
| Cross-platform helper | `enclaveapp_app_storage::platform::check_meta_integrity` (currently macOS-only branch) |
| Agent RPCs | `SSH_AGENTC_SSHENC_MIGRATE_META`, `SSH_AGENTC_SSHENC_CHECK_MIGRATION_MARKER`, `SSH_AGENTC_SSHENC_SET_MIGRATION_MARKER` in `sshenc-agent-proto/src/message.rs` |

### Track 1: Windows TPM (CNG)

**Crate:** `enclaveapp-windows`.

- **Per-key tag storage.** Two viable mechanisms:
  - `NCryptSetProperty` on the persisted CNG key handle with a
    custom property name (e.g. `L"sshenc-meta-tag"`). Pro: tag
    travels with the key; deleting the key cleans up the tag for
    free. Con: NCrypt custom-property quirks across Windows
    versions; need to test on 10 / 11 / Server 2022.
  - Separate `<%APPDATA%\<app>\.meta-tags\<label>.dpapi>` file
    per key, encrypted via `CryptProtectData(CRYPTPROTECT_UI_FORBIDDEN)`.
    Pro: simpler to implement, mirrors the existing
    `.meta-hmac.dpapi` pattern in `crates/enclaveapp-windows/src/meta_hmac.rs`.
    Con: another file the user can delete (deletion primitive
    risk applies — but DPAPI is bound to the user profile, so a
    fresh write would fail without the right user context, which
    helps).
- **Recommended:** option 1 (`NCryptSetProperty`). Same trust
  domain as the wrapping key.
- **Migration marker:** another DPAPI blob at
  `%APPDATA%\<app>\.migrate-marker.dpapi`. Cannot live in NCrypt
  because no per-key handle exists at marker-set time.
  Alternative: a single keyring-style entry via Windows Credential
  Manager's `CredRead`/`CredWrite` for app-scoped credentials —
  more aligned with the keychain pattern but more code. Pick
  whichever is cheaper.
- **Per-op verify:** add `ensure_meta_integrity` analogue to
  `crates/enclaveapp-windows/src/sign.rs::TpmSigner::sign` (or a
  new helper in `crates/enclaveapp-windows/src/keychain.rs` if
  there is one) that fires before `NCryptSignHash`.
- **Test environment:** must run on a real Windows host with a
  TPM. Hyper-V / Parallels VMs with vTPM enabled should work.
  Plain VMs without vTPM cannot exercise this.
- **Existing CI matrix:** `Check / Test (Windows)` already runs
  on `windows-latest` (currently `windows-2025`). Confirm whether
  GitHub-hosted runners have vTPM (they do not, by default —
  TPM-bound tests will need to be `#[ignore]`d on CI and run
  via a local Windows VM or self-hosted runner).

### Track 2: Linux keyring (software)

**Crate:** `enclaveapp-keyring`.

- **Per-key tag storage.** Two viable mechanisms:
  - Kernel keyring via the `keyutils` crate. `add_key` /
    `keyctl_read` with a per-key keyring entry under a
    user-scoped session keyring. Trust domain: same as the
    wrapping key (per-app keyring entry).
  - File-backed: a sibling file `<keys_dir>/<label>.meta.tag`
    at 0600. **Worse** than the keyring path because it's another
    `rm`-able file — same deletion primitive issue the macOS PR
    explicitly avoided. Avoid unless keyring is unavailable.
- **Recommended:** kernel keyring with file fallback.
- **Migration marker:** keyring entry under
  `enclaveapp:sshenc:migrate-marker` or similar. Same access
  semantics as the meta-HMAC key entry already in
  `enclaveapp-keyring::meta_hmac_key`.
- **Per-op verify:** wire into
  `crates/enclaveapp-keyring/src/sign.rs::SoftwareSigner::sign`
  before the actual ECDSA signature.
- **Note:** the Linux keyring backend is software-only. The
  trust anchor here protects against same-UID FS attackers but
  does not provide hardware-rooted security. Worth being explicit
  about that in the threat model entry — the meta-tag is an
  integrity check, not a confidentiality boundary.

### Track 3: Linux TPM (`enclaveapp-linux-tpm`)

**Caveat first:** the Linux TPM backend currently does **not**
enforce `AccessPolicy` at sign time (per
`libenclaveapp/THREAT_MODEL.md` § "Linux TPM backend"). Adding
meta-tag protection on top of a backend that doesn't gate on
policy is partial — the `AccessPolicy` field could be respected
by the meta-tag check but ignored at the TPM layer. Decide whether
to fix the policy-enforcement gap first or accept that meta-tag is
"integrity for the displayed value, not enforcement for the
hardware op" on Linux TPM.

- **Per-key tag storage.** Sealed against the TPM's PCR-bound
  policy via `Esys_PolicySecret` + `Esys_HashSequenceComplete`,
  or a TPM-NV-RAM index. Heavy. Cheaper alternative: piggy-back
  on the kernel keyring (Track 2) since the Linux TPM signer
  already has a software side for ancillary state.
- **Recommended:** kernel keyring (Track 2), shared mechanism
  between software-keyring and TPM Linux backends.
- **Per-op verify:** wire into
  `crates/enclaveapp-linux-tpm/src/sign.rs::LinuxTpmSigner::sign`.

### Track 4: shell rc support beyond zsh/bash

**Crate:** `sshenc-core` (`shell_env.rs`) and `sshenc-cli`
(`commands.rs::install` / `uninstall`).

Current coverage:

- `Shell::Zsh` → `~/.zshrc`
- `Shell::Bash` on macOS → `~/.bash_profile`
- `Shell::Bash` on Linux → `~/.bashrc`
- `Shell::Unknown` (fish, PowerShell, cmd.exe, others) → no
  rc edit; user is told to add the snippet manually.

Follow-up tracks:

- **fish (`~/.config/fish/config.fish`):** different syntax. Use
  `set -gx SSH_AUTH_SOCK` instead of `export`. Conditional with
  `test -S` instead of `[ -S ]`. Add `Shell::Fish` variant to the
  enum and a fish-specific snippet generator.
- **PowerShell (`$PROFILE`, typically
  `~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1`):**
  PowerShell 7's profile file. Different syntax:
  `if (Test-Path "$env:USERPROFILE\.sshenc\agent.sock") { $env:SSH_AUTH_SOCK = ... }`.
  Note: native Windows ssh-keygen reads `SSH_AUTH_SOCK` differently
  than POSIX — it expects a named pipe path, not a Unix socket path.
  Confirm Windows OpenSSH behavior before writing the snippet.
- **cmd.exe:** has no rc file. Use `setx SSH_AUTH_SOCK` to write to
  the user's persistent environment, plus a transient `set` for
  the current session. Document that cmd.exe support is "user-
  level env var only" — no per-session rc.
- **Windows PowerShell 5.1 (the legacy system one):** different
  profile path (`~/Documents/WindowsPowerShell/...`). Probably
  not worth special-casing; users running modern setups have
  PowerShell 7.

### Track 5: cross-app coverage

`migrate-meta` ships only in sshenc. The trust-anchor design is
also relevant to:

- **awsenc** — uses `enclaveapp-app-storage::encryption` for AWS
  credential storage. The encryption-side `ensure_key` already
  uses `verify_meta_integrity` with auto-migrate; the same hole
  the trust anchor closes for sshenc applies there. Add an
  `awsenc migrate-meta` subcommand and the matching agent RPC
  (or have awsenc reuse sshenc's agent RPCs by app-name
  parameter).
- **sso-jwt** — same situation as awsenc.
- **npmenc** — same.
- **gitenc** — wraps sshenc, no separate migrate-meta needed.

The cross-platform `meta_migration_marker` and `meta_tag` modules
should be parameterized by app-name (already done — they take
`app_name: &str`). The agent RPC handlers in `sshenc-agent` are
hardcoded to `"sshenc"` today; a follow-up either:

1. Generalizes the agent to multi-app, or
2. Each app gets its own agent (current pattern: awsenc-agent,
   etc.), each with its own copy of the migrate-meta RPC handler.

Pick one before duplicating the macOS sshenc-agent code into
awsenc-agent, or the duplication compounds.

## Open questions (implementation-time)

1. **Where in the keychain item does the tag live?** Settled:
   separate Keychain item per key under service
   `com.godaddy.<app>.meta-tag`, account = label. Cleaner abstraction
   than prepending a header to the wrapped blob; no FFI-boundary
   risk; same ACL pattern as the wrapping key. Item count grows by N
   (one per key) — acceptable tradeoff.
2. **Linux keyring / Linux TPM mechanics for the keychain-attr
   equivalent.** Out of scope for the macOS-first PR. Will mirror
   the per-key item pattern using each platform's secure store.
3. **Should `migrate-meta` show *what changed* in the policy
   fields?** Settled: yes for `presence_mode: none` /
   `access_policy: None`, no for arbitrary diffs (no baseline to
   diff against). The `POLICY=NONE !!` marker is the signal.
