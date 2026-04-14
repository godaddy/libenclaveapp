# enclaveapp-bridge

JSON-RPC TPM bridge for WSL-to-Windows communication.

When running inside WSL, applications can't access the Windows TPM directly. This crate provides the protocol and client for a bridge pattern: a small Windows executable reads JSON-RPC requests from stdin and writes responses to stdout, performing TPM operations on behalf of the WSL process.

## Protocol

Single-line JSON over stdin/stdout:

```
-> {"method":"encrypt","params":{"data":"<base64>","biometric":false,"app_name":"awsenc"}}
<- {"result":"<base64>","error":null}
```

### Methods

| Method | Description |
|---|---|
| `init` | Initialize TPM key for the given app |
| `encrypt` | Encrypt base64-encoded data |
| `decrypt` | Decrypt base64-encoded data |
| `destroy` | Delete the TPM key |

## Client

The client discovers the bridge executable on the Windows filesystem from within WSL:

```rust
use enclaveapp_bridge::{find_bridge, bridge_encrypt, bridge_decrypt};

if let Some(bridge) = find_bridge("awsenc") {
    let ciphertext = bridge_encrypt(&bridge, "awsenc", plaintext, false)?;
    let plaintext = bridge_decrypt(&bridge, "awsenc", &ciphertext, false)?;
}
```

Discovery paths:
- `/mnt/c/Program Files/<app_name>/<app_name>-bridge.exe`
- `/mnt/c/ProgramData/<app_name>/<app_name>-bridge.exe`
- `$PATH`

The higher-level `enclaveapp-app-storage` crate also adds app-specific
`<app_name>-tpm-bridge.exe` fallbacks for consumers such as `awsenc` and
`sso-jwt`.

## Server

This crate provides protocol types and the client. The server binary (which runs on Windows and performs actual TPM operations) is implemented by consuming applications using `enclaveapp-windows` for the crypto.
