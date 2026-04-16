# Linux Setup Guide

Setup instructions for running enclave apps (awsenc, sshenc, sso-jwt, npmenc/npxenc) on Linux, including WSL2.

## Platform Detection Order

On Linux, the apps detect the platform in this order:

1. **`--keyring` flag** — if passed, skip all detection and use the system keyring directly
2. **WSL2 detected** — try the Windows TPM bridge; fall back to keyring if bridge not found
3. **Native Linux with TPM** — try libtss2 (hardware TPM); fall back to keyring
4. **No TPM** — use system keyring (requires D-Bus Secret Service)

## Required Packages

### Ubuntu / Debian (apt)

```bash
# Runtime dependencies
sudo apt-get install -y libtss2-dev libdbus-1-dev

# Keyring support (required for software-backed key storage)
sudo apt-get install -y gnome-keyring dbus-x11 libsecret-tools
```

### Fedora (dnf)

```bash
# Runtime dependencies
sudo dnf install -y tpm2-tss-devel dbus-devel

# Keyring support
sudo dnf install -y gnome-keyring dbus-x11 libsecret
```

### RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (dnf)

```bash
# Runtime dependencies
sudo dnf install -y tpm2-tss-devel dbus-devel

# Keyring support
sudo dnf install -y gnome-keyring gnome-keyring-pam dbus-x11 libsecret pinentry
```

Note: RHEL 9 ships gnome-keyring 40.0 which requires `gnome-keyring-pam` and `pinentry` for interactive keyring creation. Newer distros (Ubuntu 24.04, Debian 13, Fedora 43) include these capabilities in the base `gnome-keyring` package.

## Keyring Setup

The system keyring must be unlocked before the apps can store or retrieve keys. This is a one-time setup per session.

### Step 1: Start D-Bus and gnome-keyring

```bash
export XDG_RUNTIME_DIR=/run/user/$(id -u)
mkdir -p $XDG_RUNTIME_DIR && chmod 700 $XDG_RUNTIME_DIR
eval $(dbus-launch --sh-syntax)
gnome-keyring-daemon --start --components=secrets
```

### Step 2: Create the default keyring (first time only)

The first time you access the keyring, you need to create a default collection. This triggers an interactive password dialog:

```bash
# This will prompt you to create a keyring password
echo "probe" | secret-tool store --label="setup" app enclaveapp key setup
```

Enter and confirm your keyring password in the dialog that appears.

### Step 3: Unlock the keyring (each session)

On subsequent sessions, the keyring needs to be unlocked. Depending on your gnome-keyring version, this happens via:

- **Interactive dialog** — gnome-keyring prompts for your password when an app first accesses the keyring
- **PAM integration** — on desktop Linux with a login manager, the keyring unlocks automatically at login

### WSL2 Notes

In WSL2, there is no login manager, so you must start D-Bus and gnome-keyring manually each session. Add this to your `.bashrc` or `.zshrc` for convenience:

```bash
if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
    export XDG_RUNTIME_DIR=/run/user/$(id -u)
    mkdir -p $XDG_RUNTIME_DIR && chmod 700 $XDG_RUNTIME_DIR
    eval $(dbus-launch --sh-syntax)
    gnome-keyring-daemon --start --components=secrets >/dev/null 2>&1
fi
```

The keyring will prompt for your password on first access each session.

## Binary Installation

### From GitHub Releases

Download the `x86_64-unknown-linux-gnu` tarball for your app:

```bash
# Example for sshenc
curl -sL https://github.com/godaddy/sshenc/releases/latest/download/sshenc-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo cp sshenc sshenc-agent sshenc-keygen gitenc /usr/local/bin/
```

### GLIBC Compatibility

The gnu binaries require glibc 2.35+. This covers:

| Distro | glibc | Status |
|--------|-------|--------|
| Ubuntu 22.04+ | 2.35+ | Supported |
| Debian 12+ | 2.36+ | Supported |
| Fedora 36+ | 2.35+ | Supported |
| RHEL 9 / AlmaLinux 9 | 2.34 | Use musl build |
| RHEL 10 / AlmaLinux 10 | 2.39+ | Supported |

For RHEL 9 / AlmaLinux 9, use the `x86_64-unknown-linux-musl` build instead (statically linked, no glibc dependency). Note: the musl build does not include keyring support — use the WSL bridge on WSL2, or a native TPM on bare metal.

## Using `--keyring` Flag

The `--keyring` flag forces the system keyring backend, bypassing WSL bridge and TPM detection. This is useful for:

- Testing the keyring backend from WSL2
- Environments where TPM detection produces unwanted errors
- Linux systems without a TPM where you want explicit keyring usage

```bash
sshenc --keyring keygen --label mykey
sshenc --keyring list
awsenc --keyring auth myprofile
sso-jwt --keyring
```

## Verified Test Matrix

All apps tested and passing on:

| Environment | Apps | Keyring |
|-------------|------|---------|
| Ubuntu 24.04 (WSL2) | awsenc, sshenc, sso-jwt, npmenc/npxenc | gnome-keyring 46.1 |
| Debian 13 (WSL2) | awsenc, sshenc, sso-jwt, npmenc/npxenc | gnome-keyring 48.0 |
| Fedora 43 (WSL2) | awsenc, sshenc, sso-jwt, npmenc/npxenc | gnome-keyring 48.0 |
| AlmaLinux 9.7 (WSL2) | awsenc, sshenc, sso-jwt, npmenc/npxenc | gnome-keyring 40.0 |
