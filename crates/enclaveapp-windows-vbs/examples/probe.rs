// Diagnostic: print the current host's VBS probe result.
// Not gated to Windows so the workspace can build everywhere; on
// non-Windows the result is always Unavailable(NotWindows).

#[allow(clippy::print_stdout)]
fn main() {
    println!("{:?}", enclaveapp_windows_vbs::probe());
}
