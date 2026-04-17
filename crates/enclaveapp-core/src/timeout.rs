//! Timeout utilities for subprocess execution and blocking reads.
//!
//! Cross-platform helpers to prevent enclave apps from hanging on
//! unresponsive subprocesses, bridge calls, or slow OS operations.

use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Result of a bounded subprocess operation.
#[derive(Debug)]
pub enum TimeoutResult<T> {
    /// Operation completed within the deadline.
    Completed(T),
    /// Operation exceeded the deadline and the child was killed.
    TimedOut,
}

impl<T> TimeoutResult<T> {
    pub fn into_option(self) -> Option<T> {
        match self {
            TimeoutResult::Completed(v) => Some(v),
            TimeoutResult::TimedOut => None,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        matches!(self, TimeoutResult::TimedOut)
    }
}

/// Poll interval for `try_wait`-based timeout loops.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait for a child process to exit, or return `TimedOut` after `timeout`
/// elapses. On timeout, the caller is responsible for killing the child.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> io::Result<TimeoutResult<ExitStatus>> {
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(TimeoutResult::Completed(status)),
            None => {
                if start.elapsed() >= timeout {
                    return Ok(TimeoutResult::TimedOut);
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// Run a child to completion, collecting stdout/stderr, bounded by `timeout`.
/// On timeout the child is killed and `TimedOut` is returned.
///
/// The child must already be configured via `.stdout(Stdio::piped())` etc.
/// if you want to capture output.
pub fn wait_output_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> io::Result<TimeoutResult<Output>> {
    // Drain stdout/stderr on threads so the child's OS pipe buffers don't
    // fill up and deadlock before we hit the timeout.
    let stdout_thread = child.stdout.take().map(|mut s| {
        thread::Builder::new()
            .name("enclaveapp-child-stdout".into())
            .spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                Ok(buf)
            })
    });
    let stderr_thread = child.stderr.take().map(|mut s| {
        thread::Builder::new()
            .name("enclaveapp-child-stderr".into())
            .spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                Ok(buf)
            })
    });

    match wait_with_timeout(&mut child, timeout)? {
        TimeoutResult::Completed(status) => {
            let stdout = match stdout_thread {
                Some(Ok(t)) => t.join().unwrap_or_else(|_| Ok(Vec::new()))?,
                _ => Vec::new(),
            };
            let stderr = match stderr_thread {
                Some(Ok(t)) => t.join().unwrap_or_else(|_| Ok(Vec::new()))?,
                _ => Vec::new(),
            };
            Ok(TimeoutResult::Completed(Output {
                status,
                stdout,
                stderr,
            }))
        }
        TimeoutResult::TimedOut => {
            drop(child.kill());
            drop(child.wait());
            Ok(TimeoutResult::TimedOut)
        }
    }
}

/// Spawn a command with piped stdout/stderr and run it to completion
/// bounded by `timeout`.
pub fn run_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> io::Result<TimeoutResult<Output>> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn()?;
    wait_output_with_timeout(child, timeout)
}

/// Spawn a command (inheriting stdout/stderr) and wait for its exit status
/// bounded by `timeout`. Kills the child on timeout.
pub fn run_status_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> io::Result<TimeoutResult<ExitStatus>> {
    let mut child = cmd.spawn()?;
    match wait_with_timeout(&mut child, timeout)? {
        TimeoutResult::Completed(status) => Ok(TimeoutResult::Completed(status)),
        TimeoutResult::TimedOut => {
            drop(child.kill());
            drop(child.wait());
            Ok(TimeoutResult::TimedOut)
        }
    }
}

/// Blocking reader of `read_line` with a timeout. Spawns a worker thread
/// that owns the reader and sends each line over a channel.
///
/// The worker continues reading until EOF/error and cannot be cancelled
/// once started — intended for cases where the reader is owned by the
/// caller for the remainder of the session.
#[derive(Debug)]
pub struct LineReaderWithTimeout {
    rx: mpsc::Receiver<io::Result<String>>,
    _thread: thread::JoinHandle<()>,
}

impl LineReaderWithTimeout {
    pub fn new<R: Read + Send + 'static>(reader: R) -> Self {
        let (tx, rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("enclaveapp-line-reader".into())
            .spawn(move || {
                let mut buf_reader = BufReader::new(reader);
                loop {
                    let mut line = String::new();
                    match buf_reader.read_line(&mut line) {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            if tx.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            drop(tx.send(Err(e)));
                            break;
                        }
                    }
                }
            })
            .expect("spawn line reader thread");
        Self {
            rx,
            _thread: thread,
        }
    }

    /// Receive the next line, or return `TimedOut` after `timeout`.
    /// Returns `Completed(Err(_))` on read error and `Completed(Ok(""))`
    /// on EOF.
    pub fn recv_line(&self, timeout: Duration) -> TimeoutResult<io::Result<String>> {
        match self.rx.recv_timeout(timeout) {
            Ok(result) => TimeoutResult::Completed(result),
            Err(mpsc::RecvTimeoutError::Timeout) => TimeoutResult::TimedOut,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                TimeoutResult::Completed(Ok(String::new()))
            }
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::process::Command;

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_completes_fast_command() {
        let result = run_with_timeout(
            {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", "echo hello"]);
                c
            },
            Duration::from_secs(5),
        )
        .unwrap();
        match result {
            TimeoutResult::Completed(output) => {
                assert!(output.status.success());
                assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
            }
            TimeoutResult::TimedOut => panic!("fast command should not time out"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_kills_slow_command() {
        let start = Instant::now();
        let result = run_with_timeout(
            {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", "sleep 10"]);
                c
            },
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(result.is_timed_out());
        // Should fire well before the 10s sleep finishes
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn line_reader_delivers_line_within_timeout() {
        use std::io::Write;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let r = child.stdout.take().unwrap();
        let mut w = child.stdin.take().unwrap();
        let reader = LineReaderWithTimeout::new(r);
        writeln!(w, "hello world").unwrap();
        w.flush().unwrap();
        match reader.recv_line(Duration::from_secs(2)) {
            TimeoutResult::Completed(Ok(line)) => assert_eq!(line.trim(), "hello world"),
            other => panic!("unexpected result: {:?}", other),
        }
        // Close stdin so cat exits, then reap the child to avoid a zombie.
        drop(w);
        drop(child.wait());
    }

    #[cfg(unix)]
    #[test]
    fn line_reader_times_out_when_no_data() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 10"]).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = LineReaderWithTimeout::new(stdout);
        let start = Instant::now();
        let result = reader.recv_line(Duration::from_millis(200));
        assert!(result.is_timed_out());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(child.kill());
        drop(child.wait());
    }
}
