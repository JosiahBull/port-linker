//! Shared Unix code (Linux + macOS): process kill via signals, username.

/// Send SIGTERM to a process, wait up to 1 second, then SIGKILL if still alive.
pub fn kill_process(pid: u32) -> Result<(), String> {
    use std::thread;
    use std::time::Duration;

    let pid_i32 = pid as i32;

    // Send SIGTERM first.
    let ret = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("SIGTERM failed for PID {pid}: {err}"));
    }

    // Wait up to 1 second for the process to exit, polling every 100ms.
    for _ in 0..10 {
        thread::sleep(Duration::from_millis(100));
        // Check if process still exists (signal 0 = existence check).
        let alive = unsafe { libc::kill(pid_i32, 0) };
        if alive != 0 {
            // Process is gone.
            return Ok(());
        }
    }

    // Still alive after 1s - send SIGKILL.
    let ret = unsafe { libc::kill(pid_i32, libc::SIGKILL) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("SIGKILL failed for PID {pid}: {err}"));
    }

    // Brief wait to confirm.
    thread::sleep(Duration::from_millis(100));
    Ok(())
}

/// Get the current username from environment variables.
pub fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_returns_nonempty() {
        let name = username();
        assert!(
            !name.is_empty(),
            "username should return a non-empty string"
        );
    }
}
