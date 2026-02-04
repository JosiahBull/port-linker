use crate::error::{PortLinkerError, Result};
use crate::process::detector::ProcessInfo;
use dialoguer::Confirm;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::{info, warn};

pub fn prompt_kill(proc_info: &ProcessInfo) -> Result<bool> {
    let message = format!(
        "Port {} is in use by {} (PID {}). Kill it?",
        0, // We don't have port here, but we can get it from context
        proc_info.name,
        proc_info.pid
    );

    let result = Confirm::new()
        .with_prompt(&message)
        .default(false)
        .interact()
        .map_err(|e| PortLinkerError::ProcessKill(format!("User prompt failed: {}", e)))?;

    Ok(result)
}

pub fn kill_process(proc_info: &ProcessInfo) -> Result<()> {
    info!("Killing process {} (PID {})", proc_info.name, proc_info.pid);

    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let pid = Pid::from_u32(proc_info.pid);

    if let Some(process) = sys.process(pid) {
        // Try SIGTERM first via kill command
        let term_result = std::process::Command::new("kill")
            .args(["-TERM", &proc_info.pid.to_string()])
            .status();

        if term_result.is_err() {
            warn!("SIGTERM failed, trying SIGKILL");
            process.kill();
        }

        // Wait a moment for process to exit
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if still running
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        if sys.process(pid).is_some() {
            // Force kill
            warn!("Process didn't exit, sending SIGKILL");
            if let Some(p) = sys.process(pid) {
                p.kill();
            }
        }

        info!("Process {} killed", proc_info.pid);
        Ok(())
    } else {
        // Process might have already exited
        warn!("Process {} not found (may have already exited)", proc_info.pid);
        Ok(())
    }
}
