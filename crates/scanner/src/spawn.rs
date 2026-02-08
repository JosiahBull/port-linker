use std::ffi::CString;
use std::ptr;

/// Run a command with args and capture stdout as bytes.
/// Uses `posix_spawnp` to avoid pulling in `std::process::Command`.
///
/// # Safety
/// Calls POSIX C functions. The caller must ensure `cmd` and `args` are valid
/// null-terminatable strings.
pub(crate) fn capture_stdout(cmd: &str, args: &[&str]) -> Option<Vec<u8>> {
    // Build null-terminated C strings for argv
    let c_cmd = CString::new(cmd).ok()?;
    let c_args: Vec<CString> = std::iter::once(cmd)
        .chain(args.iter().copied())
        .filter_map(|a| CString::new(a).ok())
        .collect();
    let mut argv_ptrs: Vec<*mut libc::c_char> = c_args.iter().map(|a| a.as_ptr().cast_mut()).collect();
    argv_ptrs.push(ptr::null_mut());

    unsafe {
        // Create pipe for stdout capture
        let mut pipe_fds = [0_i32; 2];
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            return None;
        }
        let [read_fd, write_fd] = pipe_fds;

        // Set up file actions: redirect child stdout to write end of pipe
        let mut file_actions: libc::posix_spawn_file_actions_t = std::mem::zeroed();
        if libc::posix_spawn_file_actions_init(&mut file_actions) != 0 {
            libc::close(read_fd);
            libc::close(write_fd);
            return None;
        }

        // Child: close read end, dup write end to stdout, close original write end
        libc::posix_spawn_file_actions_addclose(&mut file_actions, read_fd);
        libc::posix_spawn_file_actions_adddup2(&mut file_actions, write_fd, libc::STDOUT_FILENO);
        libc::posix_spawn_file_actions_addclose(&mut file_actions, write_fd);

        // Also redirect stderr to /dev/null
        let devnull = CString::new("/dev/null").unwrap();
        libc::posix_spawn_file_actions_addopen(
            &mut file_actions,
            libc::STDERR_FILENO,
            devnull.as_ptr(),
            libc::O_WRONLY,
            0,
        );

        // Spawn the child process
        let mut pid: libc::pid_t = 0;
        let ret = libc::posix_spawnp(
            &mut pid,
            c_cmd.as_ptr(),
            &file_actions,
            ptr::null(),
            argv_ptrs.as_ptr(),
            ptr::null_mut(),
        );

        libc::posix_spawn_file_actions_destroy(&mut file_actions);

        // Parent: close write end
        libc::close(write_fd);

        if ret != 0 {
            libc::close(read_fd);
            return None;
        }

        // Read all stdout from the pipe
        let mut output = Vec::with_capacity(4096);
        let mut buf = [0_u8; 4096];
        loop {
            let n = libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(read_fd);

        // Wait for child to exit
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);

        // Check exit status (WIFEXITED && WEXITSTATUS == 0)
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Some(output)
        } else {
            None
        }
    }
}
