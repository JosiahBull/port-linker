pub mod detector;
pub mod killer;

pub use detector::{find_process_on_port, ProcessInfo};
pub use killer::{kill_process, prompt_kill};
