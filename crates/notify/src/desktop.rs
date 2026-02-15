use crate::NotificationEvent;
use crate::error::{NotifyError, Result};
use assets::LOGO_128;
use std::path::PathBuf;
use std::sync::OnceLock;

use common::platform::{CurrentPlatform, Notifier as PlatformNotifier, Platform};

/// Get path to the logo file, creating it in a temp location if needed
fn get_logo_path() -> Option<&'static PathBuf> {
    static LOGO_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    LOGO_PATH
        .get_or_init(|| {
            let cache_dir = CurrentPlatform::cache_dir()?;
            let logo_dir = cache_dir.join("port-linker");
            std::fs::create_dir_all(&logo_dir).ok()?;

            let logo_path = logo_dir.join("logo.png");

            // Write the logo if it doesn't exist or is different
            let should_write = match std::fs::read(&logo_path) {
                Ok(existing) => existing != LOGO_128,
                Err(_) => true,
            };

            if should_write {
                std::fs::write(&logo_path, LOGO_128).ok()?;
            }

            Some(logo_path)
        })
        .as_ref()
}

pub fn show_notification(event: &NotificationEvent, with_sound: bool) -> Result<()> {
    // Ensure logo is cached (best-effort, only affects platforms that use it).
    let _ = get_logo_path();

    let notifier = <CurrentPlatform as Platform>::Notifier::default();
    notifier
        .show(&event.title(), &event.body(), event.is_error(), with_sound)
        .map_err(NotifyError::Notification)
}
