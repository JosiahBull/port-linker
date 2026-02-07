use crate::error::{NotifyError, Result};
use crate::NotificationEvent;
use assets::LOGO_128;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Get path to the logo file, creating it in a temp location if needed
fn get_logo_path() -> Option<&'static PathBuf> {
    static LOGO_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    LOGO_PATH
        .get_or_init(|| {
            let cache_dir = dirs::cache_dir()?;
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
    #[cfg(target_os = "macos")]
    {
        show_notification_macos(event, with_sound)
    }

    #[cfg(target_os = "linux")]
    {
        show_notification_linux(event, with_sound)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (event, with_sound);
        Ok(())
    }
}

/// Show notification on macOS using terminal-notifier (if available) or osascript
///
/// This is a workaround becuase the notify_rust crate is shit on macos, not it's fault - the wrapper it's built over
/// is also pretty garbage - probably due to lack of support from Apple.
#[cfg(target_os = "macos")]
fn show_notification_macos(event: &NotificationEvent, with_sound: bool) -> Result<()> {
    use std::process::Command;

    let title = event.title();
    let body = event.body();

    // Try terminal-notifier first (it supports custom icons)
    if let Some(icon_path) = get_logo_path() {
        if let Ok(output) = Command::new("terminal-notifier")
            .arg("-title")
            .arg(&title)
            .arg("-message")
            .arg(&body)
            .arg("-contentImage")
            .arg(icon_path)
            .args(if with_sound {
                vec!["-sound", if event.is_error() { "Basso" } else { "Pop" }]
            } else {
                vec![]
            })
            .output()
        {
            if output.status.success() {
                return Ok(());
            }
            // Fall through to osascript if terminal-notifier failed
        }
    }

    // Fallback to osascript (no icon support, but always available)
    let escaped_title = title.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_body = body.replace('\\', "\\\\").replace('"', "\\\"");

    let sound_part = if with_sound {
        if event.is_error() {
            " sound name \"Basso\""
        } else {
            " sound name \"Pop\""
        }
    } else {
        ""
    };

    let script = format!(
        "display notification \"{}\" with title \"{}\"{}",
        escaped_body, escaped_title, sound_part
    );

    let output = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| NotifyError::Notification(format!("Failed to run osascript: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NotifyError::Notification(format!(
            "osascript failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Show notification on Linux using notify-rust
#[cfg(target_os = "linux")]
fn show_notification_linux(event: &NotificationEvent, with_sound: bool) -> Result<()> {
    use notify_rust::{Hint, Notification, Urgency};

    let mut notification = Notification::new();

    notification
        .summary(&event.title())
        .body(&event.body())
        .appname("port-linker");

    // Set embedded icon
    if let Some(icon_path) = get_logo_path() {
        notification.icon(icon_path.to_string_lossy().as_ref());
    }

    if event.is_error() {
        notification.urgency(Urgency::Critical);
    } else {
        notification.urgency(Urgency::Normal);
    }

    if with_sound {
        if event.is_error() {
            notification.hint(Hint::SoundName("dialog-error".to_string()));
        } else {
            notification.hint(Hint::SoundName("message-new-instant".to_string()));
        }
    }

    notification
        .show()
        .map_err(|e| NotifyError::Notification(e.to_string()))?;

    Ok(())
}
