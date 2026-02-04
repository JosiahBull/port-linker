use crate::error::{PortLinkerError, Result};
use crate::notify::NotificationEvent;
use notify_rust::Notification;

pub fn show_notification(event: &NotificationEvent, with_sound: bool) -> Result<()> {
    let mut notification = Notification::new();

    notification
        .summary(&event.title())
        .body(&event.body())
        .appname("port-linker");

    // Set urgency/priority based on event type
    #[cfg(target_os = "linux")]
    {
        use notify_rust::Urgency;
        if event.is_error() {
            notification.urgency(Urgency::Critical);
        } else {
            notification.urgency(Urgency::Normal);
        }
    }

    // Add sound on macOS
    #[cfg(target_os = "macos")]
    {
        if with_sound {
            if event.is_error() {
                notification.sound_name("Basso");
            } else {
                notification.sound_name("Pop");
            }
        }
    }

    // Add sound hint on Linux (freedesktop)
    #[cfg(target_os = "linux")]
    {
        if with_sound {
            if event.is_error() {
                notification.hint(notify_rust::Hint::SoundName(
                    "dialog-error".to_string(),
                ));
            } else {
                notification.hint(notify_rust::Hint::SoundName(
                    "message-new-instant".to_string(),
                ));
            }
        }
    }

    notification
        .show()
        .map_err(|e| PortLinkerError::Notification(e.to_string()))?;

    Ok(())
}
