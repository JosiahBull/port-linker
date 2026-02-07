//! Pre-rendered logo assets for port-linker.
//!
//! This crate provides PNG versions of the port-linker logo at various sizes,
//! rendered from the SVG source during build time.

/// Logo PNG at 64x64 pixels (small notifications)
pub static LOGO_64: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo_64.png"));

/// Logo PNG at 128x128 pixels (standard notifications)
pub static LOGO_128: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo_128.png"));

/// Logo PNG at 256x256 pixels (high-DPI notifications)
pub static LOGO_256: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo_256.png"));
