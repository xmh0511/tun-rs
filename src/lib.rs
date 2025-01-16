#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use r#async::*;

pub use crate::address::IntoAddress;
pub use crate::configuration::Layer;
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
))]
pub use crate::configuration::*;
pub use crate::error::{BoxError, Error, Result};
#[cfg(unix)]
pub use crate::platform::create_with_fd;
pub use crate::platform::Device;

mod error;

mod address;
mod device;

#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub mod r#async;
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
))]
mod configuration;
pub mod platform;
pub const DEFAULT_MTU: u16 = 1500;

pub const PACKET_INFORMATION_LENGTH: usize = 4;
