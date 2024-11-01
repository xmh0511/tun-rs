#![cfg_attr(docsrs, feature(doc_cfg))]
mod error;
pub use crate::error::{BoxError, Error, Result};

mod address;
pub use crate::address::IntoAddress;

mod device;
pub use crate::device::AbstractDevice;

mod configuration;
pub use crate::configuration::{Configuration, Layer};

pub mod platform;
pub use crate::platform::create;
#[cfg(unix)]
pub use crate::platform::create_with_fd;

#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub mod r#async;
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use r#async::*;

pub fn configure() -> Configuration {
    Configuration::default()
}

#[cfg(unix)]
pub const DEFAULT_MTU: u16 = 1500;
#[cfg(windows)]
pub const DEFAULT_MTU: u16 = 0xFFFF; // 65535

pub const PACKET_INFORMATION_LENGTH: usize = 4;

pub mod getifaddrs;
