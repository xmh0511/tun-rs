pub mod sys;

mod device;

pub use self::device::Device;
use std::os::fd::RawFd;

use crate::configuration::Configuration;
use crate::error::Result;

/// macOS-only interface configuration.
#[derive(Copy, Clone, Debug, Default)]
pub struct PlatformConfig;

/// Create a TUN device with the given name.
pub fn create(configuration: &Configuration) -> Result<Device> {
    Device::new(configuration)
}
/// # Safety
/// The fd passed in must be an owned file descriptor; in particular, it must be open.
pub unsafe fn create_with_fd(fd: RawFd) -> Result<Device> {
    Ok(Device::from_fd(fd)?)
}
