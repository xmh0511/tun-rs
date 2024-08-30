mod device;

pub use self::device::Device;
use std::os::fd::{FromRawFd, RawFd};

use crate::configuration::Configuration;
use crate::error::Result;

/// Android-only interface configuration.
#[derive(Copy, Clone, Default, Debug)]
pub struct PlatformConfig;

use super::Device as DeviceWrapper;
/// Create a TUN device with the given name.
pub fn create(_configuration: &Configuration) -> Result<DeviceWrapper> {
    unimplemented!()
}
/// # Safety
/// The fd passed in must be an owned file descriptor; in particular, it must be open.
pub unsafe fn create_with_fd(fd: RawFd) -> Result<DeviceWrapper> {
    Ok(DeviceWrapper(Device::from_raw_fd(fd)))
}
