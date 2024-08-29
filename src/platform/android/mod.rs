//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

//! Android specific functionality.

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
