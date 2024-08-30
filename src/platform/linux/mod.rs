pub mod sys;

mod device;

pub use self::device::Device;
use std::os::fd::{FromRawFd, RawFd};

use crate::configuration::Configuration;
use crate::error::Result;

/// Linux-only interface configuration.
#[derive(Copy, Clone, Debug)]
pub struct PlatformConfig {
    /// switch of Enable/Disable packet information for network driver
    pub(crate) packet_information: bool,
}

/// `packet_information` is default to be `false` and `ensure_root_privileges` is default to be `true`.
impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            packet_information: false,
        }
    }
}

impl PlatformConfig {
    /// Enable or disable packet information, the first 4 bytes of
    /// each packet delivered from/to Linux underlying API is a header with flags and protocol type when enabled.
    pub fn packet_information(&mut self, value: bool) -> &mut Self {
        self.packet_information = value;
        self
    }
}

use super::Device as DeviceWrapper;
/// Create a TUN device with the given name.
pub fn create(configuration: &Configuration) -> Result<DeviceWrapper> {
    Ok(DeviceWrapper(Device::new(configuration)?))
}
/// # Safety
/// The fd passed in must be an owned file descriptor; in particular, it must be open.
pub unsafe fn create_with_fd(fd: RawFd) -> Result<DeviceWrapper> {
    Ok(DeviceWrapper(Device::from_raw_fd(fd)))
}
