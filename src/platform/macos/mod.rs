pub mod sys;

mod device;

pub use self::device::Device;
use std::os::fd::{FromRawFd, RawFd};

use crate::configuration::Configuration;
use crate::error::Result;

/// macOS-only interface configuration.
#[derive(Copy, Clone, Debug)]
pub struct PlatformConfig {
    pub(crate) packet_information: bool,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            packet_information: true, // default is true in macOS
        }
    }
}

impl PlatformConfig {
    /// Enable or disable packet information, the first 4 bytes of
    /// each packet delivered from/to macOS underlying API is a header with flags and protocol type when enabled.
    ///
    /// - If we open an `utun` device, there always exist PI.
    ///
    /// - If we use `Network Extension` to build our App:
    ///
    ///   - If get the fd from
    ///     ```Objective-C
    ///     int32_t tunFd = [[NEPacketTunnelProvider::packetFlow valueForKeyPath:@"socket.fileDescriptor"] intValue];
    ///     ```
    ///     there exist PI.
    ///
    ///   - But if get packet from `[NEPacketTunnelProvider::packetFlow readPacketsWithCompletionHandler:]`
    ///     and write packet via `[NEPacketTunnelProvider::packetFlow writePackets:withProtocols:]`, there is no PI.
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
