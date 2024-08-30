mod device;

pub use device::Device;
use std::os::fd::{FromRawFd, RawFd};

use crate::configuration::Configuration;
use crate::error::Result;

/// iOS-only interface configuration.
#[derive(Copy, Clone, Debug)]
pub struct PlatformConfig {
    /// switch of Enable/Disable packet information for network driver
    pub(crate) packet_information: bool,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            packet_information: true, // default is true in iOS
        }
    }
}

impl PlatformConfig {
    /// Enable or disable packet information, the first 4 bytes of
    /// each packet delivered from/to iOS underlying API is a header with flags and protocol type when enabled.
    ///
    /// - If get the fd from
    ///   ```Objective-C
    ///   int32_t tunFd = [[NEPacketTunnelProvider::packetFlow valueForKeyPath:@"socket.fileDescriptor"] intValue];
    ///   ```
    ///   there exist PI.
    ///
    /// - But if get packet from `[NEPacketTunnelProvider::packetFlow readPacketsWithCompletionHandler:]`
    ///   and write packet via `[NEPacketTunnelProvider::packetFlow writePackets:withProtocols:]`, there is no PI.
    pub fn packet_information(&mut self, value: bool) -> &mut Self {
        self.packet_information = value;
        self
    }
}

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
