pub mod sys;

mod checksum;
mod device;
pub(crate) mod offload;
pub use device::Device;
pub use offload::ExpandBuffer;
pub use offload::GROTable;
pub use offload::IDEAL_BATCH_SIZE;
pub use offload::VIRTIO_NET_HDR_LEN;
use std::os::fd::RawFd;

use crate::configuration::Configuration;
use crate::error::Result;

/// Linux-only interface configuration.
#[derive(Copy, Clone, Debug)]
pub struct PlatformConfig {
    /// switch of Enable/Disable packet information for network driver
    pub(crate) packet_information: bool,
    pub(crate) tx_queue_len: Option<u32>,
    pub(crate) offload: bool,
}

/// `packet_information` is default to be `false` and `ensure_root_privileges` is default to be `true`.
impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            packet_information: false,
            tx_queue_len: None,
            offload: false,
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
    pub fn tx_queue_len(&mut self, value: u32) -> &mut Self {
        self.tx_queue_len = Some(value);
        self
    }
    /// Enable/Disable TUN offloads
    pub fn offload(&mut self, value: bool) -> &mut Self {
        self.offload = value;
        self
    }
}

/// Create a TUN device with the given name.
pub fn create(configuration: &Configuration) -> Result<Device> {
    Device::new(configuration)
}
/// # Safety
/// The fd passed in must be an owned file descriptor; in particular, it must be open.
pub unsafe fn create_with_fd(fd: RawFd) -> Result<Device> {
    Ok(Device::from_fd(fd)?)
}
