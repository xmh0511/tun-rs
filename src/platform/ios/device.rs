#![allow(unused_variables)]

use crate::{device::AbstractDevice, platform::posix::Tun};

/// A TUN device for iOS.
pub struct Device {
    pub(crate) tun: Tun,
}
impl Device {
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self { tun }
    }
}
impl AbstractDevice for Device {
    fn ignore_packet_info(&self) -> bool {
        self.tun.ignore_packet_info()
    }

    fn set_ignore_packet_info(&self, ign: bool) {
        self.tun.set_ignore_packet_info(ign)
    }
}
