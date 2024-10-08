#![allow(unused_variables)]

use crate::platform::posix::Tun;

/// A TUN device for Android.
pub struct Device {
    pub(crate) tun: Tun,
}
impl Device {
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self { tun }
    }
}
