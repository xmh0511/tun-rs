use crate::platform::unix::Tun;

/// A TUN device for Android.
pub struct DeviceInner {
    pub(crate) tun: Tun,
}
impl DeviceInner {
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self { tun }
    }
}
