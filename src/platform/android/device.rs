use crate::platform::unix::Tun;

/// A TUN device for Android.
pub(crate) struct DeviceInner {
    pub(crate) tun: Tun,
}
impl DeviceInner {
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self { tun }
    }
}
