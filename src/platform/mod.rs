#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub mod linux;
use std::ops::Deref;

#[cfg(target_os = "linux")]
pub use self::linux::{Device as DeviceInner, *};

#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::{Device as DeviceInner, *};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::{Device as DeviceInner, *};

#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "ios")]
pub use self::ios::{Device as DeviceInner, *};

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub use self::android::{Device as DeviceInner, *};

#[cfg(unix)]
pub use crate::platform::posix::Tun;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::{create, Device as DeviceInner, PlatformConfig, Tun};

#[cfg(target_family = "unix")]
use std::os::unix::io::RawFd;

#[repr(transparent)]
pub struct Device(pub(crate) DeviceInner);

impl Device {
    /// Recv a packet from tun device
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf)
    }

    /// Send a packet to tun device
    #[inline]
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf)
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    #[cfg(any(feature = "experimental", target_os = "windows"))]
    /// Do not use nonblocking fd when you want to use shutdown
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown()
    }
}

/// Construct a Device from an existing file descriptor
#[cfg(target_family = "unix")]
impl std::os::fd::FromRawFd for Device {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Device(DeviceInner::from_raw_fd(fd))
    }
}

#[cfg(target_family = "unix")]
impl std::os::fd::IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl Deref for Device {
    type Target = DeviceInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
#[cfg(test)]
mod test {
    use crate::configuration::Configuration;
    use crate::device::AbstractDevice;
    use std::net::Ipv4Addr;

    #[test]
    fn create() {
        let dev = super::create(
            Configuration::default()
                .name("utun6")
                .address_with_prefix("192.168.50.1", 24)
                .mtu(crate::DEFAULT_MTU)
                .up(),
        )
        .unwrap();

        assert_eq!(
            "192.168.50.1".parse::<Ipv4Addr>().unwrap(),
            dev.address().unwrap()
        );

        assert_eq!(
            "255.255.0.0".parse::<Ipv4Addr>().unwrap(),
            dev.netmask().unwrap()
        );

        assert_eq!(crate::DEFAULT_MTU, dev.mtu().unwrap());
    }
}
