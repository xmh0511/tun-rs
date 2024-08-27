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

//! Platform specific modules.

#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub mod linux;
use std::ops::Deref;

#[cfg(target_os = "linux")]
pub use self::linux::{create, Device as DeviceInner, PlatformConfig};

#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::{create, Device as DeviceInner, PlatformConfig};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::{create, Device as DeviceInner, PlatformConfig};

#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "ios")]
pub use self::ios::{create, Device as DeviceInner, PlatformConfig};

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub use self::android::{create, Device as DeviceInner, PlatformConfig};

#[cfg(unix)]
pub use crate::platform::posix::Tun;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::{create, Device as DeviceInner, PlatformConfig, Tun};

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
    #[cfg(feature = "experimental")]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown()
    }
}

impl Deref for Device {
    type Target = DeviceInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
