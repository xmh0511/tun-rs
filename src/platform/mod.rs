#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use self::linux::*;

#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::*;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;

#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "ios")]
pub use self::ios::*;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub use self::android::*;

#[cfg(unix)]
pub use crate::platform::posix::Tun;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

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

        assert!(dev
            .addresses()
            .unwrap()
            .into_iter()
            .any(|v| v.address == "192.168.50.1".parse::<Ipv4Addr>().unwrap()));

        assert_eq!(crate::DEFAULT_MTU, dev.mtu().unwrap());
    }
}
