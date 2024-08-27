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

#[allow(unused_imports)]
use crate::address::IntoAddress;
use crate::platform::PlatformConfig;
use crate::AbstractDevice;
#[allow(unused_imports)]
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        #[allow(dead_code)]
        #[derive(Clone, Debug)]
        pub(crate) struct WinHandle(std::os::windows::raw::HANDLE);
        unsafe impl Send for WinHandle {}
        unsafe impl Sync for WinHandle {}
    }
}

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum Layer {
    L2,
    #[default]
    L3,
}

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub struct Configuration {
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) name: Option<String>,
    pub(crate) platform_config: PlatformConfig,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) address: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) destination: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) broadcast: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) netmask: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) mtu: Option<u16>,
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub(crate) enabled: Option<bool>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    pub(crate) layer: Option<Layer>,
    #[cfg(unix)]
    pub(crate) raw_fd: Option<RawFd>,
    #[cfg(not(unix))]
    pub(crate) raw_fd: Option<i32>,
    #[cfg(windows)]
    pub(crate) raw_handle: Option<WinHandle>,
    #[cfg(windows)]
    pub(crate) ring_capacity: Option<u32>,
    #[cfg(windows)]
    pub(crate) metric: Option<u16>,
    #[cfg(unix)]
    pub(crate) close_fd_on_drop: Option<bool>,
}

impl Configuration {
    /// Access the platform-dependent configuration.
    pub fn platform_config<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut PlatformConfig),
    {
        f(&mut self.platform_config);
        self
    }

    /// Set the tun name.
    ///
    /// [Note: on macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`. -- end note]
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn name<S: AsRef<str>>(&mut self, tun_name: S) -> &mut Self {
        self.name = Some(tun_name.as_ref().into());
        self
    }

    /// Set the address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn address_with_prefix<A: IntoAddress>(&mut self, value: A, prefix: u8) -> &mut Self {
        self.address = Some(value.into_address().unwrap());
        self.netmask = Some(prefix.into_address().unwrap());
        self
    }

    /// Set the destination address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn destination<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.destination = Some(value.into_address().unwrap());
        self
    }

    /// Set the broadcast address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn broadcast<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.broadcast = Some(value.into_address().unwrap());
        self
    }

    /// Set the MTU.
    ///
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn mtu(&mut self, value: u16) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    /// Set the interface to be enabled once created.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }

    /// Set the interface to be disabled once created.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub fn down(&mut self) -> &mut Self {
        self.enabled = Some(false);
        self
    }

    /// Set the OSI layer of operation.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    pub fn layer(&mut self, value: Layer) -> &mut Self {
        self.layer = Some(value);
        self
    }

    /// Set the raw fd.
    #[cfg(unix)]
    pub fn raw_fd(&mut self, fd: RawFd) -> &mut Self {
        self.raw_fd = Some(fd);
        self
    }
    #[cfg(not(unix))]
    pub fn raw_fd(&mut self, fd: i32) -> &mut Self {
        self.raw_fd = Some(fd);
        self
    }
    #[cfg(windows)]
    pub fn raw_handle(&mut self, handle: std::os::windows::raw::HANDLE) -> &mut Self {
        self.raw_handle = Some(WinHandle(handle));
        self
    }
    #[cfg(windows)]
    pub fn ring_capacity(&mut self, ring_capacity: u32) -> &mut Self {
        self.ring_capacity = Some(ring_capacity);
        self
    }
    #[cfg(windows)]
    pub fn metric(&mut self, metric: u16) -> &mut Self {
        self.metric = Some(metric);
        self
    }
    /// Set whether to close the received raw file descriptor on drop or not.
    /// The default behaviour is to close the received or tun2 generated file descriptor.
    /// Note: If this is set to false, it is up to the caller to ensure the
    /// file descriptor that they pass via [Configuration::raw_fd] is properly closed.
    #[cfg(unix)]
    pub fn close_fd_on_drop(&mut self, value: bool) -> &mut Self {
        self.close_fd_on_drop = Some(value);
        self
    }
}

/// Reconfigure the device.
#[allow(dead_code)]
pub(crate) fn configure<D: AbstractDevice>(
    device: &D,
    config: &Configuration,
) -> crate::error::Result<()> {
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    {
        if let Some(mtu) = config.mtu {
            device.set_mtu(mtu)?;
        }
        if let (Some(address), Some(netmask)) = (config.address, config.netmask) {
            device.set_network_address(address, netmask, config.destination)?;
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    if let Some(ip) = config.broadcast {
        device.set_broadcast(ip)?;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    if let Some(enabled) = config.enabled {
        device.enabled(enabled)?;
    }
    _ = device;
    _ = config;
    Ok(())
}
