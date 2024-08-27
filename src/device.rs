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
use crate::error::Result;
use crate::IntoAddress;
#[allow(unused_imports)]
use std::net::IpAddr;

/// A TUN abstract device interface.
pub trait AbstractDevice {
    /// Get the device tun name.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn tun_name(&self) -> Result<String>;

    /// Set the device tun name.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    fn set_tun_name(&self, tun_name: &str) -> Result<()>;

    /// Turn on or off the interface.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    fn enabled(&self, value: bool) -> Result<()>;

    /// Get the address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn address(&self) -> Result<IpAddr>;

    /// Get the destination address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn destination(&self) -> Result<IpAddr>;

    /// Set the destination address.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    fn set_destination<A: IntoAddress>(&self, value: A) -> Result<()>;

    /// Get the broadcast address.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    fn broadcast(&self) -> Result<IpAddr>;

    /// Set the broadcast address.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()>;

    /// Get the netmask.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn netmask(&self) -> Result<IpAddr>;

    /// Sets the network addresses of this adapter, including network address, subnet mask, and gateway
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn set_network_address<A: IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> Result<()>;

    /// Get the MTU.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn mtu(&self) -> Result<u16>;

    /// Set the MTU.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn set_mtu(&self, value: u16) -> Result<()>;

    /// Return whether the underlying tun device on the platform has packet information
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios",))]
    fn packet_information(&self) -> bool;
}
