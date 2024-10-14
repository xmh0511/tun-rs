#[allow(unused_imports)]
use crate::error::Result;
#[allow(unused_imports)]
use crate::IntoAddress;
#[allow(unused_imports)]
use std::net::IpAddr;

#[allow(dead_code)]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;
/// A TUN abstract device interface.
pub trait AbstractDevice {
    /// Get the device tun name.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn name(&self) -> Result<String>;

    /// Set the device tun name.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    fn set_name(&self, name: &str) -> Result<()>;

    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn if_index(&self) -> Result<u32>;

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
    fn addresses(&self) -> Result<Vec<crate::getifaddrs::Interface>>;

    /// Get the broadcast address.
    #[cfg(target_os = "linux")]
    fn broadcast(&self) -> Result<IpAddr>;

    /// Set the broadcast address.
    #[cfg(target_os = "linux")]
    fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()>;

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

    /// Remove the specified address
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> Result<()>;

    /// Add Ipv6 address
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> Result<()>;

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

    /// Ignore packet-information during reading and writing
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn ignore_packet_info(&self) -> bool;

    /// Ignore packet-information during reading and writing
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn set_ignore_packet_info(&self, ign: bool);

    /// Set mac address
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> Result<()>;
    /// Get mac address
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    fn get_mac_address(&self) -> Result<[u8; ETHER_ADDR_LEN as usize]>;
    #[cfg(target_os = "windows")]
    fn set_metric(&self, metric: u16) -> Result<()>;
}
